#include "common.h"

#include "db-wrapper.h"
#include "mysql-db-ops.h"

#include <mysql.h>

/* Connection Pool. */

typedef struct MySQLDBConnPool {
    DBConnPool parent;
    char *host;
    char *user;
    char *password;
    unsigned int port;
    char *db_name;
    char *unix_socket;
    gboolean use_ssl;
    char *charset;
} MySQLDBConnPool;

DBConnPool *
mysql_db_conn_pool_new (const char *host,
                        const char *user,
                        const char *password,
                        unsigned int port,
                        const char *db_name,
                        const char *unix_socket,
                        gboolean use_ssl,
                        const char *charset)
{
    MySQLDBConnPool *pool = g_new0 (MySQLDBConnPool, 1);

    pool->host = g_strdup (host);
    pool->user = g_strdup (user);
    pool->password = g_strdup (password);
    pool->port = port;
    pool->db_name = g_strdup(db_name);
    pool->unix_socket = g_strdup(unix_socket);
    pool->use_ssl = use_ssl;
    pool->charset = g_strdup(charset);

    mysql_library_init (0, NULL, NULL);

    return (DBConnPool *)pool;
}

void
mysql_db_conn_pool_free (DBConnPool *vpool)
{
    MySQLDBConnPool *pool = (MySQLDBConnPool *)vpool;

    g_free (pool->host);
    g_free (pool->user);
    g_free (pool->password);
    g_free (pool->db_name);
    g_free (pool->unix_socket);
    g_free (pool->charset);

    g_free (pool);
}

/* Connection. */

typedef struct MySQLDBConnection {
    DBConnection parent;
    MYSQL *db;
} MySQLDBConnection;

#define SQL_DEFAULT_TCP_TIMEOUT 3

static MYSQL *
connect_mysql (MySQLDBConnPool *pool, GError **error)
{
    my_bool yes = 1;
    volatile int connect_timeout = SQL_DEFAULT_TCP_TIMEOUT;
    unsigned long client_flags = CLIENT_MULTI_STATEMENTS;
    MYSQL *db;

    db = mysql_init (NULL);
    if (!db) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Failed to allocate mysql handle.");
        return NULL;
    }

    if (pool->use_ssl)
        mysql_ssl_set(db, 0,0,0,0,0);

    if (pool->charset)
        mysql_options(db, MYSQL_SET_CHARSET_NAME, pool->charset);

    mysql_options(db, MYSQL_OPT_CONNECT_TIMEOUT, (const char*)&connect_timeout);
    mysql_options(db, MYSQL_OPT_RECONNECT, (const char*)&yes);

    if (mysql_real_connect(db, pool->host, pool->user, pool->password,
                           pool->db_name, pool->port,
                           pool->unix_socket, client_flags)) {
        return db;
    } else {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Failed to connect to MySQL: %s", mysql_error(db));
        mysql_close (db);
        return NULL;
    }
}

DBConnection *
mysql_get_db_connection (DBConnPool *vpool, GError **error)
{
    MySQLDBConnPool *pool = (MySQLDBConnPool *)vpool;
    MySQLDBConnection *conn;
    MYSQL *db = connect_mysql (pool, error);
    if (!db)
        return NULL;
    conn = g_new0 (MySQLDBConnection, 1);
    conn->db = db;
    return (DBConnection *)conn;
}

void
mysql_db_connection_close (DBConnection *vconn)
{
    if (!vconn)
        return;

    MySQLDBConnection *conn = (MySQLDBConnection *)vconn;

    mysql_close (conn->db);

    g_free (conn);
}

gboolean
mysql_db_connection_ping (DBConnection *vconn)
{
    MySQLDBConnection *conn = (MySQLDBConnection *)vconn;

    return (mysql_ping (conn->db) == 0);
}

gboolean
mysql_db_connection_execute (DBConnection *vconn, const char *sql, GError **error)
{
    MySQLDBConnection *conn = (MySQLDBConnection *)vconn;

    int rc = mysql_real_query (conn->db, sql, strlen(sql));
    if (rc != 0) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "MySQL failed to execute: %s", mysql_error(conn->db));
        return FALSE;
    }
    return TRUE;
}

/* Result Set. */

#define DEFAULT_COLUMN_SIZE 256

typedef struct MySQLResultSet {
    ResultSet parent;
    MYSQL_STMT *stmt;
    int column_count;
    MYSQL_BIND *bind;
    int need_rebind;
} MySQLResultSet;

void
mysql_result_set_free (ResultSet *vr)
{
    if (!vr)
        return;

    MySQLResultSet *r = (MySQLResultSet *)vr;

    mysql_stmt_free_result (r->stmt);
    mysql_stmt_close (r->stmt);

    int i;
    for (i = 0; i < r->column_count; ++i) {
        g_free (r->bind[i].buffer);
        g_free (r->bind[i].length);
        g_free (r->bind[i].is_null);
    }
    g_free (r->bind);
    g_free (r);
}

static MySQLResultSet *
mysql_result_set_new (MYSQL_STMT *stmt, GError **error)
{
    MySQLResultSet *r = g_new0 (MySQLResultSet, 1);
    int i;

    r->stmt = stmt;
    r->column_count = mysql_stmt_field_count (stmt);
    r->bind = g_new0 (MYSQL_BIND, r->column_count);
    for (i = 0; i < r->column_count; ++i) {
        r->bind[i].buffer = g_malloc (DEFAULT_COLUMN_SIZE + 1);
        r->bind[i].buffer_type = MYSQL_TYPE_STRING;
        r->bind[i].buffer_length = DEFAULT_COLUMN_SIZE;
        r->bind[i].length = g_new0 (unsigned long, 1);
        r->bind[i].is_null = g_new0 (my_bool, 1);
    }

    if (mysql_stmt_bind_result (stmt, r->bind) != 0) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "mysql_stmt_bind_result failed: %s\n", mysql_stmt_error(stmt));
        mysql_result_set_free ((ResultSet*)r);
        return NULL;
    }

    return r;
}

static MYSQL_STMT *
prepare (MYSQL *db, const char *sql, GError **error)
{
    MYSQL_STMT *stmt;

    stmt = mysql_stmt_init (db);
    if (!stmt) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "mysql_stmt_init out of memory");
        return NULL;
    }

    if (mysql_stmt_prepare (stmt, sql, strlen(sql)) != 0) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "mysql_stmt_prepare failed: %s",
                     mysql_stmt_error(stmt));
        mysql_stmt_close (stmt);
        return NULL;
    }

    return stmt;
}

ResultSet *
mysql_execute_query (DBConnection *vconn, const char *sql, GError **error)
{
    MySQLDBConnection *conn = (MySQLDBConnection *)vconn;
    MYSQL_STMT *stmt;
    MySQLResultSet *r;

    stmt = prepare (conn->db, sql, error);
    if (!stmt) {
        return NULL;
    }

    unsigned long cursor = CURSOR_TYPE_READ_ONLY;
    mysql_stmt_attr_set (stmt, STMT_ATTR_CURSOR_TYPE, &cursor);

    if (mysql_stmt_execute (stmt) != 0) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "mysql_stmt_execute failed: %s",
                     mysql_stmt_error(stmt));
        mysql_stmt_close (stmt);
        return NULL;
    }

    r = mysql_result_set_new (stmt, error);
    if (!r) {
        mysql_stmt_close (stmt);
        return NULL;
    }

    return (ResultSet *)r;
}

static gboolean
check_mysql_column_size (MySQLResultSet *r, int i, GError **error)
{
    unsigned long real_length = *(r->bind[i].length);

    if ((real_length > r->bind[i].buffer_length)) {
        /* Column was truncated, resize and fetch column directly. */
        g_free (r->bind[i].buffer);
        r->bind[i].buffer = g_malloc (real_length + 1);
        r->bind[i].buffer_length = real_length;
        if (mysql_stmt_fetch_column (r->stmt, &r->bind[i], i, 0) != 0) {
            g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                         "mysql_stmt_fetch_column failed: %s",
                         mysql_stmt_error(r->stmt));
            return FALSE;
        }
        r->need_rebind = TRUE;
    }

    return TRUE;
}

gboolean
mysql_result_set_next (ResultSet *vr, GError **error)
{
    MySQLResultSet *r = (MySQLResultSet *)vr;

    if (r->need_rebind) {
        if (mysql_stmt_bind_result (r->stmt, r->bind) != 0) {
            g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                         "mysql_stmt_bind_result failed: %s",
                         mysql_stmt_error(r->stmt));
            return FALSE;
        }
        r->need_rebind = FALSE;
    }

    int rc = mysql_stmt_fetch (r->stmt);
    if (rc == 1) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "mysql_stmt_fetch failed: %s", mysql_stmt_error(r->stmt));
        return FALSE;
    }
    return ((rc == 0) || (rc == MYSQL_DATA_TRUNCATED));
}

const char *
mysql_result_set_get_string (ResultSet *vr, int i, GError **error)
{
    MySQLResultSet *r = (MySQLResultSet *)vr;
    char *ret;

    if (i < 0 || i >= r->column_count) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Column index is out of range.");
        return NULL;
    }

    if (*(r->bind[i].is_null)) {
        return NULL;
    }

    if (!check_mysql_column_size (r, i, error)) {
        return NULL;
    }

    ret = r->bind[i].buffer;
    ret[*(r->bind[i].length)] = 0;
    return ret;
}

int
mysql_result_set_get_column_count (ResultSet *vr)
{
    MySQLResultSet *r = (MySQLResultSet *)vr;

    return r->column_count;
}

typedef struct MySQLDBStmt {
    DBStmt parent;
    int param_count;
    MYSQL_STMT *stmt;
    MYSQL_BIND *bind;
} MySQLDBStmt;

static MySQLDBStmt *
mysql_stmt_new (MYSQL_STMT *stmt)
{
    MySQLDBStmt *p = g_new0 (MySQLDBStmt, 1);

    p->stmt = stmt;
    p->param_count = (int)mysql_stmt_param_count(stmt);
    if (p->param_count>0) {
        p->bind = g_new0 (MYSQL_BIND, p->param_count);
    }

    return p;
}

DBStmt *
mysql_prepare_statement (DBConnection *vconn, const char *sql, GError **error)
{
    MySQLDBConnection *conn = (MySQLDBConnection *)vconn;
    MYSQL_STMT *stmt;
    MySQLDBStmt *ret;

    stmt = prepare (conn->db, sql, error);
    if (!stmt) {
        return NULL;
    }

    ret = mysql_stmt_new (stmt);

    return (DBStmt*)ret;
}

gboolean
mysql_stmt_set_int (DBStmt *vstmt, int i, int x, GError **error)
{
    MySQLDBStmt *stmt = (MySQLDBStmt *)vstmt;
    int *pval;

    if (i < 0 || i >= stmt->param_count) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Column index is out of range.");
        return FALSE;
    }

    pval = g_new (int, 1);
    *pval = x;

    stmt->bind[i].buffer_type = MYSQL_TYPE_LONG;
    stmt->bind[i].buffer = (char *)pval;
    stmt->bind[i].is_null = 0;

    return TRUE;
}

gboolean
mysql_stmt_set_int64 (DBStmt *vstmt, int i, gint64 x, GError **error)
{
    MySQLDBStmt *stmt = (MySQLDBStmt *)vstmt;
    gint64 *pval;

    if (i < 0 || i >= stmt->param_count) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Column index is out of range.");
        return FALSE;
    }

    pval = g_new (gint64, 1);
    *pval = x;

    stmt->bind[i].buffer_type = MYSQL_TYPE_LONGLONG;
    stmt->bind[i].buffer = (char *)pval;
    stmt->bind[i].is_null = 0;

    return TRUE;
}

gboolean
mysql_stmt_set_string (DBStmt *vstmt, int i, const char *s, GError **error)
{
    MySQLDBStmt *stmt = (MySQLDBStmt *)vstmt;
    static my_bool yes = TRUE;
    unsigned long *plen;

    if (i < 0 || i >= stmt->param_count) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Column index is out of range.");
        return FALSE;
    }

    stmt->bind[i].buffer_type = MYSQL_TYPE_STRING;
    stmt->bind[i].buffer = g_strdup(s);
    plen = g_new (unsigned long, 1);
    stmt->bind[i].length = plen;
    if (!s) {
        *plen = 0;
        stmt->bind[i].is_null = &yes;
    } else {
        *plen = strlen(s);
        stmt->bind[i].is_null = 0;
    }

    return TRUE;
}

gboolean
mysql_db_stmt_execute (DBStmt *vstmt, GError **error)
{
    MySQLDBStmt *stmt = (MySQLDBStmt *)vstmt;

    if (stmt->param_count > 0 &&
        mysql_stmt_bind_param (stmt->stmt, stmt->bind) != 0) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "mysql_stmt_bind_param failed: %s",
                     mysql_stmt_error(stmt->stmt));
        return FALSE;
    }

    unsigned long cursor = CURSOR_TYPE_NO_CURSOR;
    mysql_stmt_attr_set (stmt->stmt, STMT_ATTR_CURSOR_TYPE, &cursor);

    if (mysql_stmt_execute (stmt->stmt) != 0) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "mysql_stmt_execute failed: %s", mysql_stmt_error(stmt->stmt));
        return FALSE;
    }

    mysql_stmt_reset (stmt->stmt);

    return TRUE;
}

ResultSet *
mysql_db_stmt_execute_query (DBStmt *vstmt, GError **error)
{
    MySQLDBStmt *stmt = (MySQLDBStmt *)vstmt;

    if (stmt->param_count > 0 &&
        mysql_stmt_bind_param (stmt->stmt, stmt->bind) != 0) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "mysql_stmt_bind_param failed: %s",
                     mysql_stmt_error(stmt->stmt));
        return NULL;
    }

    unsigned long cursor = CURSOR_TYPE_READ_ONLY;
    mysql_stmt_attr_set (stmt->stmt, STMT_ATTR_CURSOR_TYPE, &cursor);

    if (mysql_stmt_execute (stmt->stmt) != 0) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "mysql_stmt_execute failed: %s", mysql_stmt_error(stmt->stmt));
        return NULL;
    }

    MySQLResultSet *r = mysql_result_set_new (stmt->stmt, error);
    if (*error) {
        return NULL;
    }

    return (ResultSet *)r;
}

void
mysql_db_stmt_free (DBStmt *vstmt)
{
    if (!vstmt)
        return;

    MySQLDBStmt *stmt = (MySQLDBStmt *)vstmt;

    /* If there is a result set associated with this stmt, the mysql stmt
     * will be freed when freeing the result set.
     */
    if (!stmt->parent.result_set) {
        mysql_stmt_free_result (stmt->stmt);
        mysql_stmt_close (stmt->stmt);
    }

    int i;
    for (i = 0; i < stmt->param_count; ++i) {
        g_free (stmt->bind[i].buffer);
        g_free (stmt->bind[i].length);
    }
    g_free (stmt->bind);

    g_free (stmt);
}

/* Transaction. */

gboolean
mysql_db_begin_transaction (DBConnection *vconn, GError **error)
{
    MySQLDBConnection *conn = (MySQLDBConnection *)vconn;

    int rc = mysql_query (conn->db, "START TRANSACTION;");
    if (rc != 0) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Failed to begin transaction: %s", mysql_error(conn->db));
    }

    return (rc == 0);
}

gboolean
mysql_db_commit (DBConnection *vconn, GError **error)
{
    MySQLDBConnection *conn = (MySQLDBConnection *)vconn;

    int rc = mysql_query (conn->db, "COMMIT;");
    if (rc != 0) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Failed to commit transaction: %s", mysql_error(conn->db));
    }

    return (rc == 0);
}

gboolean
mysql_db_rollback (DBConnection *vconn, GError **error)
{
    MySQLDBConnection *conn = (MySQLDBConnection *)vconn;

    int rc = mysql_query (conn->db, "ROLLBACK;");
    if (rc != 0) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Failed to rollback transaction: %s", mysql_error(conn->db));
    }

    return (rc == 0);
}
