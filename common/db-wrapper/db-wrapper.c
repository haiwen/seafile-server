#include "common.h"

#include "db-wrapper.h"
#include "mysql-db-ops.h"
#include "sqlite-db-ops.h"
#include "pgsql-db-ops.h"

typedef struct DBOperations {
    void (*db_conn_pool_free) (DBConnPool *);
    DBConnection* (*get_db_connection) (DBConnPool *, GError **);
    void (*db_connection_close) (DBConnection *);
    gboolean (*db_connection_ping) (DBConnection *);
    gboolean (*db_connection_execute) (DBConnection *, const char *, GError **);
    ResultSet* (*db_connection_execute_query) (DBConnection *, const char *, GError **);
    gboolean (*result_set_next) (ResultSet *, GError **);
    const char* (*result_set_get_string) (ResultSet *, int, GError **);
    void (*result_set_free) (ResultSet *);
    int (*result_set_get_column_count) (ResultSet *);
    DBStmt* (*db_connection_prepare_statement) (DBConnection *, const char *, GError **);
    gboolean (*db_stmt_set_int) (DBStmt *, int, int, GError **);
    gboolean (*db_stmt_set_int64) (DBStmt *, int, gint64, GError **);
    gboolean (*db_stmt_set_string) (DBStmt *, int, const char *, GError **);
    gboolean (*db_stmt_execute) (DBStmt *, GError **);
    ResultSet* (*db_stmt_execute_query) (DBStmt *, GError **);
    void (*db_stmt_free) (DBStmt *);
    gboolean (*db_connection_begin_transaction) (DBConnection *, GError **);
    gboolean (*db_connection_commit) (DBConnection *, GError **);
    gboolean (*db_connection_rollback) (DBConnection *, GError **);
} DBOperations;

static DBOperations db_ops;

/* DB Connection Pool. */

static void
init_conn_pool_common (DBConnPool *pool, int max_connections)
{
    pool->connections = g_ptr_array_sized_new (max_connections);
    pthread_mutex_init (&pool->lock, NULL);
    pool->max_connections = max_connections;
}

DBConnPool *
db_conn_pool_new_mysql (const char *host,
                        const char *user,
                        const char *password,
                        unsigned int port,
                        const char *db_name,
                        const char *unix_socket,
                        gboolean use_ssl,
                        const char *charset,
                        int max_connections)
{
    db_ops.db_conn_pool_free = mysql_db_conn_pool_free;
    db_ops.get_db_connection = mysql_get_db_connection;
    db_ops.db_connection_close = mysql_db_connection_close;
    db_ops.db_connection_ping = mysql_db_connection_ping;
    db_ops.db_connection_execute = mysql_db_connection_execute;
    db_ops.db_connection_execute_query = mysql_execute_query;
    db_ops.result_set_next = mysql_result_set_next;
    db_ops.result_set_get_string = mysql_result_set_get_string;
    db_ops.result_set_free = mysql_result_set_free;
    db_ops.result_set_get_column_count = mysql_result_set_get_column_count;
    db_ops.db_connection_prepare_statement = mysql_prepare_statement;
    db_ops.db_stmt_set_int = mysql_stmt_set_int;
    db_ops.db_stmt_set_int64 = mysql_stmt_set_int64;
    db_ops.db_stmt_set_string = mysql_stmt_set_string;
    db_ops.db_stmt_execute = mysql_db_stmt_execute;
    db_ops.db_stmt_execute_query = mysql_db_stmt_execute_query;
    db_ops.db_stmt_free = mysql_db_stmt_free;
    db_ops.db_connection_begin_transaction = mysql_db_begin_transaction;
    db_ops.db_connection_commit = mysql_db_commit;
    db_ops.db_connection_rollback = mysql_db_rollback;

    DBConnPool *pool;

    pool = mysql_db_conn_pool_new (host, user, password, port, db_name, unix_socket,
                                   use_ssl, charset);
    init_conn_pool_common (pool, max_connections);

    return pool;
}

DBConnPool *
db_conn_pool_new_pgsql (const char *host,
                        const char *user,
                        const char *password,
                        const char *db_name,
                        const char *unix_socket,
                        int max_connections)
{
    db_ops.db_conn_pool_free = pgsql_db_conn_pool_free;
    db_ops.get_db_connection = pgsql_get_db_connection;
    db_ops.db_connection_close = pgsql_db_connection_close;
    db_ops.db_connection_ping = pgsql_db_connection_ping;
    db_ops.db_connection_execute = pgsql_db_connection_execute;
    db_ops.db_connection_execute_query = pgsql_execute_query;
    db_ops.result_set_next = pgsql_result_set_next;
    db_ops.result_set_get_string = pgsql_result_set_get_string;
    db_ops.result_set_free = pgsql_result_set_free;
    db_ops.result_set_get_column_count = pgsql_result_set_get_column_count;
    db_ops.db_connection_prepare_statement = pgsql_prepare_statement;
    db_ops.db_stmt_set_int = pgsql_stmt_set_int;
    db_ops.db_stmt_set_int64 = pgsql_stmt_set_int64;
    db_ops.db_stmt_set_string = pgsql_stmt_set_string;
    db_ops.db_stmt_execute = pgsql_db_stmt_execute;
    db_ops.db_stmt_execute_query = pgsql_db_stmt_execute_query;
    db_ops.db_stmt_free = pgsql_db_stmt_free;
    db_ops.db_connection_begin_transaction = pgsql_db_begin_transaction;
    db_ops.db_connection_commit = pgsql_db_commit;
    db_ops.db_connection_rollback = pgsql_db_rollback;

    DBConnPool *pool;

    pool = pgsql_db_conn_pool_new (host, user, password, db_name, unix_socket);
    init_conn_pool_common (pool, max_connections);

    return pool;
}

DBConnPool *
db_conn_pool_new_sqlite (const char *db_path, int max_connections)
{
    db_ops.db_conn_pool_free = sqlite_db_conn_pool_free;
    db_ops.get_db_connection = sqlite_get_db_connection;
    db_ops.db_connection_close = sqlite_db_connection_close;
    db_ops.db_connection_ping = sqlite_db_connection_ping;
    db_ops.db_connection_execute = sqlite_db_connection_execute;
    db_ops.db_connection_execute_query = sqlite_execute_query;
    db_ops.result_set_next = sqlite_result_set_next;
    db_ops.result_set_get_string = sqlite_result_set_get_string;
    db_ops.result_set_free = sqlite_result_set_free;
    db_ops.result_set_get_column_count = sqlite_result_set_get_column_count;
    db_ops.db_connection_prepare_statement = sqlite_prepare_statement;
    db_ops.db_stmt_set_int = sqlite_stmt_set_int;
    db_ops.db_stmt_set_int64 = sqlite_stmt_set_int64;
    db_ops.db_stmt_set_string = sqlite_stmt_set_string;
    db_ops.db_stmt_execute = sqlite_db_stmt_execute;
    db_ops.db_stmt_execute_query = sqlite_db_stmt_execute_query;
    db_ops.db_stmt_free = sqlite_db_stmt_free;
    db_ops.db_connection_begin_transaction = sqlite_db_begin_transaction;
    db_ops.db_connection_commit = sqlite_db_commit;
    db_ops.db_connection_rollback = sqlite_db_rollback;

    DBConnPool *pool;

    pool = sqlite_db_conn_pool_new (db_path);
    init_conn_pool_common (pool, max_connections);

    return pool;
}

void
db_conn_pool_free (DBConnPool *pool)
{
    g_ptr_array_free (pool->connections, TRUE);
    pthread_mutex_destroy (&pool->lock);

    return db_ops.db_conn_pool_free (pool);
}

/* DB Connections. */

DBConnection *
db_conn_pool_get_connection (DBConnPool *pool, GError **error)
{
    DBConnection *conn = NULL;

    pthread_mutex_lock (&pool->lock);

    guint i, size = pool->connections->len;
    for (i = 0; i < size; ++i) {
        conn = g_ptr_array_index (pool->connections, i);
        if (conn->is_available && db_connection_ping (conn)) {
            conn->is_available = FALSE;
            goto out;
        }
    }
    conn = NULL;
    if (size < pool->max_connections) {
        conn = db_ops.get_db_connection (pool, error);
        if (conn) {
            conn->is_available = TRUE;
            conn->pool = pool;
            g_ptr_array_add (pool->connections, conn);
        }
    }

out:
    pthread_mutex_unlock (&pool->lock);
    return conn;
}

static void
db_connection_clear (DBConnection *conn)
{
    result_set_free (conn->result_set);
    db_stmt_free (conn->stmt);
    conn->result_set = NULL;
    conn->stmt = NULL;
}

void
db_connection_close (DBConnection *conn)
{
    if (!conn)
        return;

    if (conn->in_transaction)
        db_connection_rollback (conn, NULL);

    db_connection_clear (conn);

    pthread_mutex_lock (&conn->pool->lock);
    conn->is_available = TRUE;
    pthread_mutex_unlock (&conn->pool->lock);
}

gboolean
db_connection_execute (DBConnection *conn, const char *sql, GError **error)
{
    return db_ops.db_connection_execute (conn, sql, error);
}

gboolean
db_connection_ping (DBConnection *conn)
{
    return db_ops.db_connection_ping (conn);
}

/* Result Sets. */

void
result_set_free (ResultSet *r)
{
    if (!r)
        return;

    return db_ops.result_set_free (r);
}

ResultSet *
db_connection_execute_query (DBConnection *conn, const char *sql, GError **error)
{
    ResultSet *result_set;

    if (conn->result_set) {
        result_set_free (conn->result_set);
        conn->result_set = NULL;
    }

    result_set = db_ops.db_connection_execute_query (conn, sql, error);

    if (result_set)
        conn->result_set = result_set;

    return result_set;
}

gboolean
result_set_next (ResultSet *r, GError **error)
{
    return db_ops.result_set_next (r, error);
}

const char *
result_set_get_string (ResultSet *r, int idx, GError **error)
{
    return db_ops.result_set_get_string (r, idx, error);
}

int
result_set_get_int (ResultSet *r, int idx, GError **error)
{
    const char *str;
    char *e;
    int ret;

    str = db_ops.result_set_get_string (r, idx, error);
    if (*error) {
        return -1;
    }

    if (!str) {
        return 0;
    }

    errno = 0;
    ret = strtol (str, &e, 10);
    if (errno || (e == str)) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Number conversion failed.");
        return -1;
    }

    return ret;
}

gint64
result_set_get_int64 (ResultSet *r, int idx, GError **error)
{
    const char *str;
    char *e;
    gint64 ret;

    str = db_ops.result_set_get_string (r, idx, error);
    if (*error) {
        return -1;
    }

    if (!str) {
        return 0;
    }

    errno = 0;
    ret = strtoll (str, &e, 10);
    if (errno || (e == str)) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Number conversion failed.");
        return -1;
    }

    return ret;
}

int
result_set_get_column_count (ResultSet *r)
{
    return db_ops.result_set_get_column_count (r);
}

/* Prepared Statements. */

DBStmt *
db_connection_prepare_statement (DBConnection *conn, const char *sql, GError **error)
{
    DBStmt *stmt;

    if (conn->stmt) {
        db_stmt_free (conn->stmt);
        conn->stmt = NULL;
    }

    stmt = db_ops.db_connection_prepare_statement (conn, sql, error);

    if (stmt)
        conn->stmt = stmt;

    return stmt;
}

int
db_stmt_set_int (DBStmt *stmt, int idx, int x, GError **error)
{
    return db_ops.db_stmt_set_int (stmt, idx, x, error);
}

int
db_stmt_set_int64 (DBStmt *stmt, int idx, gint64 x, GError **error)
{
    return db_ops.db_stmt_set_int64 (stmt, idx, x, error);
}

int
db_stmt_set_string (DBStmt *stmt, int idx, const char *s, GError **error)
{
    return db_ops.db_stmt_set_string (stmt, idx, s, error);
}

gboolean
db_stmt_execute (DBStmt *stmt, GError **error)
{
    return db_ops.db_stmt_execute (stmt, error);
}

ResultSet *
db_stmt_execute_query (DBStmt *stmt, GError **error)
{
    ResultSet *result_set;

    if (stmt->result_set) {
        result_set_free (stmt->result_set);
        stmt->result_set = NULL;
    }

    result_set = db_ops.db_stmt_execute_query (stmt, error);

    if (result_set)
        stmt->result_set = result_set;

    return result_set;
}

void
db_stmt_free (DBStmt *stmt)
{
    if (!stmt)
        return;

    if (stmt->result_set)
        result_set_free (stmt->result_set);

    return db_ops.db_stmt_free (stmt);
}

/* Transactions. */

gboolean
db_connection_begin_transaction (DBConnection *conn, GError **error)
{
    gboolean ret;

    ret = db_ops.db_connection_begin_transaction (conn, error);
    if (ret)
        conn->in_transaction++;

    return ret;
}

gboolean
db_connection_commit (DBConnection *conn, GError **error)
{
    if (conn->in_transaction)
        conn->in_transaction = 0;

    return db_ops.db_connection_commit (conn, error);
}

gboolean
db_connection_rollback (DBConnection *conn, GError **error)
{
    if (conn->in_transaction) {
        db_connection_clear (conn);
        conn->in_transaction = 0;
    }

    return db_ops.db_connection_rollback (conn, error);
}
