
#include "common.h"

#include "log.h"

#include "seaf-db.h"

#include <stdarg.h>
#ifdef HAVE_MYSQL
#include <mysql.h>
#endif
#ifdef HAVE_POSTGRES
#include <libpq-fe.h>
#endif
#include <sqlite3.h>
#include <pthread.h>

struct DBConnPool {
    GPtrArray *connections;
    pthread_mutex_t lock;
    int max_connections;
};
typedef struct DBConnPool DBConnPool;

struct SeafDB {
    int type;
    DBConnPool *pool;
};

typedef struct DBConnection {
    gboolean is_available;
    DBConnPool *pool;
} DBConnection;

struct SeafDBRow {
    /* Empty */
};

struct SeafDBTrans {
    DBConnection *conn;
    gboolean need_close;
};

typedef struct DBOperations {
    DBConnection* (*get_connection)(SeafDB *db);
    void (*release_connection)(DBConnection *conn, gboolean need_close);
    int (*execute_sql_no_stmt)(DBConnection *conn, const char *sql);
    int (*execute_sql)(DBConnection *conn, const char *sql,
                       int n, va_list args);
    int (*query_foreach_row)(DBConnection *conn,
                             const char *sql, SeafDBRowFunc callback, void *data,
                             int n, va_list args);
    int (*row_get_column_count)(SeafDBRow *row);
    const char* (*row_get_column_string)(SeafDBRow *row, int idx);
    int (*row_get_column_int)(SeafDBRow *row, int idx);
    gint64 (*row_get_column_int64)(SeafDBRow *row, int idx);
} DBOperations;

static DBOperations db_ops;

#ifdef HAVE_MYSQL

/* MySQL Ops */
static SeafDB *
mysql_db_new (const char *host,
              int port,
              const char *user,
              const char *password,
              const char *db_name,
              const char *unix_socket,
              gboolean use_ssl,
              const char *charset);
static DBConnection *
mysql_db_get_connection (SeafDB *db);
static void
mysql_db_release_connection (DBConnection *vconn);
static int
mysql_db_execute_sql_no_stmt (DBConnection *vconn, const char *sql);
static int
mysql_db_execute_sql (DBConnection *vconn, const char *sql, int n, va_list args);
static int
mysql_db_query_foreach_row (DBConnection *vconn, const char *sql,
                            SeafDBRowFunc callback, void *data,
                            int n, va_list args);
static int
mysql_db_row_get_column_count (SeafDBRow *row);
static const char *
mysql_db_row_get_column_string (SeafDBRow *row, int idx);
static int
mysql_db_row_get_column_int (SeafDBRow *row, int idx);
static gint64
mysql_db_row_get_column_int64 (SeafDBRow *row, int idx);
static gboolean
mysql_db_connection_ping (DBConnection *vconn);

static DBConnPool *
mysql_init_conn_pool_common (int max_connections)
{
    DBConnPool *pool = g_new0(DBConnPool, 1);
    pool->connections = g_ptr_array_sized_new (max_connections);
    pthread_mutex_init (&pool->lock, NULL);
    pool->max_connections = max_connections;

    return pool;
}

static DBConnection *
mysql_conn_pool_get_connection (SeafDB *db)
{
    DBConnPool *pool = db->pool;
    DBConnection *conn = NULL;

    if (pool->max_connections == 0) {
        conn = mysql_db_get_connection (db);
        conn->pool = pool;
        return conn;
    }

    pthread_mutex_lock (&pool->lock);

    guint i, size = pool->connections->len;
    for (i = 0; i < size; ++i) {
        conn = g_ptr_array_index (pool->connections, i);
        if (conn->is_available && mysql_db_connection_ping (conn)) {
            conn->is_available = FALSE;
            goto out;
        }
    }
    conn = NULL;
    if (size < pool->max_connections) {
        conn = mysql_db_get_connection (db);
        if (conn) {
            conn->pool = pool;
            conn->is_available = FALSE;
            g_ptr_array_add (pool->connections, conn);
        }
    }

out:
    pthread_mutex_unlock (&pool->lock);
    return conn;
}

static void
mysql_conn_pool_release_connection (DBConnection *conn, gboolean need_close)
{
    if (!conn)
        return;

    if (conn->pool->max_connections == 0) {
        mysql_db_release_connection (conn);
        return;
    }

    if (need_close) {
        pthread_mutex_lock (&conn->pool->lock);
        g_ptr_array_remove (conn->pool->connections, conn);
        pthread_mutex_unlock (&conn->pool->lock);
        mysql_db_release_connection (conn);
        return;
    }

    pthread_mutex_lock (&conn->pool->lock);
    conn->is_available = TRUE;
    pthread_mutex_unlock (&conn->pool->lock);
}

#define KEEPALIVE_INTERVAL 30
static void *
mysql_conn_keepalive (void *arg)
{
    DBConnPool *pool = arg;
    DBConnection *conn = NULL;

    while (1) {
        pthread_mutex_lock (&pool->lock);

        guint i, size = pool->connections->len;
        for (i = 0; i < size; ++i) {
            conn = g_ptr_array_index (pool->connections, i);
            if (conn->is_available) {
                mysql_db_connection_ping (conn);
            }
        }
        pthread_mutex_unlock (&pool->lock);

        sleep (KEEPALIVE_INTERVAL);
    }

    return NULL;
}

SeafDB *
seaf_db_new_mysql (const char *host,
                   int port,
                   const char *user, 
                   const char *passwd,
                   const char *db_name,
                   const char *unix_socket,
                   gboolean use_ssl,
                   const char *charset,
                   int max_connections)
{
    SeafDB *db;

    db = mysql_db_new (host, port, user, passwd, db_name, unix_socket, use_ssl, charset);
    if (!db)
        return NULL;
    db->type = SEAF_DB_TYPE_MYSQL;

    db_ops.get_connection = mysql_conn_pool_get_connection;
    db_ops.release_connection = mysql_conn_pool_release_connection;
    db_ops.execute_sql_no_stmt = mysql_db_execute_sql_no_stmt;
    db_ops.execute_sql = mysql_db_execute_sql;
    db_ops.query_foreach_row = mysql_db_query_foreach_row;
    db_ops.row_get_column_count = mysql_db_row_get_column_count;
    db_ops.row_get_column_string = mysql_db_row_get_column_string;
    db_ops.row_get_column_int = mysql_db_row_get_column_int;
    db_ops.row_get_column_int64 = mysql_db_row_get_column_int64;

    db->pool = mysql_init_conn_pool_common (max_connections);

    pthread_t tid;
    int ret = pthread_create (&tid, NULL, mysql_conn_keepalive, db->pool);
    if (ret != 0) {
        seaf_warning ("Failed to create mysql connection keepalive thread.\n");
        return NULL;
    }
    pthread_detach (tid);

    return db;
}

#endif

#ifdef HAVE_POSTGRES

/* Popstgres Ops */
static SeafDB *
pgsql_db_new (const char *host,
              int port,
              const char *user,
              const char *password,
              const char *db_name,
              const char *unix_socket,
              gboolean use_ssl);
static DBConnection *
pgsql_db_get_connection (SeafDB *db);
static void
pgsql_db_release_connection (DBConnection *vconn);
static int
pgsql_db_execute_sql_no_stmt (DBConnection *vconn, const char *sql);
static int
pgsql_db_execute_sql (DBConnection *vconn, const char *sql, int n, va_list args);
static int
pgsql_db_query_foreach_row (DBConnection *vconn, const char *sql,
                            SeafDBRowFunc callback, void *data,
                            int n, va_list args);
static int
pgsql_db_row_get_column_count (SeafDBRow *row);
static const char *
pgsql_db_row_get_column_string (SeafDBRow *row, int idx);
static int
pgsql_db_row_get_column_int (SeafDBRow *row, int idx);
static gint64
pgsql_db_row_get_column_int64 (SeafDBRow *row, int idx);
static gboolean
pgsql_db_connection_ping (DBConnection *vconn);

static DBConnPool *
pgsql_init_conn_pool_common (int max_connections)
{
    DBConnPool *pool = g_new0(DBConnPool, 1);
    pool->connections = g_ptr_array_sized_new (max_connections);
    pthread_mutex_init (&pool->lock, NULL);
    pool->max_connections = max_connections;

    return pool;
}

static DBConnection *
pgsql_conn_pool_get_connection (SeafDB *db)
{
    DBConnPool *pool = db->pool;
    DBConnection *conn = NULL;

    if (pool->max_connections == 0) {
        conn = pgsql_db_get_connection (db);
        conn->pool = pool;
        return conn;
    }

    pthread_mutex_lock (&pool->lock);

    guint i, size = pool->connections->len;
    for (i = 0; i < size; ++i) {
        conn = g_ptr_array_index (pool->connections, i);
        if (conn->is_available && pgsql_db_connection_ping (conn)) {
            conn->is_available = FALSE;
            goto out;
        }
    }
    conn = NULL;
    if (size < pool->max_connections) {
        conn = pgsql_db_get_connection (db);
        if (conn) {
            conn->pool = pool;
            conn->is_available = FALSE;
            g_ptr_array_add (pool->connections, conn);
        }
    }

out:
    pthread_mutex_unlock (&pool->lock);
    return conn;
}

static void
pgsql_conn_pool_release_connection (DBConnection *conn, gboolean need_close)
{
    if (!conn)
        return;

    if (conn->pool->max_connections == 0) {
        pgsql_db_release_connection (conn);
        return;
    }

    if (need_close) {
        pthread_mutex_lock (&conn->pool->lock);
        g_ptr_array_remove (conn->pool->connections, conn);
        pthread_mutex_unlock (&conn->pool->lock);
        pgsql_db_release_connection (conn);
        return;
    }

    pthread_mutex_lock (&conn->pool->lock);
    conn->is_available = TRUE;
    pthread_mutex_unlock (&conn->pool->lock);
}

#define KEEPALIVE_INTERVAL 30
static void *
pgsql_conn_keepalive (void *arg)
{
    DBConnPool *pool = arg;
    DBConnection *conn = NULL;

    while (1) {
        pthread_mutex_lock (&pool->lock);

        guint i, size = pool->connections->len;
        for (i = 0; i < size; ++i) {
            conn = g_ptr_array_index (pool->connections, i);
            if (conn->is_available) {
                pgsql_db_connection_ping (conn);
            }
        }
        pthread_mutex_unlock (&pool->lock);

        sleep (KEEPALIVE_INTERVAL);
    }

    return NULL;
}

SeafDB *
seaf_db_new_pgsql (const char *host,
                   int port,
                   const char *user, 
                   const char *passwd,
                   const char *db_name,
                   const char *unix_socket,
                   gboolean use_ssl,
                   int max_connections)
{
    SeafDB *db;

    db = pgsql_db_new (host, port, user, passwd, db_name, unix_socket, use_ssl);
    if (!db)
        return NULL;
    db->type = SEAF_DB_TYPE_PGSQL;

    db_ops.get_connection = pgsql_conn_pool_get_connection;
    db_ops.release_connection = pgsql_conn_pool_release_connection;
    db_ops.execute_sql_no_stmt = pgsql_db_execute_sql_no_stmt;
    db_ops.execute_sql = pgsql_db_execute_sql;
    db_ops.query_foreach_row = pgsql_db_query_foreach_row;
    db_ops.row_get_column_count = pgsql_db_row_get_column_count;
    db_ops.row_get_column_string = pgsql_db_row_get_column_string;
    db_ops.row_get_column_int = pgsql_db_row_get_column_int;
    db_ops.row_get_column_int64 = pgsql_db_row_get_column_int64;

    db->pool = pgsql_init_conn_pool_common (max_connections);

    pthread_t tid;
    int ret = pthread_create (&tid, NULL, pgsql_conn_keepalive, db->pool);
    if (ret != 0) {
        seaf_warning ("Failed to create pgsql connection keepalive thread.\n");
        return NULL;
    }
    pthread_detach (tid);

    return db;
}

#endif

/* SQLite Ops */
static SeafDB *
sqlite_db_new (const char *db_path);
static DBConnection *
sqlite_db_get_connection (SeafDB *db);
static void
sqlite_db_release_connection (DBConnection *vconn, gboolean need_close);
static int
sqlite_db_execute_sql_no_stmt (DBConnection *vconn, const char *sql);
static int
sqlite_db_execute_sql (DBConnection *vconn, const char *sql, int n, va_list args);
static int
sqlite_db_query_foreach_row (DBConnection *vconn, const char *sql,
                             SeafDBRowFunc callback, void *data,
                             int n, va_list args);
static int
sqlite_db_row_get_column_count (SeafDBRow *row);
static const char *
sqlite_db_row_get_column_string (SeafDBRow *row, int idx);
static int
sqlite_db_row_get_column_int (SeafDBRow *row, int idx);
static gint64
sqlite_db_row_get_column_int64 (SeafDBRow *row, int idx);

SeafDB *
seaf_db_new_sqlite (const char *db_path, int max_connections)
{
    SeafDB *db;

    db = sqlite_db_new (db_path);
    if (!db)
        return NULL;
    db->type = SEAF_DB_TYPE_SQLITE;

    db_ops.get_connection = sqlite_db_get_connection;
    db_ops.release_connection = sqlite_db_release_connection;
    db_ops.execute_sql_no_stmt = sqlite_db_execute_sql_no_stmt;
    db_ops.execute_sql = sqlite_db_execute_sql;
    db_ops.query_foreach_row = sqlite_db_query_foreach_row;
    db_ops.row_get_column_count = sqlite_db_row_get_column_count;
    db_ops.row_get_column_string = sqlite_db_row_get_column_string;
    db_ops.row_get_column_int = sqlite_db_row_get_column_int;
    db_ops.row_get_column_int64 = sqlite_db_row_get_column_int64;

    return db;
}

int
seaf_db_type (SeafDB *db)
{
    return db->type;
}

int
seaf_db_query (SeafDB *db, const char *sql)
{
    DBConnection *conn = db_ops.get_connection (db);
    if (!conn)
        return -1;

    int ret;
    ret = db_ops.execute_sql_no_stmt (conn, sql);

    db_ops.release_connection (conn, ret < 0);
    return ret;
}

gboolean
seaf_db_check_for_existence (SeafDB *db, const char *sql, gboolean *db_err)
{
    return seaf_db_statement_exists (db, sql, db_err, 0);
}

int
seaf_db_foreach_selected_row (SeafDB *db, const char *sql, 
                              SeafDBRowFunc callback, void *data)
{
    return seaf_db_statement_foreach_row (db, sql, callback, data, 0);
}

const char *
seaf_db_row_get_column_text (SeafDBRow *row, guint32 idx)
{
    g_return_val_if_fail (idx < db_ops.row_get_column_count(row), NULL);

    return db_ops.row_get_column_string (row, idx);
}

int
seaf_db_row_get_column_int (SeafDBRow *row, guint32 idx)
{
    g_return_val_if_fail (idx < db_ops.row_get_column_count(row), -1);

    return db_ops.row_get_column_int (row, idx);
}

gint64
seaf_db_row_get_column_int64 (SeafDBRow *row, guint32 idx)
{
    g_return_val_if_fail (idx < db_ops.row_get_column_count(row), -1);

    return db_ops.row_get_column_int64 (row, idx);
}

int
seaf_db_get_int (SeafDB *db, const char *sql)
{
    return seaf_db_statement_get_int (db, sql, 0);
}

gint64
seaf_db_get_int64 (SeafDB *db, const char *sql)
{
    return seaf_db_statement_get_int64 (db, sql, 0);
}

char *
seaf_db_get_string (SeafDB *db, const char *sql)
{
    return seaf_db_statement_get_string (db, sql, 0);
}

int
seaf_db_statement_query (SeafDB *db, const char *sql, int n, ...)
{
    int ret;
    DBConnection *conn = NULL;

    conn = db_ops.get_connection (db);
    if (!conn)
        return -1;

    va_list args;
    va_start (args, n);
    ret = db_ops.execute_sql (conn, sql, n, args);
    va_end (args);

    db_ops.release_connection (conn, ret < 0);

    return ret;
}

gboolean
seaf_db_statement_exists (SeafDB *db, const char *sql, gboolean *db_err, int n, ...)
{
    int n_rows;
    DBConnection *conn = NULL;

    conn = db_ops.get_connection(db);
    if (!conn) {
        *db_err = TRUE;
        return FALSE;
    }

    va_list args;
    va_start (args, n);
    n_rows = db_ops.query_foreach_row (conn, sql, NULL, NULL, n, args);
    va_end (args);

    db_ops.release_connection(conn, n_rows < 0);

    if (n_rows < 0) {
        *db_err = TRUE;
        return FALSE;
    } else {
        *db_err = FALSE;
        return (n_rows != 0);
    }
}

int
seaf_db_statement_foreach_row (SeafDB *db, const char *sql,
                               SeafDBRowFunc callback, void *data,
                               int n, ...)
{
    int ret;
    DBConnection *conn = NULL;

    conn = db_ops.get_connection (db);
    if (!conn)
        return -1;

    va_list args;
    va_start (args, n);
    ret = db_ops.query_foreach_row (conn, sql, callback, data, n, args);
    va_end (args);

    db_ops.release_connection (conn, ret < 0);

    return ret;
}

static gboolean
get_int_cb (SeafDBRow *row, void *data)
{
    int *pret = (int*)data;

    *pret = seaf_db_row_get_column_int (row, 0);

    return FALSE;
}

int
seaf_db_statement_get_int (SeafDB *db, const char *sql, int n, ...)
{
    int ret = -1;
    int rc;
    DBConnection *conn = NULL;

    conn = db_ops.get_connection (db);
    if (!conn)
        return -1;

    va_list args;
    va_start (args, n);
    rc = db_ops.query_foreach_row (conn, sql, get_int_cb, &ret, n, args);
    va_end (args);

    db_ops.release_connection (conn, rc < 0);

    if (rc < 0)
        return -1;

    return ret;
}

static gboolean
get_int64_cb (SeafDBRow *row, void *data)
{
    gint64 *pret = (gint64*)data;

    *pret = seaf_db_row_get_column_int64 (row, 0);

    return FALSE;
}

gint64
seaf_db_statement_get_int64 (SeafDB *db, const char *sql, int n, ...)
{
    gint64 ret = -1;
    int rc;
    DBConnection *conn = NULL;

    conn = db_ops.get_connection (db);
    if (!conn)
        return -1;

    va_list args;
    va_start (args, n);
    rc = db_ops.query_foreach_row (conn, sql, get_int64_cb, &ret, n, args);
    va_end(args);

    db_ops.release_connection (conn, rc < 0);

    if (rc < 0)
        return -1;

    return ret;
}

static gboolean
get_string_cb (SeafDBRow *row, void *data)
{
    char **pret = (char**)data;

    *pret = g_strdup(seaf_db_row_get_column_text (row, 0));

    return FALSE;
}

char *
seaf_db_statement_get_string (SeafDB *db, const char *sql, int n, ...)
{
    char *ret = NULL;
    int rc;
    DBConnection *conn = NULL;

    conn = db_ops.get_connection (db);
    if (!conn)
        return NULL;

    va_list args;
    va_start (args, n);
    rc = db_ops.query_foreach_row (conn, sql, get_string_cb, &ret, n, args);
    va_end(args);

    db_ops.release_connection (conn, rc < 0);

    if (rc < 0)
        return NULL;

    return ret;
}

/* Transaction */

SeafDBTrans *
seaf_db_begin_transaction (SeafDB *db)
{
    SeafDBTrans *trans = NULL;
    DBConnection *conn = db_ops.get_connection(db);
    if (!conn) {
        return trans;
    }

    if (db_ops.execute_sql_no_stmt (conn, "BEGIN") < 0) {
        db_ops.release_connection (conn, TRUE);
        return trans;
    }

    trans = g_new0 (SeafDBTrans, 1);
    trans->conn = conn;

    return trans;
}

void
seaf_db_trans_close (SeafDBTrans *trans)
{
    db_ops.release_connection (trans->conn, trans->need_close);
    g_free (trans);
}

int
seaf_db_commit (SeafDBTrans *trans)
{
    DBConnection *conn = trans->conn;

    if (db_ops.execute_sql_no_stmt (conn, "COMMIT") < 0) {
        trans->need_close = TRUE;
        return -1;
    }

    return 0;
}

int
seaf_db_rollback (SeafDBTrans *trans)
{
    DBConnection *conn = trans->conn;

    if (db_ops.execute_sql_no_stmt (conn, "ROLLBACK") < 0) {
        trans->need_close = TRUE;
        return -1;
    }

    return 0;
}

int
seaf_db_trans_query (SeafDBTrans *trans, const char *sql, int n, ...)
{
    int ret;

    va_list args;
    va_start (args, n);
    ret = db_ops.execute_sql (trans->conn, sql, n, args);
    va_end (args);

    if (ret < 0)
        trans->need_close = TRUE;

    return ret;
}

gboolean
seaf_db_trans_check_for_existence (SeafDBTrans *trans,
                                   const char *sql,
                                   gboolean *db_err,
                                   int n, ...)
{
    int n_rows;

    va_list args;
    va_start (args, n);
    n_rows = db_ops.query_foreach_row (trans->conn, sql, NULL, NULL, n, args);
    va_end (args);

    if (n_rows < 0) {
        trans->need_close = TRUE;
        *db_err = TRUE;
        return FALSE;
    } else {
        *db_err = FALSE;
        return (n_rows != 0);
    }
}

int
seaf_db_trans_foreach_selected_row (SeafDBTrans *trans, const char *sql, 
                                    SeafDBRowFunc callback, void *data,
                                    int n, ...)
{
    int ret;

    va_list args;
    va_start (args, n);
    ret = db_ops.query_foreach_row (trans->conn, sql, callback, data, n, args);
    va_end (args);

    if (ret < 0)
        trans->need_close = TRUE;

    return ret;
}

int
seaf_db_row_get_column_count (SeafDBRow *row)
{
    return db_ops.row_get_column_count(row);
}

#ifdef HAVE_MYSQL

/* MySQL DB */

typedef struct MySQLDB {
    struct SeafDB parent;
    char *host;
    char *user;
    char *password;
    unsigned int port;
    char *db_name;
    char *unix_socket;
    gboolean use_ssl;
    char *charset;
} MySQLDB;

typedef struct MySQLDBConnection {
    struct DBConnection parent;
    MYSQL *db_conn;
} MySQLDBConnection;

static gboolean
mysql_db_connection_ping (DBConnection *vconn)
{
    MySQLDBConnection *conn = (MySQLDBConnection *)vconn;

    return (mysql_ping (conn->db_conn) == 0);
}

static SeafDB *
mysql_db_new (const char *host,
              int port,
              const char *user,
              const char *password,
              const char *db_name,
              const char *unix_socket,
              gboolean use_ssl,
              const char *charset)
{
    MySQLDB *db = g_new0 (MySQLDB, 1);

    db->host = g_strdup (host);
    db->user = g_strdup (user);
    db->password = g_strdup (password);
    db->port = port;
    db->db_name = g_strdup(db_name);
    db->unix_socket = g_strdup(unix_socket);
    db->use_ssl = use_ssl;
    db->charset = g_strdup(charset);

    mysql_library_init (0, NULL, NULL);

    return (SeafDB *)db;
}

typedef char my_bool;

static DBConnection *
mysql_db_get_connection (SeafDB *vdb)
{
    MySQLDB *db = (MySQLDB *)vdb;
    my_bool yes = 1;
    int conn_timeout = 1;
    int read_write_timeout = 5;
    MYSQL *db_conn;
    MySQLDBConnection *conn = NULL;

    db_conn = mysql_init (NULL);
    if (!db_conn) {
        seaf_warning ("Failed to init mysql connection object.\n");
        return NULL;
    }

    if (db->use_ssl)
        mysql_ssl_set(db_conn, 0,0,0,0,0);

    if (db->charset)
        mysql_options(db_conn, MYSQL_SET_CHARSET_NAME, db->charset);

    mysql_options(db_conn, MYSQL_OPT_CONNECT_TIMEOUT, (const char*)&conn_timeout);
    mysql_options(db_conn, MYSQL_OPT_RECONNECT, (const char*)&yes);
    mysql_options(db_conn, MYSQL_OPT_READ_TIMEOUT, (const char*)&read_write_timeout);
    mysql_options(db_conn, MYSQL_OPT_WRITE_TIMEOUT, (const char*)&read_write_timeout);

    if (!mysql_real_connect(db_conn, db->host, db->user, db->password,
                            db->db_name, db->port,
                            db->unix_socket, CLIENT_MULTI_STATEMENTS)) {
        seaf_warning ("Failed to connect to MySQL: %s\n", mysql_error(db_conn));
        mysql_close (db_conn);
        return NULL;
    }

    conn = g_new0 (MySQLDBConnection, 1);
    conn->db_conn = db_conn;

    return (DBConnection *)conn;
}

static void
mysql_db_release_connection (DBConnection *vconn)
{
    if (!vconn)
        return;

    MySQLDBConnection *conn = (MySQLDBConnection *)vconn;

    mysql_close (conn->db_conn);

    g_free (conn);
}

static int
mysql_db_execute_sql_no_stmt (DBConnection *vconn, const char *sql)
{
    MySQLDBConnection *conn = (MySQLDBConnection *)vconn;

    if (mysql_query (conn->db_conn, sql) != 0) {
        seaf_warning ("Failed to execute sql %s: %s\n", sql, mysql_error(conn->db_conn));
        return -1;
    }

    return 0;
}

static MYSQL_STMT *
_prepare_stmt_mysql (MYSQL *db, const char *sql)
{
    MYSQL_STMT *stmt;

    stmt = mysql_stmt_init (db);
    if (!stmt) {
        seaf_warning ("mysql_stmt_init failed.\n");
        return NULL;
    }

    if (mysql_stmt_prepare (stmt, sql, strlen(sql)) != 0) {
        seaf_warning ("Failed to prepare sql %s: %s\n", sql, mysql_stmt_error(stmt));
        mysql_stmt_close (stmt);
        return NULL;
    }

    return stmt;
}

static int
_bind_params_mysql (MYSQL_STMT *stmt, MYSQL_BIND *params, int n, va_list args)
{
    int i;
    const char *type;

    for (i = 0; i < n; ++i) {
        type = va_arg (args, const char *);
        if (strcmp(type, "int") == 0) {
            int x = va_arg (args, int);
            int *pval = g_new (int, 1);
            *pval = x;
            params[i].buffer_type = MYSQL_TYPE_LONG;
            params[i].buffer = pval;
            params[i].is_null = 0;
        } else if (strcmp (type, "int64") == 0) {
            gint64 x = va_arg (args, gint64);
            gint64 *pval = g_new (gint64, 1);
            *pval = x;
            params[i].buffer_type = MYSQL_TYPE_LONGLONG;
            params[i].buffer = pval;
            params[i].is_null = 0;
        } else if (strcmp (type, "string") == 0) {
            const char *s = va_arg (args, const char *);
            static my_bool yes = TRUE;
            params[i].buffer_type = MYSQL_TYPE_STRING;
            params[i].buffer = g_strdup(s);
            unsigned long *plen = g_new (unsigned long, 1);
            params[i].length = plen;
            if (!s) {
                *plen = 0;
                params[i].buffer_length = 0;
                params[i].is_null = &yes;
            } else {
                *plen = strlen(s);
                params[i].buffer_length = *plen + 1;
                params[i].is_null = 0;
            }
        } else {
            seaf_warning ("BUG: invalid prep stmt parameter type %s.\n", type);
            g_return_val_if_reached (-1);
        }
    }

    if (mysql_stmt_bind_param (stmt, params) != 0) {
        return -1;
    }

    return 0;
}

static int
mysql_db_execute_sql (DBConnection *vconn, const char *sql, int n, va_list args)
{
    MySQLDBConnection *conn = (MySQLDBConnection *)vconn;
    MYSQL *db = conn->db_conn;
    MYSQL_STMT *stmt = NULL;
    MYSQL_BIND *params = NULL;
    int ret = 0;

    stmt = _prepare_stmt_mysql (db, sql);
    if (!stmt) {
        return -1;
    }

    if (n > 0) {
        params = g_new0 (MYSQL_BIND, n);
        if (_bind_params_mysql (stmt, params, n, args) < 0) {
            seaf_warning ("Failed to bind parameters for %s: %s.\n",
                          sql, mysql_stmt_error(stmt));
            ret = -1;
            goto out;
        }
    }

    if (mysql_stmt_execute (stmt) != 0) {
        seaf_warning ("Failed to execute sql %s: %s\n", sql, mysql_stmt_error(stmt));
        ret = -1;
        goto out;
    }

out:
    if (stmt)
        mysql_stmt_close (stmt);
    if (params) {
        int i;
        for (i = 0; i < n; ++i) {
            g_free (params[i].buffer);
            g_free (params[i].length);
        }
        g_free (params);
    }
    return ret;
}

typedef struct MySQLDBRow {
    SeafDBRow parent;
    int column_count;
    MYSQL_STMT *stmt;
    MYSQL_BIND *results;
    /* Used when returned columns are truncated. */
    MYSQL_BIND *new_binds;
} MySQLDBRow;

#define DEFAULT_MYSQL_COLUMN_SIZE 1024

static int
mysql_db_query_foreach_row (DBConnection *vconn, const char *sql,
                            SeafDBRowFunc callback, void *data,
                            int n, va_list args)
{
    MySQLDBConnection *conn = (MySQLDBConnection *)vconn;
    MYSQL *db = conn->db_conn;
    MYSQL_STMT *stmt = NULL;
    MYSQL_BIND *params = NULL;
    MySQLDBRow row;
    int nrows = 0;
    int i;

    memset (&row, 0, sizeof(row));

    stmt = _prepare_stmt_mysql (db, sql);
    if (!stmt) {
        return -1;
    }

    if (n > 0) {
        params = g_new0 (MYSQL_BIND, n);
        if (_bind_params_mysql (stmt, params, n, args) < 0) {
            nrows = -1;
            goto out;
        }
    }

    if (mysql_stmt_execute (stmt) != 0) {
        seaf_warning ("Failed to execute sql %s: %s\n", sql, mysql_stmt_error(stmt));
        nrows = -1;
        goto out;
    }

    row.column_count = mysql_stmt_field_count (stmt);
    row.stmt = stmt;
    row.results = g_new0 (MYSQL_BIND, row.column_count);
    for (i = 0; i < row.column_count; ++i) {
        row.results[i].buffer = g_malloc (DEFAULT_MYSQL_COLUMN_SIZE + 1);
        /* Ask MySQL to convert fields to string, to avoid the trouble of
         * checking field types.
         */
        row.results[i].buffer_type = MYSQL_TYPE_STRING;
        row.results[i].buffer_length = DEFAULT_MYSQL_COLUMN_SIZE;
        row.results[i].length = g_new0 (unsigned long, 1);
        row.results[i].is_null = g_new0 (my_bool, 1);
    }
    row.new_binds = g_new0 (MYSQL_BIND, row.column_count);

    if (mysql_stmt_bind_result (stmt, row.results) != 0) {
        seaf_warning ("Failed to bind result for sql %s: %s\n", sql, mysql_stmt_error(stmt));
        nrows = -1;
        goto out;
    }

    int rc;
    gboolean next_row = TRUE;
    while (1) {
        rc = mysql_stmt_fetch (stmt);
        if (rc == 1) {
            seaf_warning ("Failed to fetch result for sql %s: %s\n",
                          sql, mysql_stmt_error(stmt));
            nrows = -1;
            goto out;
        }
        if (rc == MYSQL_NO_DATA)
            break;

        /* rc == 0 or rc == MYSQL_DATA_TRUNCATED */

        ++nrows;
        if (callback)
            next_row = callback ((SeafDBRow *)&row, data);

        for (i = 0; i < row.column_count; ++i) {
            g_free (row.new_binds[i].buffer);
            g_free (row.new_binds[i].length);
            g_free (row.new_binds[i].is_null);
            memset (&row.new_binds[i], 0, sizeof(MYSQL_BIND));
        }

        if (!next_row)
            break;
    }

out:
    if (stmt) {
        mysql_stmt_free_result (stmt);
        mysql_stmt_close (stmt);
    }
    if (params) {
        for (i = 0; i < n; ++i) {
            g_free (params[i].buffer);
            g_free (params[i].length);
        }
        g_free (params);
    }
    if (row.results) {
        for (i = 0; i < row.column_count; ++i) {
            g_free (row.results[i].buffer);
            g_free (row.results[i].length);
            g_free (row.results[i].is_null);
        }
        g_free (row.results);
    }
    if (row.new_binds) {
        for (i = 0; i < row.column_count; ++i) {
            g_free (row.new_binds[i].buffer);
            g_free (row.new_binds[i].length);
            g_free (row.new_binds[i].is_null);
        }
        g_free (row.new_binds);
    }
    return nrows;
}

static int
mysql_db_row_get_column_count (SeafDBRow *vrow)
{
    MySQLDBRow *row = (MySQLDBRow *)vrow;
    return row->column_count;
}

static const char *
mysql_db_row_get_column_string (SeafDBRow *vrow, int i)
{
    MySQLDBRow *row = (MySQLDBRow *)vrow;

    if (*(row->results[i].is_null)) {
        return NULL;
    }

    char *ret = NULL;
    unsigned long real_length = *(row->results[i].length);
    /* If column size is larger then allocated buffer size, re-allocate a new buffer
     * and fetch the column directly.
     */
    if (real_length > row->results[i].buffer_length) {
        row->new_binds[i].buffer = g_malloc (real_length + 1);
        row->new_binds[i].buffer_type = MYSQL_TYPE_STRING;
        row->new_binds[i].buffer_length = real_length;
        row->new_binds[i].length = g_new0 (unsigned long, 1);
        row->new_binds[i].is_null = g_new0 (my_bool, 1);
        if (mysql_stmt_fetch_column (row->stmt, &row->new_binds[i], i, 0) != 0) {
            seaf_warning ("Faield to fetch column: %s\n", mysql_stmt_error(row->stmt));
            return NULL;
        }

        ret = row->new_binds[i].buffer;
    } else {
        ret = row->results[i].buffer;
    }
    ret[real_length] = 0;

    return ret;
}

static int
mysql_db_row_get_column_int (SeafDBRow *vrow, int idx)
{
    const char *str;
    char *e;
    int ret;

    str = mysql_db_row_get_column_string (vrow, idx);
    if (!str) {
        return 0;
    }

    errno = 0;
    ret = strtol (str, &e, 10);
    if (errno || (e == str)) {
        seaf_warning ("Number conversion failed.\n");
        return -1;
    }

    return ret;
}

static gint64
mysql_db_row_get_column_int64 (SeafDBRow *vrow, int idx)
{
    const char *str;
    char *e;
    gint64 ret;

    str = mysql_db_row_get_column_string (vrow, idx);
    if (!str) {
        return 0;
    }

    errno = 0;
    ret = strtoll (str, &e, 10);
    if (errno || (e == str)) {
        seaf_warning ("Number conversion failed.\n");
        return -1;
    }

    return ret;
}

#endif  /* HAVE_MYSQL */

#ifdef HAVE_POSTGRES

/* Postgres DB */

typedef struct PostgresDB {
    struct SeafDB parent;
    char *host;
    char *user;
    char *password;
    unsigned int port;
    char *db_name;
    char *unix_socket;
    gboolean use_ssl;
} PostgresDB;

typedef struct PostgresDBConnection {
    struct DBConnection parent;
    PGconn *db_conn;
} PostgresDBConnection;

static gboolean
pgsql_db_connection_ping (DBConnection *vconn)
{
    PostgresDBConnection *conn = (PostgresDBConnection *)vconn;

    return (PQstatus(conn->db_conn) == CONNECTION_OK);
}

static SeafDB *
pgsql_db_new (const char *host,
              int port,
              const char *user,
              const char *password,
              const char *db_name,
              const char *unix_socket,
              gboolean use_ssl)
{
    PostgresDB *db = g_new0 (PostgresDB, 1);

    db->host = g_strdup (host);
    db->user = g_strdup (user);
    db->password = g_strdup (password);
    db->port = port;
    db->db_name = g_strdup(db_name);
    db->unix_socket = g_strdup(unix_socket);
    db->use_ssl = use_ssl;

    return (SeafDB *)db;
}

static char *
_pgsql_escape_connect_string (const char *str)
{
    GString *buf = g_string_new (NULL);
    const char *p;

    for (p = str; *p != '\0'; ++p) {
        if (*p == '\'' || *p == '\\') {
            g_string_append_c (buf, '\\');
            g_string_append_c (buf, *p);
        } else {
            g_string_append_c (buf, *p);
        }
    }

    return g_string_free (buf, FALSE);
}

static DBConnection *
pgsql_db_get_connection (SeafDB *vdb)
{
    PostgresDB *db = (PostgresDB *)vdb;
    PGconn *db_conn;
    PostgresDBConnection *conn = NULL;

    GString *buf = g_string_new (NULL);
    g_string_append_printf (buf, "user='%s' ", db->user);

    char* esc_password = _pgsql_escape_connect_string (db->password);
    g_string_append_printf (buf, "password='%s' ", esc_password);
    g_free (esc_password);

    if (db->unix_socket) {
        g_string_append_printf (buf, "host='%s' ", db->unix_socket);
    } else {
        g_string_append_printf (buf, "host='%s' ", db->host);
    }

    if (db->port > 0) {
        g_string_append_printf (buf, "port=%u ", db->port);
    }

    g_string_append_printf (buf, "dbname='%s' ", db->db_name);

    if (db->use_ssl) {
        g_string_append_printf (buf, "sslmode=require");
    }

    db_conn = PQconnectdb (buf->str);
    if (PQstatus (db_conn) != CONNECTION_OK) {
        seaf_warning ("Failed to init pgsql connection object.\n");
        PQfinish (db_conn);
        return NULL;
    }

    conn = g_new0 (PostgresDBConnection, 1);
    conn->db_conn = db_conn;

    return (DBConnection *)conn;
}

static void
pgsql_db_release_connection (DBConnection *vconn)
{
    if (!vconn)
        return;

    PostgresDBConnection *conn = (PostgresDBConnection *)vconn;

    PQfinish (conn->db_conn);

    g_free (conn);
}

static int
pgsql_db_execute_sql_no_stmt (DBConnection *vconn, const char *sql)
{
    PostgresDBConnection *conn = (PostgresDBConnection *)vconn;

    PGresult* res = PQexec(conn->db_conn, sql);
    if (!res) {
        seaf_warning ("Failed to execute sql %s: unknown error\n", sql);
        return -1;
    }
    ExecStatusType status = PQresultStatus(res);
    if (status != PGRES_EMPTY_QUERY && status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK) {
        seaf_warning ("Failed to execute sql %s: %s\n", sql, PQresultErrorMessage(res));
        PQclear (res);
        return -1;
    }

    PQclear (res);
    return 0;
}

/* Convert '?' in the query string to $1, $2, etc. */
static char *
_pgsql_db_format_query_string (const char *sql)
{
    GString *buf = g_string_new (NULL);
    const char *p;
    int i = 0;

    for (p = sql; *p != '\0'; ++p) {
        if (*p == '?') {
            ++i;
            g_string_append_c (buf, '$');
            g_string_append_printf (buf, "%d", i);
        } else {
            g_string_append_c (buf, *p);
        }
    }

    return g_string_free (buf, FALSE);
}

#define 	INT2OID    21
#define 	INT4OID    23
#define 	INT8OID    20
#define 	TEXTOID    25
#define     VARCHAROID 1043
#define     BPCHAROID  1042
#define     TIMESTAMPOID  1114
#define     TIMESTAMPTZOID  1184

static PGresult*
_pgsql_db_execute_stmt(PGconn *db, const char *sql, int n, va_list args)
{
    Oid *paramTypes = g_new0(Oid, n);
    const char** paramValues = g_new0(const char*, n);
    if (n > 0) {
        paramTypes = g_new0(Oid, n);
        for (int i = 0; i < n; i++) {
            const char* type = va_arg (args, const char *);
            if (strcmp(type, "int") == 0) {
                int value = va_arg (args, int);
                paramTypes[i] = INT4OID;
                paramValues[i] = g_strdup_printf("%d", value);
            } else if (strcmp (type, "int64") == 0) {
                gint64 value = va_arg (args, gint64);
                paramTypes[i] = INT8OID;
                paramValues[i] = g_strdup_printf("%"G_GINT64_FORMAT, value);
            } else if (strcmp (type, "string") == 0) {
                const char* value = va_arg (args, const char *);
                paramTypes[i] = TEXTOID;
                paramValues[i] = g_strdup(value);
            } else {
                seaf_warning ("BUG: invalid prep stmt parameter type %s.\n", type);
                g_return_val_if_reached (NULL);
            }
        }
    }

    return PQexecParams (
            db,
            _pgsql_db_format_query_string(sql),
            n,
            paramTypes,
            paramValues,
            NULL,
            NULL,
            0
    );
}

static int
pgsql_db_execute_sql (DBConnection *vconn, const char *sql, int n, va_list args)
{
    PostgresDBConnection *conn = (PostgresDBConnection *)vconn;

    PGresult *res = _pgsql_db_execute_stmt(conn->db_conn, sql, n, args);
    if (!res) {
        seaf_warning ("Failed to execute sql %s: unknown error\n", sql);
        return -1;
    }
    ExecStatusType status = PQresultStatus(res);
    if (status != PGRES_EMPTY_QUERY && status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK) {
        seaf_warning ("Failed to execute sql %s: %s\n", sql, PQresultErrorMessage(res));
        PQclear (res);
        return -1;
    }

    PQclear (res);
    return 0;
}

typedef struct PgSQLDBRow {
    SeafDBRow parent;
    int column_count;
    int row_index;
    PGresult *results;
} PgSQLDBRow;

static int
pgsql_db_query_foreach_row (DBConnection *vconn, const char *sql,
                            SeafDBRowFunc callback, void *data,
                            int n, va_list args)
{
    PostgresDBConnection *conn = (PostgresDBConnection *)vconn;

    PGresult *res = _pgsql_db_execute_stmt(conn->db_conn, sql, n, args);
    if (!res) {
        seaf_warning ("Failed to execute sql %s: unknown error\n", sql);
        return -1;
    }
    ExecStatusType status = PQresultStatus(res);
    if (status != PGRES_EMPTY_QUERY && status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK) {
        seaf_warning ("Failed to execute sql %s: %s\n", sql, PQresultErrorMessage(res));
        PQclear (res);
        return -1;
    }

    PgSQLDBRow row;
    memset(&row, 0, sizeof(row));
    row.column_count = PQnfields(res);
    row.results = res;
    int row_count = PQntuples(res);
    for (int i = 0; i < row_count; i++) {
        row.row_index = i;
        if (callback && !callback((SeafDBRow *) &row, data)) {
            break;
        }
    };
    PQclear(res);
    return row_count;
}

static int
pgsql_db_row_get_column_count (SeafDBRow *vrow)
{
    PgSQLDBRow *row = (PgSQLDBRow *)vrow;
    return row->column_count;
}

static const char *
pgsql_db_row_get_column_string (SeafDBRow *vrow, int idx)
{
    PgSQLDBRow *row = (PgSQLDBRow *)vrow;

    if (idx >= row->column_count) {
        seaf_warning("Tried retrieving column %d but only have %d columns\n", idx, row->column_count);
        return NULL;
    }

    if (PQgetisnull(row->results, row->row_index, idx)) {
        return NULL;
    }

    return PQgetvalue(row->results, row->row_index, idx);
}

static int
pgsql_db_row_get_column_int (SeafDBRow *vrow, int idx)
{
    PgSQLDBRow *row = (PgSQLDBRow *)vrow;

    const char* data = pgsql_db_row_get_column_string(row, idx);
    if (!data || 0 == strlen(data)) {
        return 0;
    }

    char *e;
    errno = 0;
    int ret = strtol (data, &e, 10);
    if (errno || (e == data)) {
        seaf_warning ("Number conversion failed.\n");
        return -1;
    }

    return ret;
}

static gint64
pgsql_db_row_get_column_int64 (SeafDBRow *vrow, int idx)
{
    PgSQLDBRow *row = (PgSQLDBRow *)vrow;

    const char* data = pgsql_db_row_get_column_string(row, idx);
    if (!data || 0 == strlen(data)) {
        return 0;
    }

    char *e;
    errno = 0;
    gint64 ret = strtoll (data, &e, 10);
    if (errno || (e == data)) {
        seaf_warning ("Number conversion failed.\n");
        return -1;
    }

    return ret;
}

#endif  /* HAVE_POSTGRES */

/* SQLite DB */

/* SQLite thread synchronization rountines.
 * See https://www.sqlite.org/unlock_notify.html
 */

typedef struct UnlockNotification {
        int fired;
        pthread_cond_t cond;
        pthread_mutex_t mutex;
} UnlockNotification;

static void
unlock_notify_cb(void **ap_arg, int n_arg)
{
    int i;

    for (i = 0; i < n_arg; i++) {
        UnlockNotification *p = (UnlockNotification *)ap_arg[i];
        pthread_mutex_lock (&p->mutex);
        p->fired = 1;
        pthread_cond_signal (&p->cond);
        pthread_mutex_unlock (&p->mutex);
    }
}

static int
wait_for_unlock_notify(sqlite3 *db)
{
    UnlockNotification un;
    un.fired = 0;
    pthread_mutex_init (&un.mutex, NULL);
    pthread_cond_init (&un.cond, NULL);

    int rc = sqlite3_unlock_notify(db, unlock_notify_cb, (void *)&un);

    if (rc == SQLITE_OK) {
        pthread_mutex_lock(&un.mutex);
        if (!un.fired)
            pthread_cond_wait (&un.cond, &un.mutex);
        pthread_mutex_unlock(&un.mutex);
    }

    pthread_cond_destroy (&un.cond);
    pthread_mutex_destroy (&un.mutex);

    return rc;
}

static int
sqlite3_blocking_step(sqlite3_stmt *stmt)
{
    int rc;
    while (SQLITE_LOCKED == (rc = sqlite3_step(stmt))) {
        rc = wait_for_unlock_notify(sqlite3_db_handle(stmt));
        if (rc != SQLITE_OK)
            break;
        sqlite3_reset(stmt);
    }
    return rc;
}

static int
sqlite3_blocking_prepare_v2(sqlite3 *db, const char *sql, int sql_len, sqlite3_stmt **pstmt, const char **pz)
{
    int rc;
    while (SQLITE_LOCKED == (rc = sqlite3_prepare_v2(db, sql, sql_len, pstmt, pz))) {
        rc = wait_for_unlock_notify(db);
        if (rc != SQLITE_OK)
            break;
    }
    return rc;
}

static int
sqlite3_blocking_exec(sqlite3 *db, const char *sql, int (*callback)(void *, int, char **, char **), void *arg, char **errmsg)
{
    int rc;
    while (SQLITE_LOCKED == (rc = sqlite3_exec(db, sql, callback, arg, errmsg))) {
        rc = wait_for_unlock_notify(db);
        if (rc != SQLITE_OK)
            break;
    }
    return rc;
}

typedef struct SQLiteDB {
    SeafDB parent;
    char *db_path;
} SQLiteDB;

typedef struct SQLiteDBConnection {
    DBConnection parent;
    sqlite3 *db_conn;
} SQLiteDBConnection;

static SeafDB *
sqlite_db_new (const char *db_path)
{
    SQLiteDB *db = g_new0 (SQLiteDB, 1);
    db->db_path = g_strdup(db_path);

    return (SeafDB *)db;
}

static DBConnection *
sqlite_db_get_connection (SeafDB *vdb)
{
    SQLiteDB *db = (SQLiteDB *)vdb;
    sqlite3 *db_conn;
    int result;
    const char *errmsg;
    SQLiteDBConnection *conn;

    result = sqlite3_open_v2 (db->db_path, &db_conn, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_SHAREDCACHE, NULL);
    if (result != SQLITE_OK) {
        errmsg = sqlite3_errmsg(db_conn);
        seaf_warning ("Failed to open sqlite db: %s\n", errmsg ? errmsg : "no error given");
        return NULL;
    }

    conn = g_new0 (SQLiteDBConnection, 1);
    conn->db_conn = db_conn;

    return (DBConnection *)conn;
}

static void
sqlite_db_release_connection (DBConnection *vconn, gboolean need_close)
{
    if (!vconn)
        return;

    SQLiteDBConnection *conn = (SQLiteDBConnection *)vconn;

    sqlite3_close (conn->db_conn);

    g_free (conn);
}

static int
sqlite_db_execute_sql_no_stmt (DBConnection *vconn, const char *sql)
{
    SQLiteDBConnection *conn = (SQLiteDBConnection *)vconn;
    char *errmsg = NULL;
    int rc;

    rc = sqlite3_blocking_exec (conn->db_conn, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        seaf_warning ("sqlite3_exec failed %s: %s", sql, errmsg ? errmsg : "no error given");
        if (errmsg)
            sqlite3_free (errmsg);
        return -1;
    }

    return 0;
}

static int
_bind_parameters_sqlite (sqlite3 *db, sqlite3_stmt *stmt, int n, va_list args)
{
    int i;
    const char *type;

    for (i = 0; i < n; ++i) {
        type = va_arg (args, const char *);
        if (strcmp(type, "int") == 0) {
            int x = va_arg (args, int);
            if (sqlite3_bind_int (stmt, i+1, x) != SQLITE_OK) {
                seaf_warning ("sqlite3_bind_int failed: %s\n", sqlite3_errmsg(db));
                return -1;
            }
        } else if (strcmp (type, "int64") == 0) {
            gint64 x = va_arg (args, gint64);
            if (sqlite3_bind_int64 (stmt, i+1, x) != SQLITE_OK) {
                seaf_warning ("sqlite3_bind_int64 failed: %s\n", sqlite3_errmsg(db));
                return -1;
            }
        } else if (strcmp (type, "string") == 0) {
            const char *s = va_arg (args, const char *);
            if (sqlite3_bind_text (stmt, i+1, s, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
                seaf_warning ("sqlite3_bind_text failed: %s\n", sqlite3_errmsg(db));
                return -1;
            }
        } else {
            seaf_warning ("BUG: invalid prep stmt parameter type %s.\n", type);
            g_return_val_if_reached (-1);
        }
    }

    return 0;
}

static int
sqlite_db_execute_sql (DBConnection *vconn, const char *sql, int n, va_list args)
{
    SQLiteDBConnection *conn = (SQLiteDBConnection *)vconn;
    sqlite3 *db = conn->db_conn;
    sqlite3_stmt *stmt;
    int rc;
    int ret = 0;

    rc = sqlite3_blocking_prepare_v2 (db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        seaf_warning ("sqlite3_prepare_v2 failed %s: %s", sql, sqlite3_errmsg(db));
        return -1;
    }

    if (_bind_parameters_sqlite (db, stmt, n, args) < 0) {
        seaf_warning ("Failed to bind parameters for sql %s\n", sql);
        ret = -1;
        goto out;
    }

    rc = sqlite3_blocking_step (stmt);
    if (rc != SQLITE_DONE) {
        seaf_warning ("sqlite3_step failed %s: %s", sql, sqlite3_errmsg(db));
        ret = -1;
        goto out;
    }

out:
    sqlite3_finalize (stmt);
    return ret;
}

typedef struct SQLiteDBRow {
    SeafDBRow parent;
    int column_count;
    sqlite3 *db;
    sqlite3_stmt *stmt;
} SQLiteDBRow;

static int
sqlite_db_query_foreach_row (DBConnection *vconn, const char *sql,
                             SeafDBRowFunc callback, void *data,
                             int n, va_list args)
{
    SQLiteDBConnection *conn = (SQLiteDBConnection *)vconn;
    sqlite3 *db = conn->db_conn;
    sqlite3_stmt *stmt;
    int rc;
    int nrows = 0;

    rc = sqlite3_blocking_prepare_v2 (db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        seaf_warning ("sqlite3_prepare_v2 failed %s: %s", sql, sqlite3_errmsg(db));
        return -1;
    }

    if (_bind_parameters_sqlite (db, stmt, n, args) < 0) {
        seaf_warning ("Failed to bind parameters for sql %s\n", sql);
        nrows = -1;
        goto out;
    }

    SQLiteDBRow row;
    memset (&row, 0, sizeof(row));
    row.db = db;
    row.stmt = stmt;
    row.column_count = sqlite3_column_count (stmt);

    while (1) {
        rc = sqlite3_blocking_step (stmt);
        if (rc == SQLITE_ROW) {
            ++nrows;
            if (callback && !callback ((SeafDBRow *)&row, data))
                break;
        } else if (rc == SQLITE_DONE) {
            break;
        } else {
            seaf_warning ("sqlite3_step failed %s: %s\n", sql, sqlite3_errmsg(db));
            nrows = -1;
            goto out;
        }
    }

out:
    sqlite3_finalize (stmt);
    return nrows;
}

static int
sqlite_db_row_get_column_count (SeafDBRow *vrow)
{
    SQLiteDBRow *row = (SQLiteDBRow *)vrow;

    return row->column_count;
}

static const char *
sqlite_db_row_get_column_string (SeafDBRow *vrow, int idx)
{
    SQLiteDBRow *row = (SQLiteDBRow *)vrow;

    return (const char *)sqlite3_column_text (row->stmt, idx);
}

static int
sqlite_db_row_get_column_int (SeafDBRow *vrow, int idx)
{
    SQLiteDBRow *row = (SQLiteDBRow *)vrow;

    return sqlite3_column_int (row->stmt, idx);
}

static gint64
sqlite_db_row_get_column_int64 (SeafDBRow *vrow, int idx)
{
    SQLiteDBRow *row = (SQLiteDBRow *)vrow;

    return sqlite3_column_int64 (row->stmt, idx);
}
