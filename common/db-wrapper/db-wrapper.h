#ifndef DB_WRAPPER_H
#define DB_WARPPER_H

#include <glib.h>
#include <pthread.h>

#define SEAF_DB_ERROR_DOMAIN g_quark_from_string("SEAF_DB")
#define SEAF_DB_ERROR_CODE 0

/* DB Connection Pool. */

struct DBConnPool {
    GPtrArray *connections;
    pthread_mutex_t lock;
    int max_connections;
};
typedef struct DBConnPool DBConnPool;

DBConnPool *
db_conn_pool_new_mysql (const char *host,
                        const char *user,
                        const char *password,
                        unsigned int port,
                        const char *db_name,
                        const char *unix_socket,
                        gboolean use_ssl,
                        const char *charset,
                        int max_connections);

DBConnPool *
db_conn_pool_new_pgsql (const char *host,
                        const char *user,
                        const char *password,
                        const char *db_name,
                        const char *unix_socket,
                        int max_connections);

DBConnPool *
db_conn_pool_new_sqlite (const char *db_path, int max_connections);

void
db_conn_pool_free (DBConnPool *pool);

/* DB Connections. */

struct ResultSet;
typedef struct ResultSet ResultSet;

struct DBStmt;
typedef struct DBStmt DBStmt;

struct DBConnection {
    gboolean is_available;
    int in_transaction;
    DBConnPool *pool;
    ResultSet *result_set;
    DBStmt *stmt;
    int conn_no;
};
typedef struct DBConnection DBConnection;

DBConnection *
db_conn_pool_get_connection (DBConnPool *pool, GError **error);

void
db_connection_close (DBConnection *conn);

gboolean
db_connection_ping (DBConnection *conn);

gboolean
db_connection_execute (DBConnection *conn, const char *sql, GError **error);

/* Result Sets. */

struct ResultSet {
    /* Empty */
};

ResultSet *
db_connection_execute_query (DBConnection *conn, const char *sql, GError **error);

gboolean
result_set_next (ResultSet *r, GError **error);

const char *
result_set_get_string (ResultSet *r, int idx, GError **error);

int
result_set_get_int (ResultSet *r, int idx, GError **error);

gint64
result_set_get_int64 (ResultSet *r, int idx, GError **error);

int
result_set_get_column_count (ResultSet *r);

void
result_set_free (ResultSet *r);

/* Prepared Statements. */

struct DBStmt {
    ResultSet *result_set;
};

DBStmt *
db_connection_prepare_statement (DBConnection *conn, const char *sql, GError **error);

gboolean
db_stmt_set_int (DBStmt *stmt, int idx, int x, GError **error);

gboolean
db_stmt_set_int64 (DBStmt *stmt, int idx, gint64 x, GError **error);

gboolean
db_stmt_set_string (DBStmt *stmt, int idx, const char *s, GError **error);

gboolean
db_stmt_execute (DBStmt *stmt, GError **error);

ResultSet *
db_stmt_execute_query (DBStmt *stmt, GError **error);

void
db_stmt_free (DBStmt *stmt);

/* Transactions. */

gboolean
db_connection_begin_transaction (DBConnection *conn, GError **error);

gboolean
db_connection_commit (DBConnection *conn, GError **error);

gboolean
db_connection_rollback (DBConnection *conn, GError **error);

#endif
