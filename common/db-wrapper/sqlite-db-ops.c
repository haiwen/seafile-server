#include "common.h"

#include "db-wrapper.h"
#include "sqlite-db-ops.h"

#include <sqlite3.h>
#include <pthread.h>

/* SQLite thread synchronization rountines. */

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

typedef struct SQLiteDBConnPool {
    DBConnPool parent;
    char *db_path;
} SQLiteDBConnPool;

DBConnPool *
sqlite_db_conn_pool_new (const char *db_path)
{
    SQLiteDBConnPool *pool = g_new0 (SQLiteDBConnPool, 1);
    pool->db_path = g_strdup(db_path);

    return (DBConnPool *)pool;
}

void
sqlite_db_conn_pool_free (DBConnPool *vpool)
{
    if (!vpool)
        return;

    SQLiteDBConnPool *pool = (SQLiteDBConnPool *)vpool;

    g_free (pool->db_path);
    g_free (pool);
}

typedef struct SQLiteDBConnection {
    DBConnection parent;
    sqlite3 *db;
} SQLiteDBConnection;

DBConnection *
sqlite_get_db_connection (DBConnPool *vpool, GError **error)
{
    SQLiteDBConnPool *pool = (SQLiteDBConnPool *)vpool;
    sqlite3 *db;
    int result;
    const char *errmsg;
    SQLiteDBConnection *conn;

    result = sqlite3_open (pool->db_path, &db);
    if (result != SQLITE_OK) {
        errmsg = sqlite3_errmsg(db);
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Failed to open sqlite db: %s",
                     errmsg ? errmsg : "no error given");
        return NULL;
    }

    conn = g_new0 (SQLiteDBConnection, 1);
    conn->db = db;

    return (DBConnection *)conn;
}

void
sqlite_db_connection_close (DBConnection *vconn)
{
    if (!vconn)
        return;

    SQLiteDBConnection *conn = (SQLiteDBConnection *)vconn;

    sqlite3_close (conn->db);

    g_free (conn);
}

gboolean
sqlite_db_connection_ping (DBConnection *vconn)
{
    return TRUE;
}

gboolean
sqlite_db_connection_execute (DBConnection *vconn, const char *sql, GError **error)
{
    SQLiteDBConnection *conn = (SQLiteDBConnection *)vconn;
    char *errmsg = NULL;
    int rc;

    rc = sqlite3_blocking_exec (conn->db, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "sqlite3_exec failed: %s",
                     errmsg ? errmsg : "no error given");
        if (errmsg)
            sqlite3_free (errmsg);
        return FALSE;
    }

    return TRUE;
}

typedef struct SQLiteResultSet {
    ResultSet parent;
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int column_count;
} SQLiteResultSet;

void
sqlite_result_set_free (ResultSet *vr)
{
    if (!vr)
        return;

    SQLiteResultSet *r = (SQLiteResultSet *)vr;

    sqlite3_finalize (r->stmt);

    g_free (r);
}

ResultSet *
sqlite_execute_query (DBConnection *vconn, const char *sql, GError **error)
{
    SQLiteDBConnection *conn = (SQLiteDBConnection *)vconn;
    sqlite3_stmt *stmt;
    int rc;
    SQLiteResultSet *r;

    rc = sqlite3_blocking_prepare_v2 (conn->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "sqlite3_prepare_v2 failed: %s", sqlite3_errmsg(conn->db));
        return NULL;
    }

    r = g_new0 (SQLiteResultSet, 1);
    r->db = conn->db;
    r->stmt = stmt;
    r->column_count = sqlite3_column_count (stmt);

    return (ResultSet *)r;
}

gboolean
sqlite_result_set_next (ResultSet *vr, GError **error)
{
    SQLiteResultSet *r = (SQLiteResultSet *)vr;
    int rc;

    rc = sqlite3_blocking_step (r->stmt);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "sqlite3_step failed: %s", sqlite3_errmsg(r->db));
        return FALSE;
    }

    return (rc == SQLITE_ROW);
}

const char *
sqlite_result_set_get_string (ResultSet *vr, int i, GError **error)
{
    SQLiteResultSet *r = (SQLiteResultSet *)vr;

    if (i < 0 || i >= r->column_count) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Column index is out of range.");
        return NULL;
    }

    return (const char *)sqlite3_column_text (r->stmt, i);
}

int
sqlite_result_set_get_column_count (ResultSet *vr)
{
    return ((SQLiteResultSet *)vr)->column_count;
}

typedef struct SQLiteDBStmt {
    DBStmt parent;
    int param_count;
    sqlite3 *db;
    sqlite3_stmt *stmt;
} SQLiteDBStmt;

DBStmt *
sqlite_prepare_statement (DBConnection *vconn, const char *sql, GError **error)
{
    SQLiteDBConnection *conn = (SQLiteDBConnection *)vconn;
    sqlite3_stmt *stmt;
    int rc;
    SQLiteDBStmt *ret;

    rc = sqlite3_blocking_prepare_v2 (conn->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "sqlite3_prepare_v2 failed: %s", sqlite3_errmsg(conn->db));
        return NULL;
    }

    ret = g_new0 (SQLiteDBStmt, 1);
    ret->stmt = stmt;
    ret->db = conn->db;
    ret->param_count = sqlite3_bind_parameter_count (stmt);

    return (DBStmt *)ret;
}

gboolean
sqlite_stmt_set_int (DBStmt *vstmt, int i, int x, GError **error)
{
    SQLiteDBStmt *stmt = (SQLiteDBStmt *)vstmt;
    int rc;

    if (i < 0 || i >= stmt->param_count) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Column index is out of range.");
        return FALSE;
    }

    rc = sqlite3_bind_int (stmt->stmt, i+1, x);
    if (rc != SQLITE_OK) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "sqlite3_bind_int failed: %s", sqlite3_errstr(rc));
        return FALSE;
    }

    return TRUE;
}

gboolean
sqlite_stmt_set_int64 (DBStmt *vstmt, int i, gint64 x, GError **error)
{
    SQLiteDBStmt *stmt = (SQLiteDBStmt *)vstmt;
    int rc;

    if (i < 0 || i >= stmt->param_count) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Column index is out of range.");
        return FALSE;
    }

    rc = sqlite3_bind_int64 (stmt->stmt, i+1, x);
    if (rc != SQLITE_OK) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "sqlite3_bind_int failed: %s", sqlite3_errstr(rc));
        return FALSE;
    }

    return TRUE;
}

gboolean
sqlite_stmt_set_string (DBStmt *vstmt, int i, const char *s, GError **error)
{
    SQLiteDBStmt *stmt = (SQLiteDBStmt *)vstmt;
    int rc;

    if (i < 0 || i >= stmt->param_count) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Column index is out of range.");
        return FALSE;
    }

    rc = sqlite3_bind_text (stmt->stmt, i+1, s, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "sqlite3_bind_int failed: %s", sqlite3_errstr(rc));
        return FALSE;
    }

    return TRUE;
}

gboolean
sqlite_db_stmt_execute (DBStmt *vstmt, GError **error)
{
    SQLiteDBStmt *stmt = (SQLiteDBStmt *)vstmt;
    int rc;

    rc = sqlite3_blocking_step (stmt->stmt);
    if (rc == SQLITE_DONE) {
        sqlite3_reset (stmt->stmt);
        return TRUE;
    } else if (rc == SQLITE_ROW) {
        sqlite3_reset (stmt->stmt);
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Select statement not allowed in db_stmt_execute.");
        return FALSE;
    } else {
        sqlite3_reset (stmt->stmt);
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "sqlite3_step failed: %s", sqlite3_errmsg(stmt->db));
        return FALSE;
    }
}

ResultSet *
sqlite_db_stmt_execute_query (DBStmt *vstmt, GError **error)
{
    SQLiteDBStmt *stmt = (SQLiteDBStmt *)vstmt;
    SQLiteResultSet *r;

    r = g_new0 (SQLiteResultSet, 1);
    r->db = stmt->db;
    r->stmt = stmt->stmt;
    r->column_count = sqlite3_column_count (r->stmt);

    return (ResultSet *)r;
}

void
sqlite_db_stmt_free (DBStmt *vstmt)
{
    if (!vstmt)
        return;

    SQLiteDBStmt *stmt = (SQLiteDBStmt *)vstmt;

    if (!stmt->parent.result_set) {
        sqlite3_finalize (stmt->stmt);
    }

    g_free (stmt);
}

gboolean
sqlite_db_begin_transaction (DBConnection *vconn, GError **error)
{
    SQLiteDBConnection *conn = (SQLiteDBConnection *)vconn;
    int rc;

    rc = sqlite3_blocking_exec (conn->db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "begin transaction failed: %s", sqlite3_errmsg(conn->db));
        return FALSE;
    }

    return TRUE;
}

gboolean
sqlite_db_commit (DBConnection *vconn, GError **error)
{
    SQLiteDBConnection *conn = (SQLiteDBConnection *)vconn;
    int rc;

    rc = sqlite3_blocking_exec (conn->db, "COMMIT TRANSACTION;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "commit transaction failed: %s", sqlite3_errmsg(conn->db));
        return FALSE;
    }

    return TRUE;
}

gboolean
sqlite_db_rollback (DBConnection *vconn, GError **error)
{
    SQLiteDBConnection *conn = (SQLiteDBConnection *)vconn;
    int rc;

    rc = sqlite3_blocking_exec (conn->db, "ROLLBACK TRANSACTION;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "rollback transaction failed: %s", sqlite3_errmsg(conn->db));
        return FALSE;
    }

    return TRUE;
}
