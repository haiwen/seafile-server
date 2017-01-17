#include "common.h"

#include "db-wrapper.h"
#include "pgsql-db-ops.h"

#include <libpq-fe.h>

typedef struct PGDBConnPool {
    DBConnPool parent;
    char *host;
    unsigned int port;
    char *user;
    char *password;
    char *db_name;
    char *unix_socket;
} PGDBConnPool;

DBConnPool *
pgsql_db_conn_pool_new (const char *host,
                        unsigned int port,
                        const char *user,
                        const char *password,
                        const char *db_name,
                        const char *unix_socket)
{
    PGDBConnPool *pool = g_new0 (PGDBConnPool, 1);

    pool->host = g_strdup (host);
    pool->port = port;
    pool->user = g_strdup (user);
    pool->password = g_strdup (password);
    pool->db_name = g_strdup(db_name);
    pool->unix_socket = g_strdup(unix_socket);

    return (DBConnPool *)pool;
}

void
pgsql_db_conn_pool_free (DBConnPool *vpool)
{
    PGDBConnPool *pool = (PGDBConnPool *)vpool;

    g_free (pool->host);
    g_free (pool->user);
    g_free (pool->password);
    g_free (pool->db_name);
    g_free (pool->unix_socket);

    g_free (pool);
}

typedef struct PGDBConnection {
    DBConnection parent;
    PGconn *db;
} PGDBConnection;

static char *
escape_string_pgsql_connect (const char *str)
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

static PGconn *
connect_pgsql (PGDBConnPool *pool, GError **error)
{
    GString *buf = g_string_new("");
    char *esc_password = NULL;
    PGconn *db;

    g_string_append_printf (buf, "user='%s' ", pool->user);

    esc_password = escape_string_pgsql_connect (pool->password);
    g_string_append_printf (buf, "password='%s' ", esc_password);
    g_free (esc_password);

    if (pool->unix_socket) {
        g_string_append_printf (buf, "host='%s' ", pool->unix_socket);
    } else {
        g_string_append_printf (buf, "host='%s' ", pool->host);
    }

    if (pool->port > 0) {
        g_string_append_printf (buf, "port=%u ", pool->port);
    }

    g_string_append_printf (buf, "dbname='%s' ", pool->db_name);
    
    db = PQconnectdb (buf->str);
    if (PQstatus (db) != CONNECTION_OK) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "PQconnectdb failed: %s", PQerrorMessage (db));
        PQfinish (db);
        db = NULL;
    }

    g_string_free (buf, TRUE);
    return db;
}

DBConnection *
pgsql_get_db_connection (DBConnPool *vpool, GError **error)
{
    PGDBConnPool *pool = (PGDBConnPool *)vpool;
    PGDBConnection *conn;

    PGconn *db = connect_pgsql (pool, error);
    if (!db)
        return NULL;

    conn = g_new0 (PGDBConnection, 1);
    conn->db = db;

    return (DBConnection *)conn;
}

void
pgsql_db_connection_close (DBConnection *vconn)
{
    if (!vconn)
        return;

    PGDBConnection *conn = (PGDBConnection *)vconn;

    PQfinish (conn->db);

    g_free (conn);
}

gboolean
pgsql_db_connection_ping (DBConnection *vconn)
{
    PGDBConnection *conn = (PGDBConnection *)vconn;

    return (PQstatus(conn->db) == CONNECTION_OK);
}

gboolean
pgsql_db_connection_execute (DBConnection *vconn, const char *sql, GError **error)
{
    PGDBConnection *conn = (PGDBConnection *)vconn;
    PGresult *res;
    gboolean ret = TRUE;

    res = PQexec (conn->db, sql);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "PQexec failed: %s", PQresultErrorMessage(res));
        ret = FALSE;
    }
    PQclear (res);

    return ret;
}

typedef struct PGResultSet {
    ResultSet parent;
    PGresult *res;
    int curr_row;
    int column_count;
    int row_count;
} PGResultSet;

void
pgsql_result_set_free (ResultSet *vr)
{
    if (!vr)
        return;

    PGResultSet *r = (PGResultSet *)vr;

    PQclear (r->res);
    g_free (r);
}

static PGResultSet *
pgsql_result_set_new (PGresult *res)
{
    PGResultSet *r;

    r = g_new0 (PGResultSet, 1);
    r->curr_row = -1;
    r->column_count = PQnfields(res);
    r->row_count = PQntuples(res);
    r->res = res;

    return r;
}

ResultSet *
pgsql_execute_query (DBConnection *vconn, const char *sql, GError **error)
{
    PGDBConnection *conn = (PGDBConnection *)vconn;
    PGresult *res;
    PGResultSet *r;

    res = PQexec (conn->db, sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "PQexec failed: %s", PQresultErrorMessage(res));
        return NULL;
    }

    r = pgsql_result_set_new (res);

    return (ResultSet *)r;
}

gboolean
pgsql_result_set_next (ResultSet *vr, GError **error)
{
    PGResultSet *r = (PGResultSet *)vr;

    return ((r->curr_row)++ < (r->row_count - 1));
}

const char *
pgsql_result_set_get_string (ResultSet *vr, int i, GError **error)
{
    PGResultSet *r = (PGResultSet *)vr;

    if (PQgetisnull(r->res, r->curr_row, i))
        return NULL;
    return PQgetvalue(r->res, r->curr_row, i);
}

int
pgsql_result_set_get_column_count (ResultSet *vr)
{
    PGResultSet *r = (PGResultSet *)vr;
    return r->column_count;
}

typedef struct PGDBStmt {
    DBStmt parent;
    char *name;
    PGconn *db;
    int param_count;
    char **values;
    int *lengths;
    int *formats;
} PGDBStmt;

static PGDBStmt *
pgsql_stmt_new (PGconn *db, char *name, int param_count)
{
    PGDBStmt *stmt = g_new0 (PGDBStmt, 1);

    stmt->name = g_strdup(name);
    stmt->db = db;
    stmt->param_count = param_count;

    if (stmt->param_count) {
        stmt->values = g_new0 (char *, param_count);
        stmt->lengths = g_new0 (int, param_count);
        stmt->formats = g_new0 (int, param_count);
    }

    return stmt;
}

/* Convert '?' in the query string to $1, $2, etc. */
static char *
pgsql_format_query_string (const char *sql, int *param_count)
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

    *param_count = i;

    return g_string_free (buf, FALSE);
}

static gint stmt_id = 0;

DBStmt *
pgsql_prepare_statement (DBConnection *vconn, const char *sql, GError **error)
{
    PGDBConnection *conn = (PGDBConnection *)vconn;
    char *query;
    int param_count;
    char *name;
    PGresult *res;
    PGDBStmt *stmt = NULL;

    query = pgsql_format_query_string (sql, &param_count);

    g_atomic_int_inc (&stmt_id);
    name = g_strdup_printf ("%d", stmt_id);

    res = PQprepare (conn->db, name, query, 0, NULL);
    ExecStatusType status = PQresultStatus(res);
    if (res && (status == PGRES_EMPTY_QUERY || status == PGRES_COMMAND_OK || status == PGRES_TUPLES_OK)) {
        stmt = pgsql_stmt_new (conn->db, name, param_count);
    } else {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "PQprepare failed: %s", PQresultErrorMessage(res));
    }

    PQclear (res);
    g_free (name);
    g_free (query);
    return (DBStmt *)stmt;
}

gboolean
pgsql_stmt_set_int (DBStmt *vstmt, int i, int x, GError **error)
{
    PGDBStmt *stmt = (PGDBStmt *)vstmt;

    if (i < 0 || i >= stmt->param_count) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Column index is out of range.");
        return FALSE;
    }

    stmt->values[i] = g_strdup_printf("%d", x);
    stmt->lengths[i] = 0;
    stmt->formats[i] = 0;

    return TRUE;
}

gboolean
pgsql_stmt_set_int64 (DBStmt *vstmt, int i, gint64 x, GError **error)
{
    PGDBStmt *stmt = (PGDBStmt *)vstmt;

    if (i < 0 || i >= stmt->param_count) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Column index is out of range.");
        return FALSE;
    }

    stmt->values[i] = g_strdup_printf("%"G_GINT64_FORMAT, x);
    stmt->lengths[i] = 0;
    stmt->formats[i] = 0;

    return TRUE;
}

gboolean
pgsql_stmt_set_string (DBStmt *vstmt, int i, const char *s, GError **error)
{
    PGDBStmt *stmt = (PGDBStmt *)vstmt;

    if (i < 0 || i >= stmt->param_count) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Column index is out of range.");
        return FALSE;
    }

    stmt->values[i] = g_strdup(s);
    stmt->lengths[i] = 0;
    stmt->formats[i] = 0;

    return TRUE;
}

gboolean
pgsql_db_stmt_execute (DBStmt *vstmt, GError **error)
{
    PGDBStmt *stmt = (PGDBStmt *)vstmt;
    PGresult *res;
    gboolean ret;

    res = PQexecPrepared (stmt->db, stmt->name, stmt->param_count,
                          (const char **)stmt->values, stmt->lengths, stmt->formats, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "PGexecPrepared failed: %s", PQresultErrorMessage(res));
        ret = FALSE;
    }

    ret = TRUE;

    PQclear(res);

    return ret;
}

ResultSet *
pgsql_db_stmt_execute_query (DBStmt *vstmt, GError **error)
{
    PGDBStmt *stmt = (PGDBStmt *)vstmt;
    PGresult *res;
    PGResultSet *ret = NULL;

    res = PQexecPrepared (stmt->db, stmt->name, stmt->param_count,
                          (const char **)stmt->values, stmt->lengths, stmt->formats, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "PGexecPrepared failed: %s", PQresultErrorMessage(res));
    }

    ret = pgsql_result_set_new (res);

    return (ResultSet *)ret;
}

void
pgsql_db_stmt_free (DBStmt *vstmt)
{
    if (!vstmt)
        return;

    char Stmt[256];
    PGDBStmt *stmt = (PGDBStmt *)vstmt;
    snprintf(Stmt, sizeof(Stmt), "DEALLOCATE \"%s\";", stmt->name);
    PQclear(PQexec(stmt->db, Stmt));

    g_free (stmt->name);

    int i;
    for (i = 0; i < stmt->param_count; ++i)
        g_free (stmt->values[i]);
    g_free (stmt->values);

    g_free (stmt->lengths);
    g_free (stmt->formats);
    g_free (stmt);
}

gboolean
pgsql_db_begin_transaction (DBConnection *vconn, GError **error)
{
    PGDBConnection *conn = (PGDBConnection *)vconn;
    gboolean ret = TRUE;

    PGresult *res = PQexec(conn->db, "BEGIN TRANSACTION;");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Begin transaction failed: %s", PQresultErrorMessage(res));
        ret = FALSE;
    }
    PQclear(res);
    return ret;
}

gboolean
pgsql_db_commit (DBConnection *vconn, GError **error)
{
    PGDBConnection *conn = (PGDBConnection *)vconn;
    gboolean ret = TRUE;

    PGresult *res = PQexec(conn->db, "COMMIT TRANSACTION;");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Commit transaction failed: %s", PQresultErrorMessage(res));
        ret = FALSE;
    }
    PQclear(res);
    return ret;
}

gboolean
pgsql_db_rollback (DBConnection *vconn, GError **error)
{
    PGDBConnection *conn = (PGDBConnection *)vconn;
    gboolean ret = TRUE;

    PGresult *res = PQexec(conn->db, "ROLLBACK TRANSACTION;");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        g_set_error (error, SEAF_DB_ERROR_DOMAIN, SEAF_DB_ERROR_CODE,
                     "Rollback transaction failed: %s", PQresultErrorMessage(res));
        ret = FALSE;
    }
    PQclear(res);
    return ret;
}
