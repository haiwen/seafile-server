#ifndef PGSQL_DB_OPS_H
#define PGSQL_DB_OPS_H

DBConnPool *
pgsql_db_conn_pool_new (const char *host,
                        const char *user,
                        const char *password,
                        const char *db_name,
                        const char *unix_socket);

void
pgsql_db_conn_pool_free (DBConnPool *vpool);

DBConnection *
pgsql_get_db_connection (DBConnPool *vpool, GError **error);

void
pgsql_db_connection_close (DBConnection *vconn);

gboolean
pgsql_db_connection_execute (DBConnection *vconn, const char *sql, GError **error);

void
pgsql_result_set_free (ResultSet *vr);

ResultSet *
pgsql_execute_query (DBConnection *vconn, const char *sql, GError **error);

gboolean
pgsql_result_set_next (ResultSet *vr, GError **error);

const char *
pgsql_result_set_get_string (ResultSet *vr, int i, GError **error);

int
pgsql_result_set_get_column_count (ResultSet *vr);

DBStmt *
pgsql_prepare_statement (DBConnection *vconn, const char *sql, GError **error);

gboolean
pgsql_stmt_set_int (DBStmt *vstmt, int i, int x, GError **error);

gboolean
pgsql_stmt_set_int64 (DBStmt *vstmt, int i, gint64 x, GError **error);

gboolean
pgsql_stmt_set_string (DBStmt *vstmt, int i, const char *s, GError **error);

gboolean
pgsql_db_stmt_execute (DBStmt *vstmt, GError **error);

ResultSet *
pgsql_db_stmt_execute_query (DBStmt *vstmt, GError **error);

void
pgsql_db_stmt_free (DBStmt *vstmt);

gboolean
pgsql_db_begin_transaction (DBConnection *vconn, GError **error);

gboolean
pgsql_db_commit (DBConnection *vconn, GError **error);

gboolean
pgsql_db_rollback (DBConnection *vconn, GError **error);

#endif
