#ifndef SQLITE_DB_OPS_H
#define SQLITE_DB_OPS_H

DBConnPool *
sqlite_db_conn_pool_new (const char *db_path, int max_connections);

void
sqlite_db_conn_pool_free (DBConnPool *vpool);

DBConnection *
sqlite_get_db_connection (DBConnPool *vpool, GError **error);

void
sqlite_db_connection_close (DBConnection *vconn);

gboolean
sqlite_db_connection_execute (DBConnection *vconn, const char *sql, GError **error);

void
sqlite_result_set_free (ResultSet *vr);

ResultSet *
sqlite_execute_query (DBConnection *vconn, const char *sql, GError **error);

gboolean
sqlite_result_set_next (ResultSet *vr, GError **error);

const char *
sqlite_result_set_get_string (ResultSet *vr, int i, GError **error);

int
sqlite_result_set_get_column_count (ResultSet *vr);

DBStmt *
sqlite_prepare_statement (DBConnection *vconn, const char *sql, GError **error);

gboolean
sqlite_stmt_set_int (DBStmt *vstmt, int i, int x, GError **error);

gboolean
sqlite_stmt_set_int64 (DBStmt *vstmt, int i, gint64 x, GError **error);

gboolean
sqlite_stmt_set_string (DBStmt *vstmt, int i, const char *s, GError **error);

gboolean
sqlite_db_stmt_execute (DBStmt *vstmt, GError **error);

ResultSet *
sqlite_db_stmt_execute_query (DBStmt *vstmt, GError **error);

void
sqlite_db_stmt_free (DBStmt *vstmt);

gboolean
sqlite_db_begin_transaction (DBConnection *vconn, GError **error);

gboolean
sqlite_db_commit (DBConnection *vconn, GError **error);

gboolean
sqlite_db_rollback (DBConnection *vconn, GError **error);

#endif
