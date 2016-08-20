#ifndef MYSQL_DB_OPS_H
#define MYSQL_DB_OPS_H

DBConnPool *
mysql_db_conn_pool_new (const char *host,
                        const char *user,
                        const char *password,
                        unsigned int port,
                        const char *db_name,
                        const char *unix_socket,
                        gboolean use_ssl,
                        const char *charset);

void
mysql_db_conn_pool_free (DBConnPool *vpool);

DBConnection *
mysql_get_db_connection (DBConnPool *vpool, GError **error);

void
mysql_db_connection_close (DBConnection *vconn);

gboolean
mysql_db_connection_ping (DBConnection *vconn);

gboolean
mysql_db_connection_execute (DBConnection *vconn, const char *sql, GError **error);

void
mysql_result_set_free (ResultSet *vr);

ResultSet *
mysql_execute_query (DBConnection *vconn, const char *sql, GError **error);

gboolean
mysql_result_set_next (ResultSet *vr, GError **error);

const char *
mysql_result_set_get_string (ResultSet *vr, int i, GError **error);

int
mysql_result_set_get_column_count (ResultSet *vr);

DBStmt *
mysql_prepare_statement (DBConnection *vconn, const char *sql, GError **error);

gboolean
mysql_stmt_set_int (DBStmt *vstmt, int i, int x, GError **error);

gboolean
mysql_stmt_set_int64 (DBStmt *vstmt, int i, gint64 x, GError **error);

gboolean
mysql_stmt_set_string (DBStmt *vstmt, int i, const char *s, GError **error);

gboolean
mysql_db_stmt_execute (DBStmt *vstmt, GError **error);

ResultSet *
mysql_db_stmt_execute_query (DBStmt *vstmt, GError **error);

void
mysql_db_stmt_free (DBStmt *vstmt);

gboolean
mysql_db_begin_transaction (DBConnection *vconn, GError **error);

gboolean
mysql_db_commit (DBConnection *vconn, GError **error);

gboolean
mysql_db_rollback (DBConnection *vconn, GError **error);

#endif
