#include "common.h"

#include "log.h"

#include "seafile-session.h"
#include "seaf-utils.h"
#include "seaf-db.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>

char *
seafile_session_get_tmp_file_path (SeafileSession *session,
                                   const char *basename,
                                   char path[])
{
    int path_len;

    path_len = strlen (session->tmp_file_dir);
    memcpy (path, session->tmp_file_dir, path_len + 1);
    path[path_len] = '/';
    strcpy (path + path_len + 1, basename);

    return path;
}

#define DEFAULT_MAX_CONNECTIONS 100

#define SQLITE_DB_NAME "seafile.db"
#define CCNET_DB "ccnet.db"

static int
sqlite_db_start (SeafileSession *session)
{
    char *db_path;
    int max_connections = 0;

    max_connections = g_key_file_get_integer (session->config,
                                              "database", "max_connections",
                                              NULL);
    if (max_connections <= 0)
        max_connections = DEFAULT_MAX_CONNECTIONS;

    db_path = g_build_filename (session->seaf_dir, SQLITE_DB_NAME, NULL);
    session->db = seaf_db_new_sqlite (db_path, max_connections);
    if (!session->db) {
        seaf_warning ("Failed to start sqlite db.\n");
        return -1;
    }

    return 0;
}

#ifdef HAVE_MYSQL

#define MYSQL_DEFAULT_PORT 3306

static int
mysql_db_start (SeafileSession *session)
{
    char *host, *user, *passwd, *db, *unix_socket, *charset;
    int port;
    gboolean use_ssl = FALSE;
    int max_connections = 0;
    GError *error = NULL;

    host = seaf_key_file_get_string (session->config, "database", "host", &error);
    unix_socket = seaf_key_file_get_string (session->config, "database", "unix_socket", NULL);
    if (!host && !unix_socket) {
        seaf_warning ("DB host or socket not set in config.\n");
        return -1;
    }

    port = g_key_file_get_integer (session->config, "database", "port", &error);
    if (error) {
        g_clear_error (&error);
        port = MYSQL_DEFAULT_PORT;
    }

    user = seaf_key_file_get_string (session->config, "database", "user", &error);
    if (!user) {
        seaf_warning ("DB user not set in config.\n");
        return -1;
    }

    passwd = seaf_key_file_get_string (session->config, "database", "password", &error);
    if (!passwd) {
        seaf_warning ("DB passwd not set in config.\n");
        return -1;
    }

    db = seaf_key_file_get_string (session->config, "database", "db_name", &error);
    if (!db) {
        seaf_warning ("DB name not set in config.\n");
        return -1;
    }

    use_ssl = g_key_file_get_boolean (session->config,
                                      "database", "use_ssl", NULL);

    charset = seaf_key_file_get_string (session->config,
                                     "database", "connection_charset", NULL);

    if (error)
        g_clear_error (&error);
    max_connections = g_key_file_get_integer (session->config,
                                              "database", "max_connections",
                                              &error);
    if (error || max_connections < 0) {
        g_clear_error (&error);
        max_connections = DEFAULT_MAX_CONNECTIONS;
    }

    session->db = seaf_db_new_mysql (host, port, user, passwd, db, unix_socket, use_ssl, charset, max_connections);
    if (!session->db) {
        seaf_warning ("Failed to start mysql db.\n");
        return -1;
    }

    g_free (host);
    g_free (user);
    g_free (passwd);
    g_free (db);
    g_free (unix_socket);
    g_free (charset);

    return 0;
}

#endif

#ifdef HAVE_POSTGRESQL

#define PGSQL_DEFAULT_PORT 5432

static int
pgsql_db_start (SeafileSession *session)
{
    char *host, *user, *passwd, *db, *unix_socket;
    unsigned int port;
    int max_connections = 0;
    GError *error = NULL;

    host = seaf_key_file_get_string (session->config, "database", "host", &error);
    unix_socket = seaf_key_file_get_string (session->config, "database", "unix_socket", NULL);
    if (!host && !unix_socket) {
        seaf_warning ("DB host or socket not set in config.\n");
        return -1;
    }
    user = seaf_key_file_get_string (session->config, "database", "user", &error);
    if (!user) {
        seaf_warning ("DB user not set in config.\n");
        return -1;
    }

    passwd = seaf_key_file_get_string (session->config, "database", "password", &error);
    if (!passwd) {
        seaf_warning ("DB passwd not set in config.\n");
        return -1;
    }

    db = seaf_key_file_get_string (session->config, "database", "db_name", &error);
    if (!db) {
        seaf_warning ("DB name not set in config.\n");
        return -1;
    }
    port = g_key_file_get_integer (session->config,
                                   "database", "port", &error);
    if (error) {
        g_clear_error (&error);
        port = PGSQL_DEFAULT_PORT;
    }

    max_connections = g_key_file_get_integer (session->config, "database", "max_connections", &error);
    if (error || max_connections < 0) {
        g_clear_error (&error);
        max_connections = DEFAULT_MAX_CONNECTIONS;
    }

    session->db = seaf_db_new_pgsql (host, port, user, passwd, db, unix_socket, max_connections);
    if (!session->db) {
        seaf_warning ("Failed to start pgsql db.\n");
        return -1;
    }

    g_free (host);
    g_free (user);
    g_free (passwd);
    g_free (db);
    g_free (unix_socket);

    return 0;
}

#endif

int
load_database_config (SeafileSession *session)
{
    char *type;
    GError *error = NULL;
    int ret = 0;
    gboolean create_tables = FALSE;

    type = seaf_key_file_get_string (session->config, "database", "type", &error);
    /* Default to use sqlite if not set. */
    if (!type || strcasecmp (type, "sqlite") == 0) {
        ret = sqlite_db_start (session);
    }
#ifdef HAVE_MYSQL
    else if (strcasecmp (type, "mysql") == 0) {
        ret = mysql_db_start (session);
    }
#endif
#ifdef HAVE_POSTGRESQL
    else if (strcasecmp (type, "pgsql") == 0) {
        ret = pgsql_db_start (session);
    }
#endif
    else {
        seaf_warning ("Unsupported db type %s.\n", type);
        ret = -1;
    }
    if (ret == 0) {
        if (g_key_file_has_key (session->config, "database", "create_tables", NULL))
            create_tables = g_key_file_get_boolean (session->config,
                                                    "database", "create_tables", NULL);
        session->create_tables = create_tables;
    }

    g_free (type);

    return ret;
}

static int
ccnet_init_sqlite_database (SeafileSession *session)
{
    char *db_path;

    db_path = g_build_path ("/", session->ccnet_dir, CCNET_DB, NULL);
    session->ccnet_db = seaf_db_new_sqlite (db_path, DEFAULT_MAX_CONNECTIONS);
    if (!session->ccnet_db) {
        seaf_warning ("Failed to open ccnet database.\n");
        return -1;
    }
    return 0;
}

#ifdef HAVE_MYSQL

static int
ccnet_init_mysql_database (SeafileSession *session)
{
    char *host, *user, *passwd, *db, *unix_socket, *charset;
    int port;
    gboolean use_ssl = FALSE;
    int max_connections = 0;

    host = ccnet_key_file_get_string (session->ccnet_config, "Database", "HOST");
    unix_socket = ccnet_key_file_get_string (session->ccnet_config, "Database", "UNIX_SOCKET");
    user = ccnet_key_file_get_string (session->ccnet_config, "Database", "USER");
    passwd = ccnet_key_file_get_string (session->ccnet_config, "Database", "PASSWD");
    db = ccnet_key_file_get_string (session->ccnet_config, "Database", "DB");

    if (!host && !unix_socket) {
        seaf_warning ("DB host or socket not set in config.\n");
        return -1;
    }
    if (!user) {
        seaf_warning ("DB user not set in config.\n");
        return -1;
    }
    if (!passwd) {
        seaf_warning ("DB passwd not set in config.\n");
        return -1;
    }
    if (!db) {
        seaf_warning ("DB name not set in config.\n");
        return -1;
    }

    GError *error = NULL;
    port = g_key_file_get_integer (session->ccnet_config, "Database", "PORT", &error);
    if (error) {
        g_clear_error (&error);
        port = MYSQL_DEFAULT_PORT;
    }

    use_ssl = g_key_file_get_boolean (session->ccnet_config, "Database", "USE_SSL", NULL);

    charset = ccnet_key_file_get_string (session->ccnet_config,
                                         "Database", "CONNECTION_CHARSET");

    max_connections = g_key_file_get_integer (session->ccnet_config,
                                              "Database", "MAX_CONNECTIONS",
                                              &error);
    if (error || max_connections < 0) {
        max_connections = DEFAULT_MAX_CONNECTIONS;
        g_clear_error (&error);
    }

    session->ccnet_db = seaf_db_new_mysql (host, port, user, passwd, db, unix_socket, use_ssl, charset, max_connections);
    if (!session->ccnet_db) {
        seaf_warning ("Failed to open ccnet database.\n");
        return -1;
    }

    g_free (host);
    g_free (user);
    g_free (passwd);
    g_free (db);
    g_free (unix_socket);
    g_free (charset);

    return 0;
}

#endif

#ifdef HAVE_POSTGRESQL

static int 
ccnet_init_pgsql_database (SeafileSession *session)
{
    char *host, *user, *passwd, *db, *unix_socket;
    unsigned int port;
    unsigned int max_connections = 0;

    host = ccnet_key_file_get_string (session->ccnet_config, "Database", "HOST");
    unix_socket = ccnet_key_file_get_string (session->ccnet_config, "Database", "UNIX_SOCKET");
    user = ccnet_key_file_get_string (session->ccnet_config, "Database", "USER");
    passwd = ccnet_key_file_get_string (session->ccnet_config, "Database", "PASSWD");
    db = ccnet_key_file_get_string (session->ccnet_config, "Database", "DB");

    if (!host && !unix_socket) {
        g_warning ("DB host or socket not set in config.\n");
        return -1;
    }
    if (!user) {
        g_warning ("DB user not set in config.\n");
        return -1;
    }
    if (!passwd) {
        g_warning ("DB passwd not set in config.\n");
        return -1;
    }
    if (!db) {
        g_warning ("DB name not set in config.\n");
        return -1;
    }

    GError *error = NULL;
    port = g_key_file_get_integer (session->ccnet_config, "Database", "PORT", &error);
    if (error) {
        g_clear_error (&error);
        port = PGSQL_DEFAULT_PORT;
    }

    max_connections = g_key_file_get_integer (session->ccnet_config, "Database", "MAX_CONNECTIONS", &error);
    if (error || max_connections < 0) {
        max_connections = DEFAULT_MAX_CONNECTIONS;
        g_clear_error (&error);
    }

    session->ccnet_db = seaf_db_new_pgsql (host, port, user, passwd, db, unix_socket, max_connections);

    if (!session->db) {
        g_warning ("Failed to open database.\n");
        return -1;
    }

    g_free (host);
    g_free (user);
    g_free (passwd);
    g_free (db);
    g_free (unix_socket);

    return 0;
}

#endif

int
load_ccnet_database_config (SeafileSession *session)
{
    int ret;
    char *engine;
    gboolean create_tables = FALSE;

    engine = ccnet_key_file_get_string (session->ccnet_config, "Database", "ENGINE");
    if (!engine || strcasecmp (engine, "sqlite") == 0) {
        seaf_message ("Use database sqlite\n");
        ret = ccnet_init_sqlite_database (session);
    }
#ifdef HAVE_MYSQL
    else if (strcasecmp (engine, "mysql") == 0) {
        seaf_message("Use database Mysql\n");
        ret = ccnet_init_mysql_database (session);
    }
#endif
#ifdef HAVE_POSTGRESQL
    else if (strcasecmp (engine, "pgsql") == 0) {
        ccnet_debug ("Use database PostgreSQL\n");
        ret = ccnet_init_pgsql_database (session);
    }
#endif
    else {
        seaf_warning ("Unknown database type: %s.\n", engine);
        ret = -1;
    }
    if (ret == 0) {
        if (g_key_file_has_key (session->ccnet_config, "Database", "CREATE_TABLES", NULL))
            create_tables = g_key_file_get_boolean (session->ccnet_config, "Database", "CREATE_TABLES", NULL);
        session->ccnet_create_tables = create_tables;
    }

    return ret;
}
