#include "common.h"

#include "log.h"

#include "seafile-session.h"
#include "seaf-utils.h"
#include "seaf-db.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <jwt.h>

#define JWT_TOKEN_EXPIRE_TIME 3*24*3600 /* 3 days*/

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
    gboolean skip_verify = FALSE;
    char *ca_path = NULL;
    int max_connections = 0;
    GError *error = NULL;

    unix_socket = seaf_key_file_get_string (session->config, 
                                         "database", "unix_socket", NULL);

    host = seaf_key_file_get_string (session->config, "database", "host", NULL);
    if (!host && !unix_socket) {
        seaf_warning ("DB host not set in config.\n");
        return -1;
    }

    port = g_key_file_get_integer (session->config, "database", "port", &error);
    if (error) {
        g_clear_error (&error);
        port = MYSQL_DEFAULT_PORT;
    }

    user = seaf_key_file_get_string (session->config, "database", "user", NULL);
    if (!user && !unix_socket) {
        seaf_warning ("DB user not set in config.\n");
        return -1;
    }

    passwd = seaf_key_file_get_string (session->config, "database", "password", NULL);
    if (!passwd && !unix_socket) {
        seaf_warning ("DB passwd not set in config.\n");
        return -1;
    }

    db = seaf_key_file_get_string (session->config, "database", "db_name", NULL);
    if (!db) {
        seaf_warning ("DB name not set in config.\n");
        return -1;
    }

    use_ssl = g_key_file_get_boolean (session->config,
                                      "database", "use_ssl", NULL);

    skip_verify = g_key_file_get_boolean (session->config,
                                          "database", "skip_verify", NULL);

    if (use_ssl && !skip_verify) {
        ca_path = seaf_key_file_get_string (session->config,
                                            "database", "ca_path", NULL);
        if (!ca_path) {
            seaf_warning ("ca_path is required if use ssl and don't skip verify.\n");
            return -1;
        }
    }

    charset = seaf_key_file_get_string (session->config,
                                     "database", "connection_charset", NULL);

    max_connections = g_key_file_get_integer (session->config,
                                              "database", "max_connections",
                                              &error);
    if (error || max_connections < 0) {
        if (error)
            g_clear_error (&error);
        max_connections = DEFAULT_MAX_CONNECTIONS;
    }

    session->db = seaf_db_new_mysql (host, port, user, passwd, db, unix_socket, use_ssl, skip_verify, ca_path, charset, max_connections);
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

static int
pgsql_db_start (SeafileSession *session)
{
    char *host, *user, *passwd, *db, *unix_socket;
    unsigned int port;
    GError *error = NULL;

    host = seaf_key_file_get_string (session->config, "database", "host", &error);
    if (!host) {
        seaf_warning ("DB host not set in config.\n");
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
        port = 0;
        g_clear_error (&error);
    }

    unix_socket = seaf_key_file_get_string (session->config,
                                         "database", "unix_socket", &error);

    session->db = seaf_db_new_pgsql (host, port, user, passwd, db, unix_socket,
                                     DEFAULT_MAX_CONNECTIONS);
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
    gboolean skip_verify = FALSE;
    char *ca_path = NULL;
    int max_connections = 0;

    host = ccnet_key_file_get_string (session->ccnet_config, "Database", "HOST");
    user = ccnet_key_file_get_string (session->ccnet_config, "Database", "USER");
    passwd = ccnet_key_file_get_string (session->ccnet_config, "Database", "PASSWD");
    db = ccnet_key_file_get_string (session->ccnet_config, "Database", "DB");
    unix_socket = ccnet_key_file_get_string (session->ccnet_config,
                                             "Database", "UNIX_SOCKET");

    if (!host && !unix_socket) {
        seaf_warning ("DB host not set in config.\n");
        return -1;
    }
    if (!user && !unix_socket) {
        seaf_warning ("DB user not set in config.\n");
        return -1;
    }
    if (!passwd && !unix_socket) {
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
    skip_verify = g_key_file_get_boolean (session->ccnet_config, "Database", "SKIP_VERIFY", NULL);
    if (use_ssl && !skip_verify) {
        ca_path = seaf_key_file_get_string (session->ccnet_config,
                                            "Database", "CA_PATH", NULL);
        if (!ca_path) {
            seaf_warning ("ca_path is required if use ssl and don't skip verify.\n");
            return -1;
        }
    }

    charset = ccnet_key_file_get_string (session->ccnet_config,
                                         "Database", "CONNECTION_CHARSET");

    max_connections = g_key_file_get_integer (session->ccnet_config,
                                              "Database", "MAX_CONNECTIONS",
                                              &error);
    if (error || max_connections < 0) {
        max_connections = DEFAULT_MAX_CONNECTIONS;
        if (error)
            g_clear_error (&error);
    }

    session->ccnet_db = seaf_db_new_mysql (host, port, user, passwd, db, unix_socket, use_ssl, skip_verify, ca_path, charset, max_connections);
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
#if 0
    else if (strncasecmp (engine, DB_PGSQL, sizeof(DB_PGSQL)) == 0) {
        ccnet_debug ("Use database PostgreSQL\n");
        ret = init_pgsql_database (session);
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

    g_free (engine);
    return ret;
}

#ifdef FULL_FEATURE

char *
seaf_gen_notif_server_jwt (const char *repo_id, const char *username)
{
    char *jwt_token = NULL;
    gint64 now = (gint64)time(NULL);

    jwt_t *jwt = NULL;

    if (!seaf->notif_server_private_key) {
        seaf_warning ("No private key is configured for generating jwt token\n");
        return NULL;
    }

    int ret = jwt_new (&jwt);
    if (ret != 0 || jwt == NULL) {
        seaf_warning ("Failed to create jwt\n");
        goto out;
    }

    ret = jwt_add_grant (jwt, "repo_id", repo_id);
    if (ret != 0) {
        seaf_warning ("Failed to add repo_id to jwt\n");
        goto out;
    }
    ret = jwt_add_grant (jwt, "username", username);
    if (ret != 0) {
        seaf_warning ("Failed to add username to jwt\n");
        goto out;
    }
    ret = jwt_add_grant_int (jwt, "exp", now + JWT_TOKEN_EXPIRE_TIME);
    if (ret != 0) {
        seaf_warning ("Failed to expire time to jwt\n");
        goto out;
    }
    ret = jwt_set_alg (jwt, JWT_ALG_HS256, (unsigned char *)seaf->notif_server_private_key, strlen(seaf->notif_server_private_key));
    if (ret != 0) {
        seaf_warning ("Failed to set alg\n");
        goto out;
    }

    jwt_token = jwt_encode_str (jwt);

out:
    jwt_free (jwt);
    return jwt_token;
}
#endif

char *
seaf_parse_auth_token (const char *auth_token)
{
    char *token = NULL;
    char **parts = NULL;

    if (!auth_token) {
        return NULL;
    }

    parts = g_strsplit (auth_token, " ", 2);
    if (!parts) {
        return NULL;
    }

    if (g_strv_length (parts) < 2) {
        g_strfreev (parts);
        return NULL;
    }

    token = g_strdup(parts[1]);

    g_strfreev (parts);
    return token;
}

void
split_filename (const char *filename, char **name, char **ext)
{
    char *dot;

    dot = strrchr (filename, '.');
    if (dot) {
        *ext = g_strdup (dot + 1);
        *name = g_strndup (filename, dot - filename);
    } else {
        *name = g_strdup (filename);
        *ext = NULL;
    }
}
