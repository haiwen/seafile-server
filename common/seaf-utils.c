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

typedef struct DBOption {
    char *user;
    char *passwd;
    char *host;
    char *ca_path;
    char *charset;
    char *ccnet_db_name;
    char *seafile_db_name;
    gboolean use_ssl;
    gboolean skip_verify;
    int port;
    int max_connections;
} DBOption;

static void
db_option_free (DBOption *option)
{
    if (!option)
        return;
    g_free (option->user);
    g_free (option->passwd);
    g_free (option->host);
    g_free (option->ca_path);
    g_free (option->charset);
    g_free (option->ccnet_db_name);
    g_free (option->seafile_db_name);
    g_free (option);
}

static int
load_db_option_from_env (DBOption *option)
{
    const char *env_user, *env_passwd, *env_host, *env_ccnet_db, *env_seafile_db;

    env_user = g_getenv("SEAFILE_MYSQL_DB_USER");
    env_passwd = g_getenv("SEAFILE_MYSQL_DB_PASSWORD");
    env_host = g_getenv("SEAFILE_MYSQL_DB_HOST");
    env_ccnet_db = g_getenv("SEAFILE_MYSQL_DB_CCNET_DB_NAME");
    env_seafile_db = g_getenv("SEAFILE_MYSQL_DB_SEAFILE_DB_NAME");

    if (env_user && g_strcmp0 (env_user, "") != 0) {
        g_free (option->user);
        option->user = g_strdup (env_user);
    }
    if (env_passwd && g_strcmp0 (env_passwd, "") != 0) {
        g_free (option->passwd);
        option->passwd = g_strdup (env_passwd);
    }
    if (env_host && g_strcmp0 (env_host, "") != 0) {
        g_free (option->host);
        option->host = g_strdup (env_host);
    }
    if (env_ccnet_db && g_strcmp0 (env_ccnet_db, "") != 0) {
        g_free (option->ccnet_db_name);
        option->ccnet_db_name = g_strdup (env_ccnet_db);
    } else if (!option->ccnet_db_name) {
        option->ccnet_db_name = g_strdup ("ccnet_db");
        seaf_message ("Failed to read SEAFILE_MYSQL_DB_CCNET_DB_NAME, use ccnet_db by default");
    }
    if (env_seafile_db && g_strcmp0 (env_seafile_db, "") != 0) {
        g_free (option->seafile_db_name);
        option->seafile_db_name = g_strdup (env_seafile_db);
    } else if (!option->seafile_db_name) {
        option->seafile_db_name = g_strdup ("seafile_db");
		seaf_message ("Failed to read SEAFILE_MYSQL_DB_SEAFILE_DB_NAME, use seafile_db by default");
    }

    return 0;
}

static DBOption *
load_db_option (SeafileSession *session)
{
    GError *error = NULL;
    int ret = 0;
    DBOption *option = g_new0 (DBOption, 1);

    option->host = seaf_key_file_get_string (session->config, "database", "host", NULL);

    option->port = g_key_file_get_integer (session->config, "database", "port", &error);
    if (error) {
        g_clear_error (&error);
        option->port = MYSQL_DEFAULT_PORT;
    }

    option->user = seaf_key_file_get_string (session->config, "database", "user", NULL);

    option->passwd = seaf_key_file_get_string (session->config, "database", "password", NULL);

    option->seafile_db_name = seaf_key_file_get_string (session->config, "database", "db_name", NULL);

    option->use_ssl = g_key_file_get_boolean (session->config,
                                      "database", "use_ssl", NULL);

    option->skip_verify = g_key_file_get_boolean (session->config,
                                          "database", "skip_verify", NULL);

    if (option->use_ssl && !option->skip_verify) {
        option->ca_path = seaf_key_file_get_string (session->config,
                                            "database", "ca_path", NULL);
        if (!option->ca_path) {
            seaf_warning ("ca_path is required if use ssl and don't skip verify.\n");
            ret = -1;
            goto out;
        }
    }

    option->charset = seaf_key_file_get_string (session->config,
                                     "database", "connection_charset", NULL);

    option->max_connections = g_key_file_get_integer (session->config,
                                              "database", "max_connections",
                                              &error);
    if (error || option->max_connections < 0) {
        if (error)
            g_clear_error (&error);
        option->max_connections = DEFAULT_MAX_CONNECTIONS;
    }

    load_db_option_from_env (option);

    if (!option->host) {
        seaf_warning ("DB host not set in config.\n");
        ret = -1;
        goto out;
    }

    if (!option->user) {
        seaf_warning ("DB user not set in config.\n");
        ret = -1;
        goto out;
    }

    if (!option->passwd) {
        seaf_warning ("DB passwd not set in config.\n");
        ret = -1;
        goto out;
    }

    if (!option->ccnet_db_name) {
        seaf_warning ("ccnet_db_name not set in config.\n");
        ret = -1;
        goto out;
    }
    if (!option->seafile_db_name) {
        seaf_warning ("db_name not set in config.\n");
        ret = -1;
        goto out;
    }

out:
    if (ret < 0) {
        db_option_free (option);
        return NULL;
    }

    return option;
}

static int
mysql_db_start (SeafileSession *session)
{
    DBOption *option = NULL;

    option = load_db_option (session);
    if (!option) {
        seaf_warning ("Failed to load database config.\n");
        return -1;
    }

    session->db = seaf_db_new_mysql (option->host, option->port, option->user, option->passwd, option->seafile_db_name,
                                     NULL, option->use_ssl, option->skip_verify, option->ca_path, option->charset, option->max_connections);
    if (!session->db) {
        db_option_free (option);
        seaf_warning ("Failed to start mysql db.\n");
        return -1;
    }

    db_option_free (option);
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
    /* Default to use mysql if not set. */
    if (type && strcasecmp (type, "sqlite") == 0) {
        ret = sqlite_db_start (session);
    }
#ifdef HAVE_MYSQL
    else {
        ret = mysql_db_start (session);
    }
#endif
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
    DBOption *option = NULL;

    option = load_db_option (session);
    if (!option) {
        seaf_warning ("Failed to load database config.\n");
        return -1;
    }

    session->ccnet_db = seaf_db_new_mysql (option->host, option->port, option->user, option->passwd, option->ccnet_db_name,
                                           NULL, option->use_ssl, option->skip_verify, option->ca_path, option->charset, option->max_connections);
    if (!session->ccnet_db) {
        db_option_free (option);
        seaf_warning ("Failed to open ccnet database.\n");
        return -1;
    }

    db_option_free (option);
    return 0;
}

#endif

int
load_ccnet_database_config (SeafileSession *session)
{
    int ret;
    char *engine;
    gboolean create_tables = FALSE;

    engine = ccnet_key_file_get_string (session->config, "database", "type");
    if (engine && strcasecmp (engine, "sqlite") == 0) {
        seaf_message ("Use database sqlite\n");
        ret = ccnet_init_sqlite_database (session);
    }
#ifdef HAVE_MYSQL
    else {
        seaf_message("Use database Mysql\n");
        ret = ccnet_init_mysql_database (session);
    }
#endif
    if (ret == 0) {
        if (g_key_file_has_key (session->config, "database", "create_tables", NULL))
            create_tables = g_key_file_get_boolean (session->config, "database", "create_tables", NULL);
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

static gboolean
collect_token_list (SeafDBRow *row, void *data)
{
    GList **p_tokens = data;
    const char *token;

    token = seaf_db_row_get_column_text (row, 0);
    *p_tokens = g_list_prepend (*p_tokens, g_strdup(token));

    return TRUE;
}

int
seaf_delete_repo_tokens (SeafRepo *repo)
{
    int ret = 0;
    const char *template;
    GList *token_list = NULL;
    GList *ptr;
    GString *token_list_str = g_string_new ("");
    GString *sql = g_string_new ("");
    int rc;

    template = "SELECT u.token FROM RepoUserToken as u WHERE u.repo_id=?";
    rc = seaf_db_statement_foreach_row (seaf->db, template,
                                        collect_token_list, &token_list,
                                        1, "string", repo->id);
    if (rc < 0) {
        goto out;
    }

    if (rc == 0)
        goto out;

    for (ptr = token_list; ptr; ptr = ptr->next) {
        const char *token = (char *)ptr->data;
        seaf_message ("delete token: %s\n", token);
        if (token_list_str->len == 0)
            g_string_append_printf (token_list_str, "'%s'", token);
        else
            g_string_append_printf (token_list_str, ",'%s'", token);
    }

    /* Note that there is a size limit on sql query. In MySQL it's 1MB by default.
     * Normally the token_list won't be that long.
     */
    g_string_printf (sql, "DELETE FROM RepoUserToken WHERE token in (%s)",
                     token_list_str->str);
    rc = seaf_db_statement_query (seaf->db, sql->str, 0);
    if (rc < 0) {
        goto out;
    }

    g_string_printf (sql, "DELETE FROM RepoTokenPeerInfo WHERE token in (%s)",
                     token_list_str->str);
    rc = seaf_db_statement_query (seaf->db, sql->str, 0);
    if (rc < 0) {
        goto out;
    }

out:
    g_string_free (token_list_str, TRUE);
    g_string_free (sql, TRUE);
    g_list_free_full (token_list, (GDestroyNotify)g_free);

    if (rc < 0) {
        ret = -1;
    }

    return ret;
}
