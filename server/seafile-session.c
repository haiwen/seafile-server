/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <stdint.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include "utils.h"

#include "seafile-session.h"

#include "mq-mgr.h"
#include "seaf-db.h"
#include "seaf-utils.h"

#include "log.h"

#define CONNECT_INTERVAL_MSEC 10 * 1000

#define DEFAULT_THREAD_POOL_SIZE 500

#define DEFAULT_FIXED_BLOCK_SIZE ((gint64)1 << 23) /* 8MB */

static void
load_fileserver_config (SeafileSession *session)
{
    int web_token_expire_time;
    int max_index_processing_threads;
    int fixed_block_size_mb;
    int max_indexing_threads;

    session->go_fileserver = g_key_file_get_boolean (session->config,
                                                     "fileserver", "use_go_fileserver",
                                                     NULL);
    if (session->go_fileserver) {
        char *type = NULL;
        type = g_key_file_get_string (session->config, "database", "type", NULL);
        if (!type || g_strcmp0 (type, "mysql") != 0) {
            session->go_fileserver = FALSE;
        }
        g_free (type);
    }

    web_token_expire_time = g_key_file_get_integer (session->config,
                                                    "fileserver", "web_token_expire_time",
                                                    NULL);
    if (web_token_expire_time <= 0) {
        session->web_token_expire_time = 3600;
    } else {
        session->web_token_expire_time = web_token_expire_time;
    }

    seaf_message ("fileserver: web_token_expire_time = %d\n",
                  session->web_token_expire_time);

    max_index_processing_threads = g_key_file_get_integer (session->config,
                                                           "fileserver", "max_index_processing_threads",
                                                           NULL);
    if (max_index_processing_threads <= 0) {
        session->max_index_processing_threads = 3;
    } else {
        session->max_index_processing_threads = max_index_processing_threads;
    }

    seaf_message ("fileserver: max_index_processing_threads= %d\n",
                  session->max_index_processing_threads);


    fixed_block_size_mb = g_key_file_get_integer (session->config,
                                                  "fileserver", "fixed_block_size",
                                                  NULL);
    if (fixed_block_size_mb <= 0){
        session->fixed_block_size = DEFAULT_FIXED_BLOCK_SIZE;
    } else {
        session->fixed_block_size = fixed_block_size_mb * ((gint64)1 << 20);
    }

    seaf_message ("fileserver: fixed_block_size = %"G_GINT64_FORMAT"\n",
                  session->fixed_block_size);

    max_indexing_threads = g_key_file_get_integer (session->config,
                                                   "fileserver", "max_indexing_threads",
                                                   NULL);
    if (max_indexing_threads <= 0) {
        session->max_indexing_threads = 1;
    } else {
        session->max_indexing_threads = max_indexing_threads;
    }

    seaf_message ("fileserver: max_indexing_threads = %d\n",
                  session->max_indexing_threads);

    return;
}

static int
load_config (SeafileSession *session, const char *config_file_path)
{
    int ret = 0;
    GError *error = NULL;
    GKeyFile *config = NULL;
    char *notif_server = NULL;
    int notif_port = 8083;
    const char *private_key = NULL;
    const char *site_root = NULL;
    const char *log_to_stdout = NULL;

    config = g_key_file_new ();
    if (!g_key_file_load_from_file (config, config_file_path,
                                    G_KEY_FILE_NONE, &error)) {
        seaf_warning ("Failed to load config file.\n");
        ret = -1;
        goto out;
    }

    session->config = config;

    session->cloud_mode = g_key_file_get_boolean (config,
                                                  "general", "cloud_mode",
                                                  NULL);

    session->obj_cache = objcache_new ();

    // Read config from env
    private_key = g_getenv("JWT_PRIVATE_KEY");
    site_root = g_getenv("SITE_ROOT");
    log_to_stdout = g_getenv("SEAFILE_LOG_TO_STDOUT");
    notif_server = g_getenv("NOTIFICATION_SERVER_URL");

    if (!private_key) {
        seaf_warning ("Failed to read JWT_PRIVATE_KEY.\n");
        ret = -1;
        goto out;
    }
    if (notif_server && g_strcmp0 (notif_server, "") != 0) {
        session->notif_server_private_key = g_strdup (private_key);
        char notif_url[128];
        g_sprintf (notif_url, "%s:%d", notif_server, notif_port);
        session->notif_url = g_strdup (notif_url);
    }
    session->seahub_pk = g_strdup (private_key);
    if (!site_root || g_strcmp0 (site_root, "") == 0) {
        site_root = "/";
    }
    session->seahub_url = g_strdup_printf("http://127.0.0.1:8000%sapi/v2.1/internal", site_root);
    session->seahub_conn_pool = connection_pool_new ();

    if (g_strcmp0 (log_to_stdout, "true") == 0) {
        session->log_to_stdout = TRUE;
    }

out:
    if (ret < 0) {
        if (config)
            g_key_file_free (config);
    }
    return ret;
}

SeafileSession *
seafile_session_new(const char *central_config_dir,
                    const char *seafile_dir,
                    const char *ccnet_dir)
{
    char *abs_central_config_dir = NULL;
    char *abs_seafile_dir;
    char *abs_ccnet_dir = NULL;
    char *tmp_file_dir;
    char *config_file_path = NULL;
    SeafileSession *session = NULL;

    abs_ccnet_dir = ccnet_expand_path (ccnet_dir);
    abs_seafile_dir = ccnet_expand_path (seafile_dir);
    tmp_file_dir = g_build_filename (abs_seafile_dir, "tmpfiles", NULL);
    if (central_config_dir) {
        abs_central_config_dir = ccnet_expand_path (central_config_dir);
    }

    if (checkdir_with_mkdir (abs_seafile_dir) < 0) {
        seaf_warning ("Config dir %s does not exist and is unable to create\n",
                   abs_seafile_dir);
        goto onerror;
    }

    if (checkdir_with_mkdir (tmp_file_dir) < 0) {
        seaf_warning ("Temp file dir %s does not exist and is unable to create\n",
                   tmp_file_dir);
        goto onerror;
    }

    if (checkdir_with_mkdir (abs_ccnet_dir) < 0) {
        seaf_warning ("Ccnet config dir %s does not exist and is unable to create\n",
                   abs_ccnet_dir);
        goto onerror;
    }

    config_file_path = g_build_filename(
        abs_central_config_dir ? abs_central_config_dir : abs_seafile_dir,
        "seafile.conf", NULL);

    session = g_new0(SeafileSession, 1);
    session->seaf_dir = abs_seafile_dir;
    session->ccnet_dir = abs_ccnet_dir;
    session->tmp_file_dir = tmp_file_dir;

    if (load_config (session, config_file_path) < 0) {
        goto onerror;
    }

    load_fileserver_config (session);

    if (load_database_config (session) < 0) {
        seaf_warning ("Failed to load database config.\n");
        goto onerror;
    }

    if (load_ccnet_database_config (session) < 0) {
        seaf_warning ("Failed to load ccnet database config.\n");
        goto onerror;
    }

    session->cfg_mgr = seaf_cfg_manager_new (session);
    if (!session->cfg_mgr)
        goto onerror;
    session->fs_mgr = seaf_fs_manager_new (session, abs_seafile_dir);
    if (!session->fs_mgr)
        goto onerror;
    session->block_mgr = seaf_block_manager_new (session, abs_seafile_dir);
    if (!session->block_mgr)
        goto onerror;
    session->commit_mgr = seaf_commit_manager_new (session);
    if (!session->commit_mgr)
        goto onerror;
    session->repo_mgr = seaf_repo_manager_new (session);
    if (!session->repo_mgr)
        goto onerror;
    session->branch_mgr = seaf_branch_manager_new (session);
    if (!session->branch_mgr)
        goto onerror;

    session->share_mgr = seaf_share_manager_new (session);
    if (!session->share_mgr)
        goto onerror;
    
    session->web_at_mgr = seaf_web_at_manager_new (session);
    if (!session->web_at_mgr)
        goto onerror;

    session->passwd_mgr = seaf_passwd_manager_new (session);
    if (!session->passwd_mgr)
        goto onerror;

    session->quota_mgr = seaf_quota_manager_new (session);
    if (!session->quota_mgr)
        goto onerror;

    session->copy_mgr = seaf_copy_manager_new (session);
    if (!session->copy_mgr)
        goto onerror;

    session->job_mgr = ccnet_job_manager_new (DEFAULT_THREAD_POOL_SIZE);

    session->size_sched = size_scheduler_new (session);

    session->mq_mgr = seaf_mq_manager_new ();
    if (!session->mq_mgr)
        goto onerror;

#ifdef HAVE_EVHTP
    session->http_server = seaf_http_server_new (session);
    if (!session->http_server)
        goto onerror;

    session->zip_download_mgr = zip_download_mgr_new ();
    if (!session->zip_download_mgr)
        goto onerror;
#endif

    session->index_blocks_mgr = index_blocks_mgr_new (session);
    if (!session->index_blocks_mgr)
        goto onerror;

    session->user_mgr = ccnet_user_manager_new (session);
    if (!session->user_mgr)
        goto onerror;

    session->group_mgr = ccnet_group_manager_new (session);
    if (!session->group_mgr)
        goto onerror;

    session->org_mgr = ccnet_org_manager_new (session);
    if (!session->org_mgr)
        goto onerror;

    if (session->notif_url) {
        session->notif_mgr = seaf_notif_manager_new (session, session->notif_url);
        if (!session->notif_mgr) {
            goto onerror;
        }
    }

    session->metric_mgr = seaf_metric_manager_new (session);
    if (!session->metric_mgr)
        goto onerror;

    return session;

onerror:
    g_free (config_file_path);
    free (abs_seafile_dir);
    free (abs_ccnet_dir);
    g_free (tmp_file_dir);
    g_free (session);
    return NULL;    
}

SeafileSession *
seafile_repair_session_new(const char *central_config_dir,
                           const char *seafile_dir,
                           const char *ccnet_dir)
{
    char *abs_central_config_dir = NULL;
    char *abs_seafile_dir;
    char *abs_ccnet_dir = NULL;
    char *tmp_file_dir;
    char *config_file_path;
    GKeyFile *config;
    SeafileSession *session = NULL;
    gboolean notif_enabled = FALSE;
    int notif_port = 8083;
    gboolean cluster_mode;
    gboolean use_block_cache;
    int block_cache_size_limit;
    char **block_cache_file_types;
    gint64 repo_file_number_limit = -1;

    abs_ccnet_dir = ccnet_expand_path (ccnet_dir);
    abs_seafile_dir = ccnet_expand_path (seafile_dir);
    tmp_file_dir = g_build_filename (abs_seafile_dir, "tmpfiles", NULL);
    if (central_config_dir) {
        abs_central_config_dir = ccnet_expand_path (central_config_dir);
    }

    config_file_path = g_build_filename(
        abs_central_config_dir ? abs_central_config_dir : abs_seafile_dir,
        "seafile.conf", NULL);

    GError *error = NULL;
    config = g_key_file_new ();
    if (!g_key_file_load_from_file (config, config_file_path, 
                                    G_KEY_FILE_NONE, &error)) {
        seaf_warning ("Failed to load config file.\n");
        g_key_file_free (config);
        g_free (config_file_path);
        goto onerror;
    }
    g_free (config_file_path);

    session = g_new0(SeafileSession, 1);
    session->seaf_dir = abs_seafile_dir;
    session->ccnet_dir = abs_ccnet_dir;
    session->tmp_file_dir = tmp_file_dir;
    session->config = config;
    session->is_repair = TRUE;

    if (load_database_config (session) < 0) {
        seaf_warning ("Failed to load database config.\n");
        goto onerror;
    }

    if (load_ccnet_database_config (session) < 0) {
        seaf_warning ("Failed to load ccnet database config.\n");
        goto onerror;
    }

    session->fs_mgr = seaf_fs_manager_new (session, abs_seafile_dir);
    if (!session->fs_mgr)
        goto onerror;
    session->block_mgr = seaf_block_manager_new (session, abs_seafile_dir);
    if (!session->block_mgr)
        goto onerror;
    session->commit_mgr = seaf_commit_manager_new (session);
    if (!session->commit_mgr)
        goto onerror;
    session->repo_mgr = seaf_repo_manager_new (session);
    if (!session->repo_mgr)
        goto onerror;
    session->branch_mgr = seaf_branch_manager_new (session);
    if (!session->branch_mgr)
        goto onerror;

    session->job_mgr = ccnet_job_manager_new (DEFAULT_THREAD_POOL_SIZE);

    session->size_sched = size_scheduler_new (session);

    return session;

onerror:
    free (abs_seafile_dir);
    free (abs_ccnet_dir);
    g_free (tmp_file_dir);
    g_free (session);
    return NULL;
}

int
seafile_session_init (SeafileSession *session)
{
    if (seaf_commit_manager_init (session->commit_mgr) < 0)
        return -1;

    if (seaf_fs_manager_init (session->fs_mgr) < 0)
        return -1;

    if (seaf_branch_manager_init (session->branch_mgr) < 0) {
        seaf_warning ("Failed to init branch manager.\n");
        return -1;
    }

    if (seaf_repo_manager_init (session->repo_mgr) < 0) {
        seaf_warning ("Failed to init repo manager.\n");
        return -1;
    }

    if (seaf_quota_manager_init (session->quota_mgr) < 0) {
        seaf_warning ("Failed to init quota manager.\n");
        return -1;
    }

    if (ccnet_user_manager_prepare (session->user_mgr) < 0) {
        seaf_warning ("Failed to init user manager.\n");
        return -1;
    }

    if (ccnet_group_manager_prepare (session->group_mgr) < 0) {
        seaf_warning ("Failed to init group manager.\n");
        return -1;
    }

    if (ccnet_org_manager_prepare (session->org_mgr) < 0) {
        seaf_warning ("Failed to init org manager.\n");
        return -1;
    }

    if ((session->create_tables || seaf_db_type(session->db) == SEAF_DB_TYPE_PGSQL)
        && seaf_cfg_manager_init (session->cfg_mgr) < 0) {
        seaf_warning ("Failed to init config manager.\n");
        return -1;
    }

    return 0;
}

int
seafile_session_start (SeafileSession *session)
{
    if (seaf_share_manager_start (session->share_mgr) < 0) {
        seaf_warning ("Failed to start share manager.\n");
        return -1;
    }

    if (seaf_web_at_manager_start (session->web_at_mgr) < 0) {
        seaf_warning ("Failed to start web access check manager.\n");
        return -1;
    }

    if (seaf_passwd_manager_start (session->passwd_mgr) < 0) {
        seaf_warning ("Failed to start password manager.\n");
        return -1;
    }

    if (size_scheduler_start (session->size_sched) < 0) {
        seaf_warning ("Failed to start size scheduler.\n");
        return -1;
    }

    if (seaf_copy_manager_start (session->copy_mgr) < 0) {
        seaf_warning ("Failed to start copy manager.\n");
        return -1;
    }

    if (!session->go_fileserver) {
#ifdef HAVE_EVHTP
        if (seaf_http_server_start (session->http_server) < 0) {
            seaf_warning ("Failed to start http server thread.\n");
            return -1;
        }
#else
        seaf_warning ("Failed to start http server thread, please use go fileserver.\n");
        return -1;
#endif
    }

    if (seaf_metric_manager_start (session->metric_mgr) < 0) {
        seaf_warning ("Failed to start metric manager.\n");
        return -1;
    }

    return 0;
}

char *
get_system_default_repo_id (SeafileSession *session)
{
    char *sql = "SELECT info_value FROM SystemInfo WHERE info_key='default_repo_id'";
    return seaf_db_get_string (session->db, sql);
}

int
set_system_default_repo_id (SeafileSession *session, const char *repo_id)
{
    char sql[256];
    snprintf (sql, sizeof(sql),
              "INSERT INTO SystemInfo (info_key, info_value) VALUES ('default_repo_id', '%s')",
              repo_id);
    return seaf_db_query (session->db, sql);
}

static int
del_system_default_repo_id (SeafileSession *session)
{
    const char *sql = "DELETE FROM SystemInfo WHERE info_key='default_repo_id'";
    return seaf_db_query (session->db, sql);
}

#define DEFAULT_TEMPLATE_DIR "library-template"

static void
copy_template_files_recursive (SeafileSession *session,
                               const char *repo_id,
                               const char *repo_dir_path,
                               const char *dir_path)
{
    GDir *dir;
    const char *name;
    char *sub_path, *repo_sub_path;
    SeafStat st;
    GError *error = NULL;
    int rc;

    dir = g_dir_open (dir_path, 0, &error);
    if (!dir) {
        seaf_warning ("Failed to open template dir %s: %s.\n",
                      dir_path, error->message);
        return;
    }

    while ((name = g_dir_read_name(dir)) != NULL) {
        sub_path = g_build_filename (dir_path, name, NULL);
        if (seaf_stat (sub_path, &st) < 0) {
            seaf_warning ("Failed to stat %s: %s.\n", sub_path, strerror(errno));
            g_free (sub_path);
            continue;
        }

        if (S_ISREG(st.st_mode)) {
            rc = seaf_repo_manager_post_file (session->repo_mgr,
                                              repo_id,
                                              sub_path,
                                              repo_dir_path,
                                              name,
                                              "System",
                                              NULL);
            if (rc < 0)
                seaf_warning ("Failed to add template file %s.\n", sub_path);
        } else if (S_ISDIR(st.st_mode)) {
            rc = seaf_repo_manager_post_dir (session->repo_mgr,
                                             repo_id,
                                             repo_dir_path,
                                             name,
                                             "System",
                                             NULL);
            if (rc < 0) {
                seaf_warning ("Failed to add template dir %s.\n", sub_path);
                g_free (sub_path);
                continue;
            }

            repo_sub_path = g_build_path ("/", repo_dir_path, name, NULL);
            copy_template_files_recursive (session, repo_id,
                                           repo_sub_path, sub_path);
            g_free (repo_sub_path);
        }
        g_free (sub_path);
    }
    g_dir_close (dir);
}

static void *
create_system_default_repo (void *data)
{
    SeafileSession *session = data;
    char *repo_id;
    char *template_path;

    /* If default repo is not set or doesn't exist, create a new one. */
    repo_id = get_system_default_repo_id (session);
    if (repo_id != NULL) {
        SeafRepo *repo;
        repo = seaf_repo_manager_get_repo (session->repo_mgr, repo_id);
        if (!repo) {
            seaf_warning ("Failed to get system default repo. Create a new one.\n");
            del_system_default_repo_id (session);
            seaf_repo_manager_del_repo (session->repo_mgr, repo_id, NULL);
            g_free (repo_id);
        } else {
            seaf_repo_unref (repo);
            g_free (repo_id);
            return data;
        }
    }

    repo_id = seaf_repo_manager_create_new_repo (session->repo_mgr,
                                                 "My Library Template",
                                                 "Template for creating 'My Library' for users",
                                                 "System",
                                                 NULL, -1, NULL, NULL, NULL);
    if (!repo_id) {
        seaf_warning ("Failed to create system default repo.\n");
        return data;
    }

    set_system_default_repo_id (session, repo_id);

    template_path = g_build_filename (session->seaf_dir, DEFAULT_TEMPLATE_DIR, NULL);
    copy_template_files_recursive (session, repo_id, "/", template_path);

    g_free (repo_id);
    g_free (template_path);
    return data;
}

void
schedule_create_system_default_repo (SeafileSession *session)
{
    int db_type = seaf_db_type (session->db);
    char *sql;

    if (db_type == SEAF_DB_TYPE_MYSQL)
        sql = "CREATE TABLE IF NOT EXISTS SystemInfo "
        "(id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
        "info_key VARCHAR(256), info_value VARCHAR(1024))";
    else
        sql = "CREATE TABLE IF NOT EXISTS SystemInfo( "
        "info_key VARCHAR(256), info_value VARCHAR(1024))";

    if ((session->create_tables || db_type == SEAF_DB_TYPE_PGSQL)
        && seaf_db_query (session->db, sql) < 0)
        return;

    ccnet_job_manager_schedule_job (session->job_mgr,
                                    create_system_default_repo,
                                    NULL, session);
}
