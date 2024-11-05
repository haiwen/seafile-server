#include "common.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <utils.h>
#include <locale.h>

#include "seafile-session.h"
#include "seaf-utils.h"

#include "log.h"

static int
read_excluded_users (SeafileSession *session);

SeafileSession *
seafile_session_new(const char *central_config_dir,
                    const char *seafile_dir,
                    const char *ccnet_dir)
{
    char *abs_central_config_dir = NULL;
    char *abs_seafile_dir;
    char *abs_ccnet_dir = NULL;
    char *tmp_file_dir;
    char *config_file_path;
    struct stat st;
    GKeyFile *config;
    SeafileSession *session = NULL;

    abs_ccnet_dir = ccnet_expand_path (ccnet_dir);
    abs_seafile_dir = ccnet_expand_path (seafile_dir);
    tmp_file_dir = g_build_filename(abs_seafile_dir, "tmpfiles", NULL);
    if (central_config_dir) {
        abs_central_config_dir = ccnet_expand_path (central_config_dir);
    }
    config_file_path = g_build_filename(
        abs_central_config_dir ? abs_central_config_dir : abs_seafile_dir,
        "seafile.conf", NULL);

    if (g_stat(abs_seafile_dir, &st) < 0 || !S_ISDIR(st.st_mode)) {
        seaf_warning ("Seafile data dir %s does not exist and is unable to create\n",
                   abs_seafile_dir);
        goto onerror;
    }

    if (g_stat(tmp_file_dir, &st) < 0 || !S_ISDIR(st.st_mode)) {
        seaf_warning("Seafile tmp dir %s does not exist and is unable to create\n",
                  tmp_file_dir);
        goto onerror;
    }

    if (g_stat(abs_ccnet_dir, &st) < 0 || !S_ISDIR(st.st_mode)) {
        seaf_warning("Ccnet dir %s does not exist and is unable to create\n",
                  abs_ccnet_dir);
        goto onerror;
    }

    GError *error = NULL;
    config = g_key_file_new ();
    if (!g_key_file_load_from_file (config, config_file_path, 
                                    G_KEY_FILE_NONE, &error)) {
        seaf_warning ("Failed to load config file.\n");
        g_free (config_file_path);
        g_key_file_free (config);
        goto onerror;
    }
    g_free (config_file_path);

    session = g_new0(SeafileSession, 1);
    session->seaf_dir = abs_seafile_dir;
    session->ccnet_dir = abs_ccnet_dir;
    session->tmp_file_dir = tmp_file_dir;
    session->config = config;
    session->excluded_users = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                     g_free, NULL);

    if (load_database_config (session) < 0) {
        seaf_warning ("Failed to load database config.\n");
        goto onerror;
    }

    if (load_ccnet_database_config (session) < 0) {
        seaf_warning ("Failed to load ccnet database config.\n");
        goto onerror;
    }

    if (read_excluded_users (session) < 0) {
        seaf_warning ("Failed to load excluded users.\n");
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
    session->user_mgr = ccnet_user_manager_new (session);
    if (!session->user_mgr)
        goto onerror;
    session->group_mgr = ccnet_group_manager_new (session);
    if (!session->group_mgr)
        goto onerror;

    return session;

onerror:
    free (abs_seafile_dir);
    free (abs_ccnet_dir);
    g_free (session);
    return NULL;    
}

static int
read_excluded_users (SeafileSession *session)
{
    char *users;
    int l, i;
    char *hash_value;

    users = seaf_key_file_get_string (session->config, "fuse", "excluded_users", NULL);
    if (!users)
        return 0;

    char **parts = g_strsplit_set(users, " ,", 0);
    l = g_strv_length(parts);
    if (l > 0)
        hash_value = g_new0(char, 1);

    for (i = 0; i < l; i++) {
        if (g_strcmp0(parts[i], "") == 0)
            continue;
        g_hash_table_insert (session->excluded_users, g_strdup(parts[i]), hash_value);
    }

    g_strfreev (parts);
    g_free (users);

    return 0;
}

int
seafile_session_init (SeafileSession *session)
{
    if (seaf_commit_manager_init (session->commit_mgr) < 0)
        return -1;

    if (seaf_fs_manager_init (session->fs_mgr) < 0)
        return -1;

    if (seaf_branch_manager_init (session->branch_mgr) < 0)
        return -1;

    if (seaf_repo_manager_init (session->repo_mgr) < 0)
        return -1;

    if (ccnet_user_manager_prepare (session->user_mgr) < 0) {
        seaf_warning ("Failed to init user manager.\n");
        return -1;
    }

    if (ccnet_group_manager_prepare (session->group_mgr) < 0) {
        seaf_warning ("Failed to init group manager.\n");
        return -1;
    }

    return 0;
}

int
seafile_session_start (SeafileSession *session)
{
    return 0;
}
