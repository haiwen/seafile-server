/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <glib/gstdio.h>

#include <openssl/sha.h>
#include <openssl/rand.h>

#include <timer.h>
#include "utils.h"
#include "log.h"

#include "seafile-session.h"
#include "commit-mgr.h"
#include "branch-mgr.h"
#include "repo-mgr.h"
#include "fs-mgr.h"
#include "seafile-error.h"
#include "seafile-crypt.h"
#include "password-hash.h"

#include "seaf-db.h"
#include "seaf-utils.h"

#define REAP_TOKEN_INTERVAL 300 /* 5 mins */
#define DECRYPTED_TOKEN_TTL 3600 /* 1 hour */
#define SCAN_TRASH_DAYS 1 /* one day */
#define TRASH_EXPIRE_DAYS 30 /* one month */

typedef struct DecryptedToken {
    char *token;
    gint64 reap_time;
} DecryptedToken;

struct _SeafRepoManagerPriv {
    /* (encrypted_token, session_key) -> decrypted token */
    GHashTable *decrypted_tokens;
    pthread_rwlock_t lock;
    CcnetTimer *reap_token_timer;

    CcnetTimer *scan_trash_timer;
};

static void
load_repo (SeafRepoManager *manager, SeafRepo *repo);

static int create_db_tables_if_not_exist (SeafRepoManager *mgr);

static int save_branch_repo_map (SeafRepoManager *manager, SeafBranch *branch);

static int reap_token (void *data);
static void decrypted_token_free (DecryptedToken *token);

gboolean
is_repo_id_valid (const char *id)
{
    if (!id)
        return FALSE;

    return is_uuid_valid (id);
}

SeafRepo*
seaf_repo_new (const char *id, const char *name, const char *desc)
{
    SeafRepo* repo;

    /* valid check */
  
    
    repo = g_new0 (SeafRepo, 1);
    memcpy (repo->id, id, 36);
    repo->id[36] = '\0';

    repo->name = g_strdup(name);
    repo->desc = g_strdup(desc);

    repo->ref_cnt = 1;

    return repo;
}

void
seaf_repo_free (SeafRepo *repo)
{
    if (repo->name) g_free (repo->name);
    if (repo->desc) g_free (repo->desc);
    if (repo->head) seaf_branch_unref (repo->head);
    if (repo->virtual_info)
        seaf_virtual_repo_info_free (repo->virtual_info);
    g_free (repo->last_modifier);
    g_free (repo->pwd_hash_algo);
    g_free (repo->pwd_hash_params);
    g_free (repo->type);
    g_free (repo);
}

void
seaf_repo_ref (SeafRepo *repo)
{
    g_atomic_int_inc (&repo->ref_cnt);
}

void
seaf_repo_unref (SeafRepo *repo)
{
    if (!repo)
        return;

    if (g_atomic_int_dec_and_test (&repo->ref_cnt))
        seaf_repo_free (repo);
}

static void
set_head_common (SeafRepo *repo, SeafBranch *branch)
{
    if (repo->head)
        seaf_branch_unref (repo->head);
    repo->head = branch;
    seaf_branch_ref(branch);
}

int
seaf_repo_set_head (SeafRepo *repo, SeafBranch *branch)
{
    if (save_branch_repo_map (repo->manager, branch) < 0)
        return -1;
    set_head_common (repo, branch);
    return 0;
}

void
seaf_repo_from_commit (SeafRepo *repo, SeafCommit *commit)
{
    repo->name = g_strdup (commit->repo_name);
    repo->desc = g_strdup (commit->repo_desc);
    repo->encrypted = commit->encrypted;
    repo->repaired = commit->repaired;
    repo->last_modify = commit->ctime;
    memcpy (repo->root_id, commit->root_id, 40);
    if (repo->encrypted) {
        repo->enc_version = commit->enc_version;
        if (repo->enc_version == 1 && !commit->pwd_hash_algo)
            memcpy (repo->magic, commit->magic, 32);
        else if (repo->enc_version == 2) {
            memcpy (repo->random_key, commit->random_key, 96);
        } else if (repo->enc_version == 3) {
            memcpy (repo->random_key, commit->random_key, 96);
            memcpy (repo->salt, commit->salt, 64);
        } else if (repo->enc_version == 4) {
            memcpy (repo->random_key, commit->random_key, 96);
            memcpy (repo->salt, commit->salt, 64);
        }
        if (repo->enc_version >= 2 && !commit->pwd_hash_algo) {
            memcpy (repo->magic, commit->magic, 64);
        }
        if (commit->pwd_hash_algo) {
            memcpy (repo->pwd_hash, commit->pwd_hash, 64);
            repo->pwd_hash_algo = g_strdup (commit->pwd_hash_algo);
            repo->pwd_hash_params = g_strdup (commit->pwd_hash_params);
        }
    }
    repo->no_local_history = commit->no_local_history;
    repo->version = commit->version;
    repo->last_modifier = g_strdup (commit->creator_name);
}

void
seaf_repo_to_commit (SeafRepo *repo, SeafCommit *commit)
{
    commit->repo_name = g_strdup (repo->name);
    commit->repo_desc = g_strdup (repo->desc);
    commit->encrypted = repo->encrypted;
    commit->repaired = repo->repaired;
    if (commit->encrypted) {
        commit->enc_version = repo->enc_version;
        if (commit->enc_version == 1 && !repo->pwd_hash_algo)
            commit->magic = g_strdup (repo->magic);
        else if (commit->enc_version == 2) {
            commit->random_key = g_strdup (repo->random_key);
        } else if (commit->enc_version == 3) {
            commit->random_key = g_strdup (repo->random_key);
            commit->salt = g_strdup (repo->salt);
        } else if (commit->enc_version == 4) {
            commit->random_key = g_strdup (repo->random_key);
            commit->salt = g_strdup (repo->salt);
        }
        if (commit->enc_version >= 2 && !repo->pwd_hash_algo) {
            commit->magic = g_strdup (repo->magic);
        }
        if (repo->pwd_hash_algo) {
            commit->pwd_hash = g_strdup (repo->pwd_hash);
            commit->pwd_hash_algo = g_strdup (repo->pwd_hash_algo);
            commit->pwd_hash_params = g_strdup (repo->pwd_hash_params);
        }
    }
    commit->no_local_history = repo->no_local_history;
    commit->version = repo->version;
}

static gboolean
collect_commit (SeafCommit *commit, void *vlist, gboolean *stop)
{
    GList **commits = vlist;

    /* The traverse function will unref the commit, so we need to ref it.
     */
    seaf_commit_ref (commit);
    *commits = g_list_prepend (*commits, commit);
    return TRUE;
}

GList *
seaf_repo_get_commits (SeafRepo *repo)
{
    GList *branches;
    GList *ptr;
    SeafBranch *branch;
    GList *commits = NULL;

    branches = seaf_branch_manager_get_branch_list (seaf->branch_mgr, repo->id);
    if (branches == NULL) {
        seaf_warning ("Failed to get branch list of repo %s.\n", repo->id);
        return NULL;
    }

    for (ptr = branches; ptr != NULL; ptr = ptr->next) {
        branch = ptr->data;
        gboolean res = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                                 repo->id,
                                                                 repo->version,
                                                                 branch->commit_id,
                                                                 collect_commit,
                                                                 &commits,
                                                                 FALSE);
        if (!res) {
            for (ptr = commits; ptr != NULL; ptr = ptr->next)
                seaf_commit_unref ((SeafCommit *)(ptr->data));
            g_list_free (commits);
            goto out;
        }
    }

    commits = g_list_reverse (commits);

out:
    for (ptr = branches; ptr != NULL; ptr = ptr->next) {
        seaf_branch_unref ((SeafBranch *)ptr->data);
    }
    return commits;
}

gboolean
should_ignore_file(const char *filename, void *data)
{
    /* GPatternSpec **spec = ignore_patterns; */

    char **components = g_strsplit (filename, "/", -1);
    int n_comps = g_strv_length (components);
    int j = 0;
    char *file_name;

    for (; j < n_comps; ++j) {
        file_name = components[j];
        if (g_strcmp0(file_name, "..") == 0) {
            g_strfreev (components);
            return TRUE;
        }
    }
    g_strfreev (components);

    if (!g_utf8_validate (filename, -1, NULL)) {
        seaf_warning ("File name %s contains non-UTF8 characters, skip.\n", filename);
        return TRUE;
    }

    /* Ignore file/dir if its name is too long. */
    if (strlen(filename) >= SEAF_DIR_NAME_LEN)
        return TRUE;

    if (strchr (filename, '/'))
        return TRUE;

    return FALSE;
}

static gboolean
collect_repo_id (SeafDBRow *row, void *data);

static int
scan_trash (void *data)
{
    GList *repo_ids = NULL;
    SeafRepoManager *mgr = seaf->repo_mgr;
    gint64 trash_expire_interval = TRASH_EXPIRE_DAYS * 24 * 3600;
    int expire_days = seaf_cfg_manager_get_config_int (seaf->cfg_mgr,
                                                       "library_trash",
                                                       "expire_days");
    if (expire_days > 0) {
        trash_expire_interval = expire_days * 24 * 3600;
    }

    gint64 expire_time = time(NULL) - trash_expire_interval;
    char *sql = "SELECT repo_id FROM RepoTrash WHERE del_time <= ?";

    int ret = seaf_db_statement_foreach_row (seaf->db, sql,
                                             collect_repo_id, &repo_ids,
                                             1, "int64", expire_time);
    if (ret < 0) {
        seaf_warning ("Get expired repo from trash failed.");
        string_list_free (repo_ids);
        return TRUE;
    }

    GList *iter;
    char *repo_id;
    for (iter=repo_ids; iter; iter=iter->next) {
        repo_id = iter->data;
        ret = seaf_repo_manager_del_repo_from_trash (mgr, repo_id, NULL);
        if (ret < 0)
            break;
    }

    string_list_free (repo_ids);

    return TRUE;
}

static void
init_scan_trash_timer (SeafRepoManagerPriv *priv, GKeyFile *config)
{
    int scan_days;
    GError *error = NULL;

    scan_days = g_key_file_get_integer (config,
                                        "library_trash", "scan_days",
                                        &error);
    if (error) {
       scan_days = SCAN_TRASH_DAYS;
       g_clear_error (&error);
    }

    priv->scan_trash_timer = ccnet_timer_new (scan_trash, NULL,
                                              scan_days * 24 * 3600 * 1000);
}

SeafRepoManager*
seaf_repo_manager_new (SeafileSession *seaf)
{
    SeafRepoManager *mgr = g_new0 (SeafRepoManager, 1);

    mgr->priv = g_new0 (SeafRepoManagerPriv, 1);
    mgr->seaf = seaf;

    mgr->priv->decrypted_tokens = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                         g_free,
                                                         (GDestroyNotify)decrypted_token_free);
    pthread_rwlock_init (&mgr->priv->lock, NULL);
    mgr->priv->reap_token_timer = ccnet_timer_new (reap_token, mgr,
                                                   REAP_TOKEN_INTERVAL * 1000);

    init_scan_trash_timer (mgr->priv, seaf->config);

    return mgr;
}

int
seaf_repo_manager_init (SeafRepoManager *mgr)
{
    /* On the server, we load repos into memory on-demand, because
     * there are too many repos.
     */
    if (create_db_tables_if_not_exist (mgr) < 0) {
        seaf_warning ("[repo mgr] failed to create tables.\n");
        return -1;
    }

    if (seaf_repo_manager_init_merge_scheduler() < 0) {
        seaf_warning ("Failed to init merge scheduler.\n");
        return -1;
    }

    return 0;
}

int
seaf_repo_manager_start (SeafRepoManager *mgr)
{
    return 0;
}

int
seaf_repo_manager_add_repo (SeafRepoManager *manager,
                            SeafRepo *repo)
{
    SeafDB *db = manager->seaf->db;

    if (seaf_db_statement_query (db, "INSERT INTO Repo (repo_id) VALUES (?)",
                                 1, "string", repo->id) < 0)
        return -1;

    repo->manager = manager;

    return 0;
}

static int
add_deleted_repo_record (SeafRepoManager *mgr, const char *repo_id)
{
    if (seaf_db_type(seaf->db) == SEAF_DB_TYPE_PGSQL) {
        gboolean exists, err;

        exists = seaf_db_statement_exists (seaf->db,
                                           "SELECT repo_id FROM GarbageRepos "
                                           "WHERE repo_id=?",
                                           &err, 1, "string", repo_id);
        if (err)
            return -1;

        if (!exists) {
            return seaf_db_statement_query(seaf->db,
                                           "INSERT INTO GarbageRepos (repo_id) VALUES (?)",
                                           1, "string", repo_id);
        }

        return 0;
    } else {
        return seaf_db_statement_query (seaf->db,
                                        "REPLACE INTO GarbageRepos (repo_id) VALUES (?)",
                                        1, "string", repo_id);
    }
}

static int
add_deleted_repo_to_trash (SeafRepoManager *mgr, const char *repo_id,
                           SeafCommit *commit)
{
    char *owner = NULL;
    int ret = -1;

    owner = seaf_repo_manager_get_repo_owner (mgr, repo_id);
    if (!owner) {
        seaf_warning ("Failed to get owner for repo %.8s.\n", repo_id);
        goto out;
    }

    gint64 size = seaf_repo_manager_get_repo_size (mgr, repo_id);
    if (size == -1) {
        seaf_warning ("Failed to get size of repo %.8s.\n", repo_id);
        goto out;
    }

    ret =  seaf_db_statement_query (mgr->seaf->db,
                                    "INSERT INTO RepoTrash (repo_id, repo_name, head_id, "
                                    "owner_id, size, org_id, del_time) "
                                    "values (?, ?, ?, ?, ?, -1, ?)", 6,
                                    "string", repo_id,
                                    "string", commit->repo_name,
                                    "string", commit->commit_id,
                                    "string", owner,
                                    "int64", size,
                                    "int64", (gint64)time(NULL));
out:
    g_free (owner);

    return ret;
}

static int
remove_virtual_repo_ondisk (SeafRepoManager *mgr,
                            const char *repo_id)
{
    SeafDB *db = mgr->seaf->db;

    /* Remove record in repo table first.
     * Once this is commited, we can gc the other tables later even if
     * we're interrupted.
     */
    if (seaf_db_statement_query (db, "DELETE FROM Repo WHERE repo_id = ?",
                                 1, "string", repo_id) < 0)
        return -1;

    /* remove branch */
    GList *p;
    GList *branch_list = 
        seaf_branch_manager_get_branch_list (seaf->branch_mgr, repo_id);
    for (p = branch_list; p; p = p->next) {
        SeafBranch *b = (SeafBranch *)p->data;
        seaf_repo_manager_branch_repo_unmap (mgr, b);
        seaf_branch_manager_del_branch (seaf->branch_mgr, repo_id, b->name);
    }
    seaf_branch_list_free (branch_list);

    seaf_db_statement_query (db, "DELETE FROM RepoOwner WHERE repo_id = ?",
                   1, "string", repo_id);

    seaf_db_statement_query (db, "DELETE FROM SharedRepo WHERE repo_id = ?",
                   1, "string", repo_id);

    seaf_db_statement_query (db, "DELETE FROM RepoGroup WHERE repo_id = ?",
                   1, "string", repo_id);

    if (!seaf->cloud_mode) {
        seaf_db_statement_query (db, "DELETE FROM InnerPubRepo WHERE repo_id = ?",
                                 1, "string", repo_id);
    }

    seaf_db_statement_query (mgr->seaf->db,
                             "DELETE FROM RepoUserToken WHERE repo_id = ?",
                             1, "string", repo_id);

    seaf_db_statement_query (mgr->seaf->db,
                             "DELETE FROM RepoValidSince WHERE repo_id = ?",
                             1, "string", repo_id);

    seaf_db_statement_query (mgr->seaf->db,
                             "DELETE FROM RepoSize WHERE repo_id = ?",
                             1, "string", repo_id);

    seaf_db_statement_query (mgr->seaf->db,
                             "DELETE FROM RepoInfo WHERE repo_id = ?",
                             1, "string", repo_id);

    /* For GC commit objects for this virtual repo. Fs and blocks are GC
     * from the parent repo.
     */
    add_deleted_repo_record (mgr, repo_id);

    return 0;
}

static gboolean
get_branch (SeafDBRow *row, void *vid)
{
    char *ret = vid;
    const char *commit_id;

    commit_id = seaf_db_row_get_column_text (row, 0);
    memcpy (ret, commit_id, 41);

    return FALSE;
}

static SeafCommit*
get_head_commit (SeafRepoManager *mgr, const char *repo_id, gboolean *has_err)
{
    char commit_id[41];
    char *sql;

    commit_id[0] = 0;
    sql = "SELECT commit_id FROM Branch WHERE name=? AND repo_id=?";
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                       get_branch, commit_id,
                                       2, "string", "master", "string", repo_id) < 0) {
        *has_err = TRUE;
        return NULL;
    }

    if (commit_id[0] == 0)
        return NULL;

    SeafCommit *head_commit = seaf_commit_manager_get_commit (seaf->commit_mgr, repo_id,
                                                              1, commit_id);

    return head_commit;
}

int
seaf_repo_manager_del_repo (SeafRepoManager *mgr,
                            const char *repo_id,
                            GError **error)
{
    gboolean has_err = FALSE;

    SeafCommit *head_commit = get_head_commit (mgr, repo_id, &has_err);
    if (has_err) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to get head commit from db");
        return -1;
    }
    if (!head_commit) {
        // head commit is missing, del repo directly
        goto del_repo;
    }

    if (add_deleted_repo_to_trash (mgr, repo_id, head_commit) < 0) {
        // Add repo to trash failed, del repo directly
        seaf_warning ("Failed to add repo %.8s to trash, delete directly.\n",
                      repo_id);
    }

    seaf_commit_unref (head_commit);

del_repo:
    if (seaf_db_statement_query (mgr->seaf->db, "DELETE FROM Repo WHERE repo_id = ?",
                                 1, "string", repo_id) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to delete repo from db");
        return -1;
    }

    /* remove branch */
    GList *p;
    GList *branch_list = seaf_branch_manager_get_branch_list (seaf->branch_mgr, repo_id);
    for (p = branch_list; p; p = p->next) {
        SeafBranch *b = (SeafBranch *)p->data;
        seaf_repo_manager_branch_repo_unmap (mgr, b);
        seaf_branch_manager_del_branch (seaf->branch_mgr, repo_id, b->name);
    }
    seaf_branch_list_free (branch_list);

    seaf_db_statement_query (mgr->seaf->db, "DELETE FROM RepoOwner WHERE repo_id = ?",
                             1, "string", repo_id);

    seaf_db_statement_query (mgr->seaf->db, "DELETE FROM SharedRepo WHERE repo_id = ?",
                             1, "string", repo_id);

    seaf_db_statement_query (mgr->seaf->db, "DELETE FROM RepoGroup WHERE repo_id = ?",
                             1, "string", repo_id);

    if (!seaf->cloud_mode) {
        seaf_db_statement_query (mgr->seaf->db, "DELETE FROM InnerPubRepo WHERE repo_id = ?",
                                 1, "string", repo_id);
    }

    seaf_db_statement_query (mgr->seaf->db,
                             "DELETE t.*, i.* FROM RepoUserToken t, "
                             "RepoTokenPeerInfo i WHERE t.token=i.token AND "
                             "t.repo_id=?",
                             1, "string", repo_id);

    seaf_db_statement_query (mgr->seaf->db,
                             "DELETE FROM RepoHistoryLimit WHERE repo_id = ?",
                             1, "string", repo_id);

    seaf_db_statement_query (mgr->seaf->db,
                             "DELETE FROM RepoValidSince WHERE repo_id = ?",
                             1, "string", repo_id);

    seaf_db_statement_query (mgr->seaf->db,
                             "DELETE FROM RepoSize WHERE repo_id = ?",
                             1, "string", repo_id);

    /* Remove virtual repos when origin repo is deleted. */
    GList *vrepos, *ptr;
    vrepos = seaf_repo_manager_get_virtual_repo_ids_by_origin (mgr, repo_id);
    for (ptr = vrepos; ptr != NULL; ptr = ptr->next)
        remove_virtual_repo_ondisk (mgr, (char *)ptr->data);
    string_list_free (vrepos);

    seaf_db_statement_query (mgr->seaf->db, "DELETE FROM RepoInfo "
                             "WHERE repo_id=?",
                             1, "string", repo_id);

    seaf_db_statement_query (mgr->seaf->db, "DELETE FROM VirtualRepo "
                             "WHERE repo_id=? OR origin_repo=?",
                             2, "string", repo_id, "string", repo_id);

    if (!head_commit)
        add_deleted_repo_record(mgr, repo_id);

    return 0;
}

int
seaf_repo_manager_del_virtual_repo (SeafRepoManager *mgr,
                                    const char *repo_id)
{
    int ret = remove_virtual_repo_ondisk (mgr, repo_id);

    if (ret < 0)
        return ret;

    return seaf_db_statement_query (mgr->seaf->db,
                                    "DELETE FROM VirtualRepo WHERE repo_id = ?",
                                    1, "string", repo_id);
}

static gboolean
repo_exists_in_db (SeafDB *db, const char *id, gboolean *db_err)
{
    return seaf_db_statement_exists (db,
                                     "SELECT repo_id FROM Repo WHERE repo_id = ?",
                                     db_err, 1, "string", id);
}

gboolean
create_repo_fill_size (SeafDBRow *row, void *data)
{
    SeafRepo **repo = data;
    SeafBranch *head;

    const char *repo_id = seaf_db_row_get_column_text (row, 0);
    gint64 size = seaf_db_row_get_column_int64 (row, 1);
    const char *commit_id = seaf_db_row_get_column_text (row, 2);
    const char *vrepo_id = seaf_db_row_get_column_text (row, 3);
    gint64 file_count = seaf_db_row_get_column_int64 (row, 7);
    int status = seaf_db_row_get_column_int(row, 8);
    const char *type = seaf_db_row_get_column_text (row, 9);

    *repo = seaf_repo_new (repo_id, NULL, NULL);
    if (!*repo)
        return FALSE;

    if (!commit_id) {
        (*repo)->is_corrupted = TRUE;
        return FALSE;
    }

    (*repo)->size = size;
    (*repo)->file_count = file_count;
    head = seaf_branch_new ("master", repo_id, commit_id);
    (*repo)->head = head;
    (*repo)->status = status;

    if (vrepo_id) {
        const char *origin_repo_id = seaf_db_row_get_column_text (row, 4);
        const char *origin_path = seaf_db_row_get_column_text (row, 5);
        const char *base_commit = seaf_db_row_get_column_text (row, 6);

        SeafVirtRepo *vinfo = g_new0 (SeafVirtRepo, 1);
        memcpy (vinfo->repo_id, vrepo_id, 36);
        memcpy (vinfo->origin_repo_id, origin_repo_id, 36);
        vinfo->path = g_strdup(origin_path);
        memcpy (vinfo->base_commit, base_commit, 40);

        (*repo)->virtual_info = vinfo;
        memcpy ((*repo)->store_id, origin_repo_id, 36);
    } else {
        memcpy ((*repo)->store_id, repo_id, 36);
    }
    if (type) {
        (*repo)->type = g_strdup(type);
    }

    return TRUE;
}

static SeafRepo*
get_repo_from_db (SeafRepoManager *mgr, const char *id, gboolean *db_err)
{
    SeafRepo *repo = NULL;
    const char *sql;

    if (seaf_db_type(mgr->seaf->db) != SEAF_DB_TYPE_PGSQL)
        sql = "SELECT r.repo_id, s.size, b.commit_id, "
            "v.repo_id, v.origin_repo, v.path, v.base_commit, fc.file_count, i.status, i.type FROM "
            "Repo r LEFT JOIN Branch b ON r.repo_id = b.repo_id "
            "LEFT JOIN RepoSize s ON r.repo_id = s.repo_id "
            "LEFT JOIN VirtualRepo v ON r.repo_id = v.repo_id "
            "LEFT JOIN RepoFileCount fc ON r.repo_id = fc.repo_id "
            "LEFT JOIN RepoInfo i on r.repo_id = i.repo_id "
            "WHERE r.repo_id = ? AND b.name = 'master'";
    else
        sql = "SELECT r.repo_id, s.\"size\", b.commit_id, "
            "v.repo_id, v.origin_repo, v.path, v.base_commit, fc.file_count, i.status FROM "
            "Repo r LEFT JOIN Branch b ON r.repo_id = b.repo_id "
            "LEFT JOIN RepoSize s ON r.repo_id = s.repo_id "
            "LEFT JOIN VirtualRepo v ON r.repo_id = v.repo_id "
            "LEFT JOIN RepoFileCount fc ON r.repo_id = fc.repo_id "
            "LEFT JOIN RepoInfo i on r.repo_id = i.repo_id "
            "WHERE r.repo_id = ? AND b.name = 'master'";

    int ret = seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                             create_repo_fill_size, &repo,
                                             1, "string", id);
    if (ret < 0)
        *db_err = TRUE;

    return repo;
}

SeafRepo*
seaf_repo_manager_get_repo (SeafRepoManager *manager, const gchar *id)
{
    int len = strlen(id);
    SeafRepo *repo = NULL;
    gboolean has_err = FALSE;

    if (len >= 37)
        return NULL;

    repo = get_repo_from_db (manager, id, &has_err);

    if (repo) {
        if (repo->is_corrupted) {
            seaf_repo_unref (repo);
            return NULL;
        }

        load_repo (manager, repo);
        if (repo->is_corrupted) {
            seaf_repo_unref (repo);
            return NULL;
        }
    }

    return repo;
}

SeafRepo*
seaf_repo_manager_get_repo_ex (SeafRepoManager *manager, const gchar *id)
{
    int len = strlen(id);
    gboolean has_err = FALSE;
    SeafRepo *ret = NULL;

    if (len >= 37)
        return NULL;

    ret = get_repo_from_db (manager, id, &has_err);
    if (has_err) {
        ret = seaf_repo_new(id, NULL, NULL);
        ret->is_corrupted = TRUE;
        return ret;
    }

    if (ret) {
        if (ret->is_corrupted) {
            return ret;
        }

        load_repo (manager, ret);
    }

    return ret;
}

gboolean
seaf_repo_manager_repo_exists (SeafRepoManager *manager, const gchar *id)
{
    gboolean db_err = FALSE;
    return repo_exists_in_db (manager->seaf->db, id, &db_err);
}

static int
save_branch_repo_map (SeafRepoManager *manager, SeafBranch *branch)
{
    if (seaf_db_type(seaf->db) == SEAF_DB_TYPE_PGSQL) {
        gboolean exists, err;
        int rc;

        exists = seaf_db_statement_exists (seaf->db,
                                           "SELECT repo_id FROM RepoHead WHERE repo_id=?",
                                           &err, 1, "string", branch->repo_id);
        if (err)
            return -1;

        if (exists)
            rc = seaf_db_statement_query (seaf->db,
                                          "UPDATE RepoHead SET branch_name=? "
                                          "WHERE repo_id=?",
                                          2, "string", branch->name,
                                          "string", branch->repo_id);
        else
            rc = seaf_db_statement_query (seaf->db,
                                          "INSERT INTO RepoHead (repo_id, branch_name) VALUES (?, ?)",
                                          2, "string", branch->repo_id,
                                          "string", branch->name);
        return rc;
    } else {
        return seaf_db_statement_query (seaf->db,
                                        "REPLACE INTO RepoHead (repo_id, branch_name) VALUES (?, ?)",
                                        2, "string", branch->repo_id,
                                        "string", branch->name);
    }

    return -1;
}

int
seaf_repo_manager_branch_repo_unmap (SeafRepoManager *manager, SeafBranch *branch)
{
    return seaf_db_statement_query (seaf->db,
                                    "DELETE FROM RepoHead WHERE branch_name = ?"
                                    " AND repo_id = ?",
                                    2, "string", branch->name,
                                    "string", branch->repo_id);
}

int
set_repo_commit_to_db (const char *repo_id, const char *repo_name, gint64 update_time,
                       int version, gboolean is_encrypted, const char *last_modifier)
{
    char *sql;
    gboolean exists = FALSE, db_err = FALSE;

    sql = "SELECT 1 FROM RepoInfo WHERE repo_id=?";
    exists = seaf_db_statement_exists (seaf->db, sql, &db_err, 1, "string", repo_id);
    if (db_err)
        return -1;

    if (update_time == 0)
        update_time = (gint64)time(NULL);

    if (exists) {
        sql = "UPDATE RepoInfo SET name=?, update_time=?, version=?, is_encrypted=?, "
            "last_modifier=? WHERE repo_id=?";
        if (seaf_db_statement_query (seaf->db, sql, 6,
                                     "string", repo_name,
                                     "int64", update_time,
                                     "int", version,
                                     "int", (is_encrypted ? 1:0),
                                     "string", last_modifier,
                                     "string", repo_id) < 0) {
            seaf_warning ("Failed to update repo info for repo %s.\n", repo_id);
            return -1;
        }    
    } else {
        sql = "INSERT INTO RepoInfo (repo_id, name, update_time, version, is_encrypted, last_modifier) "
            "VALUES (?, ?, ?, ?, ?, ?)";
        if (seaf_db_statement_query (seaf->db, sql, 6,
                                     "string", repo_id,
                                     "string", repo_name,
                                     "int64", update_time,
                                     "int", version,
                                     "int", (is_encrypted ? 1:0),
                                     "string", last_modifier) < 0) {
            seaf_warning ("Failed to add repo info for repo %s.\n", repo_id);
            return -1;
        }
    }

    return 0;
}

static void
load_repo_commit (SeafRepoManager *manager,
                  SeafRepo *repo)
{
    SeafCommit *commit;

    commit = seaf_commit_manager_get_commit_compatible (manager->seaf->commit_mgr,
                                                        repo->id,
                                                        repo->head->commit_id);
    if (!commit) {
        seaf_warning ("Commit %s:%s is missing\n", repo->id, repo->head->commit_id);
        repo->is_corrupted = TRUE;
        return;
    }

    seaf_repo_from_commit (repo, commit);

    seaf_commit_unref (commit);
}

static void
load_repo (SeafRepoManager *manager, SeafRepo *repo)
{
    repo->manager = manager;

    load_repo_commit (manager, repo);
}

static void
load_mini_repo (SeafRepoManager *manager, SeafRepo *repo)
{
    repo->manager = manager;
    SeafCommit *commit;

    commit = seaf_commit_manager_get_commit_compatible (manager->seaf->commit_mgr,
                                                        repo->id,
                                                        repo->head->commit_id);
    if (!commit) {
        seaf_warning ("Commit %s:%s is missing\n", repo->id, repo->head->commit_id);
        repo->is_corrupted = TRUE;
        return;
    }

    repo->name = g_strdup (commit->repo_name);
    repo->encrypted = commit->encrypted;
    repo->last_modify = commit->ctime;
    repo->version = commit->version;
    repo->last_modifier = g_strdup (commit->creator_name);

    seaf_commit_unref (commit);
}

static int
create_tables_mysql (SeafRepoManager *mgr)
{
    SeafDB *db = mgr->seaf->db;
    char *sql;

    sql = "CREATE TABLE IF NOT EXISTS Repo (id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
          "repo_id CHAR(37), UNIQUE INDEX (repo_id))"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoOwner ("
        "id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
        "repo_id CHAR(37), "
        "owner_id VARCHAR(255),"
        "UNIQUE INDEX (repo_id), INDEX (owner_id))"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoGroup (id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT,"
        "repo_id CHAR(37), "
        "group_id INTEGER, user_name VARCHAR(255), permission CHAR(15), "
        "UNIQUE INDEX (group_id, repo_id), "
        "INDEX (repo_id), INDEX (user_name))"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS InnerPubRepo ("
        "id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
        "repo_id CHAR(37),"
        "permission CHAR(15), UNIQUE INDEX (repo_id))"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoUserToken ("
        "id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
        "repo_id CHAR(37), "
        "email VARCHAR(255), "
        "token CHAR(41), "
        "UNIQUE INDEX(repo_id, token), INDEX(token), INDEX (email))"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoTokenPeerInfo ("
        "id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
        "token CHAR(41), "
        "peer_id CHAR(41), "
        "peer_ip VARCHAR(50), "
        "peer_name VARCHAR(255), "
        "sync_time BIGINT, "
        "client_ver VARCHAR(20), UNIQUE INDEX(token), INDEX(peer_id))"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoHead ("
        "id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
        "repo_id CHAR(37), branch_name VARCHAR(10), UNIQUE INDEX(repo_id))"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoSize ("
        "id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
        "repo_id CHAR(37),"
        "size BIGINT UNSIGNED,"
        "head_id CHAR(41), UNIQUE INDEX (repo_id))"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoHistoryLimit ("
        "id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
        "repo_id CHAR(37), days INTEGER, UNIQUE INDEX(repo_id))"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoValidSince ("
        "id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
        "repo_id CHAR(37), timestamp BIGINT, UNIQUE INDEX(repo_id))"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS WebAP (id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
        "repo_id CHAR(37), "
        "access_property CHAR(10), UNIQUE INDEX(repo_id))"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS VirtualRepo (id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
        "repo_id CHAR(36),"
        "origin_repo CHAR(36), path TEXT, base_commit CHAR(40), UNIQUE INDEX(repo_id), INDEX(origin_repo))"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS GarbageRepos (id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
          "repo_id CHAR(36), UNIQUE INDEX(repo_id))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    /* Tables for online GC */

    sql = "CREATE TABLE IF NOT EXISTS GCID (id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
          "repo_id CHAR(36), gc_id CHAR(36), UNIQUE INDEX(repo_id)) ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS LastGCID (id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
          "repo_id CHAR(36), client_id VARCHAR(128), gc_id CHAR(36), UNIQUE INDEX(repo_id, client_id)) ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoTrash (id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
        "repo_id CHAR(36),"
        "repo_name VARCHAR(255), head_id CHAR(40), owner_id VARCHAR(255),"
        "size BIGINT(20), org_id INTEGER, del_time BIGINT, "
        "UNIQUE INDEX(repo_id), INDEX(owner_id), INDEX(org_id))ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoFileCount ("
        "id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
        "repo_id CHAR(36),"
        "file_count BIGINT UNSIGNED, UNIQUE INDEX(repo_id))ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoInfo (id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
        "repo_id CHAR(36), "
        "name VARCHAR(255) NOT NULL, update_time BIGINT, version INTEGER, "
        "is_encrypted INTEGER, last_modifier VARCHAR(255), status INTEGER DEFAULT 0, type VARCHAR(10), "
        "UNIQUE INDEX(repo_id), INDEX(type)) ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS WebUploadTempFiles ( "
        "id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, repo_id CHAR(40) NOT NULL, "
        "file_path TEXT NOT NULL, tmp_file_path TEXT NOT NULL, INDEX(repo_id)) ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    return 0;
}

static int
create_tables_sqlite (SeafRepoManager *mgr)
{
    SeafDB *db = mgr->seaf->db;
    char *sql;

    sql = "CREATE TABLE IF NOT EXISTS Repo (repo_id CHAR(37) PRIMARY KEY)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    /* Owner */

    sql = "CREATE TABLE IF NOT EXISTS RepoOwner ("
        "repo_id CHAR(37) PRIMARY KEY, "
        "owner_id TEXT)";
    if (seaf_db_query (db, sql) < 0)
        return -1;
    sql = "CREATE INDEX IF NOT EXISTS OwnerIndex ON RepoOwner (owner_id)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    /* Group repo */

    sql = "CREATE TABLE IF NOT EXISTS RepoGroup (repo_id CHAR(37), "
        "group_id INTEGER, user_name TEXT, permission CHAR(15))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE UNIQUE INDEX IF NOT EXISTS groupid_repoid_indx on "
        "RepoGroup (group_id, repo_id)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE INDEX IF NOT EXISTS repogroup_repoid_index on "
        "RepoGroup (repo_id)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE INDEX IF NOT EXISTS repogroup_username_indx on "
        "RepoGroup (user_name)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    /* Public repo */

    sql = "CREATE TABLE IF NOT EXISTS InnerPubRepo ("
        "repo_id CHAR(37) PRIMARY KEY,"
        "permission CHAR(15))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoUserToken ("
        "repo_id CHAR(37), "
        "email VARCHAR(255), "
        "token CHAR(41))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE UNIQUE INDEX IF NOT EXISTS repo_token_indx on "
        "RepoUserToken (repo_id, token)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE INDEX IF NOT EXISTS repo_token_email_indx on "
        "RepoUserToken (email)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoTokenPeerInfo ("
        "token CHAR(41) PRIMARY KEY, "
        "peer_id CHAR(41), "
        "peer_ip VARCHAR(50), "
        "peer_name VARCHAR(255), "
        "sync_time BIGINT, "
        "client_ver VARCHAR(20))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoHead ("
        "repo_id CHAR(37) PRIMARY KEY, branch_name VARCHAR(10))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoSize ("
        "repo_id CHAR(37) PRIMARY KEY,"
        "size BIGINT UNSIGNED,"
        "head_id CHAR(41))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoHistoryLimit ("
        "repo_id CHAR(37) PRIMARY KEY, days INTEGER)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoValidSince ("
        "repo_id CHAR(37) PRIMARY KEY, timestamp BIGINT)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS WebAP (repo_id CHAR(37) PRIMARY KEY, "
        "access_property CHAR(10))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS VirtualRepo (repo_id CHAR(36) PRIMARY KEY,"
        "origin_repo CHAR(36), path TEXT, base_commit CHAR(40))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE INDEX IF NOT EXISTS virtualrepo_origin_repo_idx "
        "ON VirtualRepo (origin_repo)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS GarbageRepos (repo_id CHAR(36) PRIMARY KEY)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoTrash (repo_id CHAR(36) PRIMARY KEY,"
        "repo_name VARCHAR(255), head_id CHAR(40), owner_id VARCHAR(255), size BIGINT UNSIGNED,"
        "org_id INTEGER, del_time BIGINT)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE INDEX IF NOT EXISTS repotrash_owner_id_idx ON RepoTrash(owner_id)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE INDEX IF NOT EXISTS repotrash_org_id_idx ON RepoTrash(org_id)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoFileCount ("
        "repo_id CHAR(36) PRIMARY KEY,"
        "file_count BIGINT UNSIGNED)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoInfo (repo_id CHAR(36) PRIMARY KEY, "
        "name VARCHAR(255) NOT NULL, update_time INTEGER, version INTEGER, "
        "is_encrypted INTEGER, last_modifier VARCHAR(255), status INTEGER DEFAULT 0)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS WebUploadTempFiles (repo_id CHAR(40) NOT NULL, "
        "file_path TEXT NOT NULL, tmp_file_path TEXT NOT NULL)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE INDEX IF NOT EXISTS webuploadtempfiles_repo_id_idx ON WebUploadTempFiles(repo_id)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    return 0;
}

/* static int */
/* create_tables_pgsql (SeafRepoManager *mgr) */
/* { */
/*     SeafDB *db = mgr->seaf->db; */
/*     char *sql; */

/*     sql = "CREATE TABLE IF NOT EXISTS Repo (repo_id CHAR(36) PRIMARY KEY)"; */
/*     if (seaf_db_query (db, sql) < 0) */
/*         return -1; */

/*     sql = "CREATE TABLE IF NOT EXISTS RepoOwner (" */
/*         "repo_id CHAR(36) PRIMARY KEY, " */
/*         "owner_id VARCHAR(255))"; */
/*     if (seaf_db_query (db, sql) < 0) */
/*         return -1; */

/*     if (!pgsql_index_exists (db, "repoowner_owner_idx")) { */
/*         sql = "CREATE INDEX repoowner_owner_idx ON RepoOwner (owner_id)"; */
/*         if (seaf_db_query (db, sql) < 0) */
/*             return -1; */
/*     } */

/*     sql = "CREATE TABLE IF NOT EXISTS RepoGroup (repo_id CHAR(36), " */
/*         "group_id INTEGER, user_name VARCHAR(255), permission VARCHAR(15), " */
/*         "UNIQUE (group_id, repo_id))"; */
/*     if (seaf_db_query (db, sql) < 0) */
/*         return -1; */

/*     if (!pgsql_index_exists (db, "repogroup_repoid_idx")) { */
/*         sql = "CREATE INDEX repogroup_repoid_idx ON RepoGroup (repo_id)"; */
/*         if (seaf_db_query (db, sql) < 0) */
/*             return -1; */
/*     } */

/*     if (!pgsql_index_exists (db, "repogroup_username_idx")) { */
/*         sql = "CREATE INDEX repogroup_username_idx ON RepoGroup (user_name)"; */
/*         if (seaf_db_query (db, sql) < 0) */
/*             return -1; */
/*     } */

/*     sql = "CREATE TABLE IF NOT EXISTS InnerPubRepo (" */
/*         "repo_id CHAR(36) PRIMARY KEY," */
/*         "permission VARCHAR(15))"; */
/*     if (seaf_db_query (db, sql) < 0) */
/*         return -1; */

/*     sql = "CREATE TABLE IF NOT EXISTS RepoUserToken (" */
/*         "repo_id CHAR(36), " */
/*         "email VARCHAR(255), " */
/*         "token CHAR(40), " */
/*         "UNIQUE (repo_id, token))"; */
/*     if (seaf_db_query (db, sql) < 0) */
/*         return -1; */

/*     if (!pgsql_index_exists (db, "repousertoken_email_idx")) { */
/*         sql = "CREATE INDEX repousertoken_email_idx ON RepoUserToken (email)"; */
/*         if (seaf_db_query (db, sql) < 0) */
/*             return -1; */
/*     } */

/*     sql = "CREATE TABLE IF NOT EXISTS RepoTokenPeerInfo (" */
/*         "token CHAR(40) PRIMARY KEY, " */
/*         "peer_id CHAR(40), " */
/*         "peer_ip VARCHAR(40), " */
/*         "peer_name VARCHAR(255), " */
/*         "sync_time BIGINT, " */
/*         "client_ver VARCHAR(20))"; */
/*     if (seaf_db_query (db, sql) < 0) */
/*         return -1; */

/*     sql = "CREATE TABLE IF NOT EXISTS RepoHead (" */
/*         "repo_id CHAR(36) PRIMARY KEY, branch_name VARCHAR(10))"; */
/*     if (seaf_db_query (db, sql) < 0) */
/*         return -1; */

/*     sql = "CREATE TABLE IF NOT EXISTS RepoSize (" */
/*         "repo_id CHAR(36) PRIMARY KEY," */
/*         "size BIGINT," */
/*         "head_id CHAR(40))"; */
/*     if (seaf_db_query (db, sql) < 0) */
/*         return -1; */

/*     sql = "CREATE TABLE IF NOT EXISTS RepoHistoryLimit (" */
/*         "repo_id CHAR(36) PRIMARY KEY, days INTEGER)"; */
/*     if (seaf_db_query (db, sql) < 0) */
/*         return -1; */

/*     sql = "CREATE TABLE IF NOT EXISTS RepoValidSince (" */
/*         "repo_id CHAR(36) PRIMARY KEY, timestamp BIGINT)"; */
/*     if (seaf_db_query (db, sql) < 0) */
/*         return -1; */

/*     sql = "CREATE TABLE IF NOT EXISTS WebAP (repo_id CHAR(36) PRIMARY KEY, " */
/*         "access_property VARCHAR(10))"; */
/*     if (seaf_db_query (db, sql) < 0) */
/*         return -1; */

/*     sql = "CREATE TABLE IF NOT EXISTS VirtualRepo (repo_id CHAR(36) PRIMARY KEY," */
/*         "origin_repo CHAR(36), path TEXT, base_commit CHAR(40))"; */
/*     if (seaf_db_query (db, sql) < 0) */
/*         return -1; */

/*     if (!pgsql_index_exists (db, "virtualrepo_origin_repo_idx")) { */
/*         sql = "CREATE INDEX virtualrepo_origin_repo_idx ON VirtualRepo (origin_repo)"; */
/*         if (seaf_db_query (db, sql) < 0) */
/*             return -1; */
/*     } */

/*     sql = "CREATE TABLE IF NOT EXISTS GarbageRepos (repo_id CHAR(36) PRIMARY KEY)"; */
/*     if (seaf_db_query (db, sql) < 0) */
/*         return -1; */

/*     sql = "CREATE TABLE IF NOT EXISTS RepoTrash (repo_id CHAR(36) PRIMARY KEY," */
/*         "repo_name VARCHAR(255), head_id CHAR(40), owner_id VARCHAR(255), size bigint," */
/*         "org_id INTEGER, del_time BIGINT)"; */
/*     if (seaf_db_query (db, sql) < 0) */
/*         return -1; */

/*     if (!pgsql_index_exists (db, "repotrash_owner_id")) { */
/*         sql = "CREATE INDEX repotrash_owner_id on RepoTrash(owner_id)"; */
/*         if (seaf_db_query (db, sql) < 0) */
/*             return -1; */
/*     } */
/*     if (!pgsql_index_exists (db, "repotrash_org_id")) { */
/*         sql = "CREATE INDEX repotrash_org_id on RepoTrash(org_id)"; */
/*         if (seaf_db_query (db, sql) < 0) */
/*             return -1; */
/*     } */

/*     sql = "CREATE TABLE IF NOT EXISTS RepoFileCount (" */
/*         "repo_id CHAR(36) PRIMARY KEY," */
/*         "file_count BIGINT)"; */
/*     if (seaf_db_query (db, sql) < 0) */
/*         return -1; */

/*     sql = "CREATE TABLE IF NOT EXISTS WebUploadTempFiles (repo_id CHAR(40) NOT NULL, " */
/*         "file_path TEXT NOT NULL, tmp_file_path TEXT NOT NULL)"; */
/*     if (seaf_db_query (db, sql) < 0) */
/*         return -1; */

/*     sql = "CREATE TABLE IF NOT EXISTS RepoInfo (repo_id CHAR(36) PRIMARY KEY, " */
/*         "name VARCHAR(255) NOT NULL, update_time BIGINT, version INTEGER, " */
/*         "is_encrypted INTEGER, last_modifier VARCHAR(255), status INTEGER DEFAULT 0)"; */
/*     if (seaf_db_query (db, sql) < 0) */
/*         return -1; */

/*     return 0; */
/* } */

static int
create_db_tables_if_not_exist (SeafRepoManager *mgr)
{
    if (!mgr->seaf->create_tables && seaf_db_type (mgr->seaf->db) != SEAF_DB_TYPE_PGSQL)
        return 0;

    SeafDB *db = mgr->seaf->db;
    int db_type = seaf_db_type (db);

    if (db_type == SEAF_DB_TYPE_MYSQL)
        return create_tables_mysql (mgr);
    else if (db_type == SEAF_DB_TYPE_SQLITE)
        return create_tables_sqlite (mgr);
    /* else if (db_type == SEAF_DB_TYPE_PGSQL) */
    /*     return create_tables_pgsql (mgr); */

    g_return_val_if_reached (-1);
}

/*
 * Repo properties functions.
 */

static inline char *
generate_repo_token ()
{
    char *uuid = gen_uuid ();
    unsigned char sha1[20];
    char token[41];
    SHA_CTX s;

    SHA1_Init (&s);
    SHA1_Update (&s, uuid, strlen(uuid));
    SHA1_Final (sha1, &s);

    rawdata_to_hex (sha1, token, 20);

    g_free (uuid);

    return g_strdup (token);
}

static int
add_repo_token (SeafRepoManager *mgr,
                const char *repo_id,
                const char *email,
                const char *token,
                GError **error)
{
    int rc = seaf_db_statement_query (mgr->seaf->db,
                                      "INSERT INTO RepoUserToken (repo_id, email, token) VALUES (?, ?, ?)",
                                      3, "string", repo_id, "string", email,
                                      "string", token);

    if (rc < 0) {
        seaf_warning ("failed to add repo token. repo = %s, email = %s\n",
                      repo_id, email);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "DB error");
        return -1;
    }

    return 0;
}

char *
seaf_repo_manager_generate_repo_token (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       const char *email,
                                       GError **error)
{
    char *token = generate_repo_token ();
    if (add_repo_token (mgr, repo_id, email, token, error) < 0) {
        g_free (token);        
        return NULL;
    }

    return token;
}

int
seaf_repo_manager_add_token_peer_info (SeafRepoManager *mgr,
                                       const char *token,
                                       const char *peer_id,
                                       const char *peer_ip,
                                       const char *peer_name,
                                       gint64 sync_time,
                                       const char *client_ver)
{
    int ret = 0;

    if (seaf_db_statement_query (mgr->seaf->db,
                                 "INSERT INTO RepoTokenPeerInfo (token, peer_id, peer_ip, peer_name, sync_time, client_ver)"
                                 "VALUES (?, ?, ?, ?, ?, ?)",
                                 6, "string", token,
                                 "string", peer_id,
                                 "string", peer_ip,
                                 "string", peer_name,
                                 "int64", sync_time,
                                 "string", client_ver) < 0)
        ret = -1;

    return ret;
}

int
seaf_repo_manager_update_token_peer_info (SeafRepoManager *mgr,
                                          const char *token,
                                          const char *peer_ip,
                                          gint64 sync_time,
                                          const char *client_ver)
{
    int ret = 0;

    if (seaf_db_statement_query (mgr->seaf->db,
                                 "UPDATE RepoTokenPeerInfo SET "
                                 "peer_ip=?, sync_time=?, client_ver=? WHERE token=?",
                                 4, "string", peer_ip,
                                 "int64", sync_time,
                                 "string", client_ver,
                                 "string", token) < 0)
        ret = -1;

    return ret;
}

gboolean
seaf_repo_manager_token_peer_info_exists (SeafRepoManager *mgr,
                                          const char *token)
{
    gboolean db_error = FALSE;

    return seaf_db_statement_exists (mgr->seaf->db,
                                     "SELECT token FROM RepoTokenPeerInfo WHERE token=?",
                                     &db_error, 1, "string", token);
}

int
seaf_repo_manager_delete_token (SeafRepoManager *mgr,
                                const char *repo_id,
                                const char *token,
                                const char *user,
                                GError **error)
{
    char *token_owner;

    token_owner = seaf_repo_manager_get_email_by_token (mgr, repo_id, token);
    if (!token_owner || strcmp (user, token_owner) != 0) {
        seaf_warning ("Requesting user is %s, token owner is %s, "
                      "refuse to delete token %.10s.\n", user, token_owner, token);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Permission denied");
        return -1;
    }

    if (seaf_db_statement_query (mgr->seaf->db,
                                 "DELETE t.*, i.* FROM RepoUserToken t, "
                                 "RepoTokenPeerInfo i WHERE t.token=i.token AND "
                                 "t.token=?",
                                 1, "string", token) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "DB error");
        return -1;
    }

    GList *tokens = NULL;
    tokens = g_list_append (tokens, g_strdup(token));
#ifdef HAVE_EVHTP
    seaf_http_server_invalidate_tokens (seaf->http_server, tokens);
#endif
    g_list_free_full (tokens, (GDestroyNotify)g_free);

    return 0;
}

static gboolean
collect_repo_token (SeafDBRow *row, void *data)
{
    GList **ret_list = data;
    const char *repo_id, *repo_owner, *email, *token;
    const char *peer_id, *peer_ip, *peer_name;
    gint64 sync_time;
    const char *client_ver;

    repo_id = seaf_db_row_get_column_text (row, 0);
    repo_owner = seaf_db_row_get_column_text (row, 1);
    email = seaf_db_row_get_column_text (row, 2);
    token = seaf_db_row_get_column_text (row, 3);

    peer_id = seaf_db_row_get_column_text (row, 4);
    peer_ip = seaf_db_row_get_column_text (row, 5);
    peer_name = seaf_db_row_get_column_text (row, 6);
    sync_time = seaf_db_row_get_column_int64 (row, 7);
    client_ver = seaf_db_row_get_column_text (row, 8);

    char *owner_l = g_ascii_strdown (repo_owner, -1);
    char *email_l = g_ascii_strdown (email, -1);

    SeafileRepoTokenInfo *repo_token_info;
    repo_token_info = g_object_new (SEAFILE_TYPE_REPO_TOKEN_INFO,
                                    "repo_id", repo_id,
                                    "repo_owner", owner_l,
                                    "email", email_l,
                                    "token", token,
                                    "peer_id", peer_id,
                                    "peer_ip", peer_ip,
                                    "peer_name", peer_name,
                                    "sync_time", sync_time,
                                    "client_ver", client_ver,
                                    NULL);

    *ret_list = g_list_prepend (*ret_list, repo_token_info);

    g_free (owner_l);
    g_free (email_l);

    return TRUE;
}

static void
fill_in_token_info (GList *info_list)
{
    GList *ptr;
    SeafileRepoTokenInfo *info;
    SeafRepo *repo;
    char *repo_name;

    for (ptr = info_list; ptr; ptr = ptr->next) {
        info = ptr->data;
        repo = seaf_repo_manager_get_repo (seaf->repo_mgr,
                                           seafile_repo_token_info_get_repo_id(info));
        if (repo)
            repo_name = g_strdup(repo->name);
        else
            repo_name = g_strdup("Unknown");
        seaf_repo_unref (repo);

        g_object_set (info, "repo_name", repo_name, NULL);
        g_free (repo_name);
    }
}

GList *
seaf_repo_manager_list_repo_tokens (SeafRepoManager *mgr,
                                    const char *repo_id,
                                    GError **error)
{
    GList *ret_list = NULL;
    char *sql;
    gboolean db_err = FALSE;

    if (!repo_exists_in_db (mgr->seaf->db, repo_id, &db_err)) {
        if (db_err) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "DB error");
        }
        return NULL;
    }

    sql = "SELECT u.repo_id, o.owner_id, u.email, u.token, "
        "p.peer_id, p.peer_ip, p.peer_name, p.sync_time, p.client_ver "
        "FROM RepoUserToken u LEFT JOIN RepoTokenPeerInfo p "
        "ON u.token = p.token, RepoOwner o "
        "WHERE u.repo_id = ? and o.repo_id = ? ";

    int n_row = seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                              collect_repo_token, &ret_list,
                                              2, "string", repo_id,
                                              "string", repo_id);
    if (n_row < 0) {
        seaf_warning ("DB error when get token info for repo %.10s.\n",
                      repo_id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "DB error");
    }

    fill_in_token_info (ret_list);

    return g_list_reverse(ret_list);
}

GList *
seaf_repo_manager_list_repo_tokens_by_email (SeafRepoManager *mgr,
                                             const char *email,
                                             GError **error)
{
    GList *ret_list = NULL;
    char *sql;

    sql = "SELECT u.repo_id, o.owner_id, u.email, u.token, "
        "p.peer_id, p.peer_ip, p.peer_name, p.sync_time, p.client_ver "
        "FROM RepoUserToken u LEFT JOIN RepoTokenPeerInfo p "
        "ON u.token = p.token, RepoOwner o "
        "WHERE u.email = ? and u.repo_id = o.repo_id";

    int n_row = seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                              collect_repo_token, &ret_list,
                                              1, "string", email);
    if (n_row < 0) {
        seaf_warning ("DB error when get token info for email %s.\n",
                      email);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "DB error");
    }

    fill_in_token_info (ret_list);

    return g_list_reverse(ret_list);
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

/**
 * Delete all repo tokens for a given user on a given client
 */

int
seaf_repo_manager_delete_repo_tokens_by_peer_id (SeafRepoManager *mgr,
                                                 const char *email,
                                                 const char *peer_id,
                                                 GList **tokens,
                                                 GError **error)
{
    int ret = 0;
    const char *template;
    GList *token_list = NULL;
    int rc = 0;
    int db_type = seaf_db_type (mgr->seaf->db);

    template = "SELECT u.token "
        "FROM RepoUserToken u, RepoTokenPeerInfo p "
        "WHERE u.token = p.token "
        "AND u.email = ? AND p.peer_id = ?";
    rc = seaf_db_statement_foreach_row (mgr->seaf->db, template,
                                        collect_token_list, &token_list,
                                        2, "string", email, "string", peer_id);
    if (rc < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "DB error");
        goto out;
    }

    if (rc == 0)
        goto out;

    if (db_type == SEAF_DB_TYPE_MYSQL) {
        rc = seaf_db_statement_query (mgr->seaf->db, "DELETE u.*, p.* "
                                      "FROM RepoUserToken u, RepoTokenPeerInfo p "
                                      "WHERE u.token=p.token AND "
                                      "u.email = ? AND p.peer_id = ?",
                                      2, "string", email, "string", peer_id);
        if (rc < 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "DB error");
            goto out;
        }
    } else if (db_type == SEAF_DB_TYPE_SQLITE) {
        GString *sql = g_string_new ("");
        GList *iter;
        int i = 0;
        char *token;

        g_string_append_printf (sql, "DELETE FROM RepoUserToken WHERE email = '%s' AND token IN (", email);
        for (iter = token_list; iter; iter = iter->next) {
            token = iter->data;
            if (i == 0)
                g_string_append_printf (sql, "'%s'", token);
            else
                g_string_append_printf (sql, ", '%s'", token);
            ++i;
        }
        g_string_append (sql, ")");

        rc = seaf_db_statement_query (mgr->seaf->db, sql->str, 0);
        if (rc < 0) {
            g_string_free (sql, TRUE);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "DB error");
            goto out;
        }
        g_string_free (sql, TRUE);

        sql = g_string_new ("");
        g_string_append_printf (sql, "DELETE FROM RepoTokenPeerInfo WHERE peer_id = '%s' AND token IN (", peer_id);
        i = 0;
        for (iter = token_list; iter; iter = iter->next) {
            token = iter->data;
            if (i == 0)
                g_string_append_printf (sql, "'%s'", token);
            else
                g_string_append_printf (sql, ", '%s'", token);
            ++i;
        }
        g_string_append (sql, ")");

        rc = seaf_db_statement_query (mgr->seaf->db, sql->str, 0);
        if (rc < 0) {
            g_string_free (sql, TRUE);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "DB error");
            goto out;
        }
        g_string_free (sql, TRUE);
    }

out:
    if (rc < 0) {
        ret = -1;
        g_list_free_full (token_list, (GDestroyNotify)g_free);
    } else {
        *tokens = token_list;
    }

    return ret;
}

int
seaf_repo_manager_delete_repo_tokens_by_email (SeafRepoManager *mgr,
                                               const char *email,
                                               GError **error)
{
    int ret = 0;
    const char *template;
    GList *token_list = NULL;
    int rc;

    template = "SELECT u.token "
        "FROM RepoUserToken u, RepoTokenPeerInfo p "
        "WHERE u.token = p.token "
        "AND u.email = ?";
    rc = seaf_db_statement_foreach_row (mgr->seaf->db, template,
                                        collect_token_list, &token_list,
                                        1, "string", email);
    if (rc < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "DB error");
        goto out;
    }

    if (rc == 0)
        goto out;

    rc = seaf_db_statement_query (mgr->seaf->db, "DELETE u.*, p.* "
                                  "FROM RepoUserToken u, RepoTokenPeerInfo p "
                                  "WHERE u.token=p.token AND "
                                  "u.email = ?",
                                  1, "string", email);
    if (rc < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "DB error");
        goto out;
    }

#ifdef HAVE_EVHTP
    seaf_http_server_invalidate_tokens (seaf->http_server, token_list);
#endif

out:
    g_list_free_full (token_list, (GDestroyNotify)g_free);

    if (rc < 0) {
        ret = -1;
    }

    return ret;
}

static gboolean
get_email_by_token_cb (SeafDBRow *row, void *data)
{
    char **email_ptr = data;

    const char *email = (const char *) seaf_db_row_get_column_text (row, 0);
    *email_ptr = g_ascii_strdown (email, -1);
    /* There should be only one result. */
    return FALSE;
}

char *
seaf_repo_manager_get_email_by_token (SeafRepoManager *manager,
                                      const char *repo_id,
                                      const char *token)
{
    if (!repo_id || !token)
        return NULL;
    
    char *email = NULL;
    char *sql;

    sql = "SELECT email FROM RepoUserToken "
        "WHERE repo_id = ? AND token = ?";

    seaf_db_statement_foreach_row (seaf->db, sql,
                                   get_email_by_token_cb, &email,
                                   2, "string", repo_id, "string", token);

    return email;
}

static gboolean
get_repo_size (SeafDBRow *row, void *vsize)
{
    gint64 *psize = vsize;

    *psize = seaf_db_row_get_column_int64 (row, 0);

    return FALSE;
}

gint64
seaf_repo_manager_get_repo_size (SeafRepoManager *mgr, const char *repo_id)
{
    gint64 size = 0;
    char *sql;

    sql = "SELECT size FROM RepoSize WHERE repo_id=?";

    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                       get_repo_size, &size,
                                       1, "string", repo_id) < 0)
        return -1;

    return size;
}

int
seaf_repo_manager_set_repo_history_limit (SeafRepoManager *mgr,
                                          const char *repo_id,
                                          int days)
{
    SeafVirtRepo *vinfo;
    SeafDB *db = mgr->seaf->db;

    vinfo = seaf_repo_manager_get_virtual_repo_info (mgr, repo_id);
    if (vinfo) {
        seaf_virtual_repo_info_free (vinfo);
        return 0;
    }

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL) {
        gboolean exists, err;
        int rc;

        exists = seaf_db_statement_exists (db,
                                           "SELECT repo_id FROM RepoHistoryLimit "
                                           "WHERE repo_id=?",
                                           &err, 1, "string", repo_id);
        if (err)
            return -1;

        if (exists)
            rc = seaf_db_statement_query (db,
                                          "UPDATE RepoHistoryLimit SET days=? "
                                          "WHERE repo_id=?",
                                          2, "int", days, "string", repo_id);
        else
            rc = seaf_db_statement_query (db,
                                          "INSERT INTO RepoHistoryLimit (repo_id, days) VALUES "
                                          "(?, ?)",
                                          2, "string", repo_id, "int", days);
        return rc;
    } else {
        if (seaf_db_statement_query (db,
                                     "REPLACE INTO RepoHistoryLimit (repo_id, days) VALUES (?, ?)",
                                     2, "string", repo_id, "int", days) < 0)
            return -1;
    }

    return 0;
}

static gboolean
get_history_limit_cb (SeafDBRow *row, void *data)
{
    int *limit = data;

    *limit = seaf_db_row_get_column_int (row, 0);

    return FALSE;
}

int
seaf_repo_manager_get_repo_history_limit (SeafRepoManager *mgr,
                                          const char *repo_id)
{
    SeafVirtRepo *vinfo;
    const char *r_repo_id = repo_id;
    char *sql;
    int per_repo_days = -1;
    int ret;

    vinfo = seaf_repo_manager_get_virtual_repo_info (mgr, repo_id);
    if (vinfo)
        r_repo_id = vinfo->origin_repo_id;

    sql = "SELECT days FROM RepoHistoryLimit WHERE repo_id=?";

    ret = seaf_db_statement_foreach_row (mgr->seaf->db, sql, get_history_limit_cb,
                                         &per_repo_days, 1, "string", r_repo_id);
    if (ret == 0) {
        // limit not set, return global one
        per_repo_days= seaf_cfg_manager_get_config_int (mgr->seaf->cfg_mgr,
                                                        "history", "keep_days");
    }

    // db error or limit set as negative, means keep full history, return -1
    if (per_repo_days < 0)
        per_repo_days = -1;

    seaf_virtual_repo_info_free (vinfo);

    return per_repo_days;
}

int
seaf_repo_manager_set_repo_valid_since (SeafRepoManager *mgr,
                                        const char *repo_id,
                                        gint64 timestamp)
{
    SeafDB *db = mgr->seaf->db;

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL) {
        gboolean exists, err;
        int rc;

        exists = seaf_db_statement_exists (db,
                                           "SELECT repo_id FROM RepoValidSince WHERE "
                                           "repo_id=?", &err, 1, "string", repo_id);
        if (err)
            return -1;

        if (exists)
            rc = seaf_db_statement_query (db,
                                          "UPDATE RepoValidSince SET timestamp=?"
                                          " WHERE repo_id=?",
                                          2, "int64", timestamp, "string", repo_id);
        else
            rc = seaf_db_statement_query (db,
                                          "INSERT INTO RepoValidSince (repo_id, timestamp) VALUES "
                                          "(?, ?)", 2, "string", repo_id,
                                          "int64", timestamp);
        if (rc < 0)
            return -1;
    } else {
        if (seaf_db_statement_query (db,
                           "REPLACE INTO RepoValidSince (repo_id, timestamp) VALUES (?, ?)",
                           2, "string", repo_id, "int64", timestamp) < 0)
            return -1;
    }

    return 0;
}

gint64
seaf_repo_manager_get_repo_valid_since (SeafRepoManager *mgr,
                                        const char *repo_id)
{
    char *sql;

    sql = "SELECT timestamp FROM RepoValidSince WHERE repo_id=?";
    /* Also return -1 if doesn't exist. */
    return seaf_db_statement_get_int64 (mgr->seaf->db, sql, 1, "string", repo_id);
}

gint64
seaf_repo_manager_get_repo_truncate_time (SeafRepoManager *mgr,
                                          const char *repo_id)
{
    int days;
    gint64 timestamp;

    days = seaf_repo_manager_get_repo_history_limit (mgr, repo_id);
    timestamp = seaf_repo_manager_get_repo_valid_since (mgr, repo_id);

    gint64 now = (gint64)time(NULL);
    if (days > 0)
        return MAX (now - days * 24 * 3600, timestamp);
    else if (days < 0)
        return timestamp;
    else
        return 0;
}

/*
 * Permission related functions.
 */

/* Owner functions. */

int
seaf_repo_manager_set_repo_owner (SeafRepoManager *mgr,
                                  const char *repo_id,
                                  const char *email)
{
    SeafDB *db = mgr->seaf->db;
    char sql[256];
    char *orig_owner = NULL;
    int ret = 0;

    orig_owner = seaf_repo_manager_get_repo_owner (mgr, repo_id);
    if (g_strcmp0 (orig_owner, email) == 0)
        goto out;

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL) {
        gboolean err;
        snprintf(sql, sizeof(sql),
                 "SELECT repo_id FROM RepoOwner WHERE repo_id=?");
        if (seaf_db_statement_exists (db, sql, &err,
                                      1, "string", repo_id))
            snprintf(sql, sizeof(sql),
                     "UPDATE RepoOwner SET owner_id='%s' WHERE "
                     "repo_id='%s'", email, repo_id);
        else
            snprintf(sql, sizeof(sql),
                     "INSERT INTO RepoOwner (repo_id, owner_id) VALUES ('%s', '%s')",
                     repo_id, email);
        if (err) {
            ret = -1;
            goto out;
        }

        if (seaf_db_query (db, sql) < 0) {
            ret = -1;
            goto out;
        }
    } else {
        if (seaf_db_statement_query (db, "REPLACE INTO RepoOwner (repo_id, owner_id) VALUES (?, ?)",
                                     2, "string", repo_id, "string", email) < 0) {
            ret = -1;
            goto out;
        }
    }

    /* If the repo was newly created, no need to remove share and virtual repos. */
    if (!orig_owner)
        goto out;

    seaf_db_statement_query (mgr->seaf->db, "DELETE FROM SharedRepo WHERE repo_id = ?",
                             1, "string", repo_id);

    seaf_db_statement_query (mgr->seaf->db, "DELETE FROM RepoGroup WHERE repo_id = ?",
                             1, "string", repo_id);

    if (!seaf->cloud_mode) {
        seaf_db_statement_query (mgr->seaf->db, "DELETE FROM InnerPubRepo WHERE repo_id = ?",
                                 1, "string", repo_id);
    }

    /* Remove virtual repos when repo ownership changes. */
    GList *vrepos, *ptr;
    vrepos = seaf_repo_manager_get_virtual_repo_ids_by_origin (mgr, repo_id);
    for (ptr = vrepos; ptr != NULL; ptr = ptr->next)
        remove_virtual_repo_ondisk (mgr, (char *)ptr->data);
    string_list_free (vrepos);

    seaf_db_statement_query (mgr->seaf->db, "DELETE FROM VirtualRepo "
                             "WHERE repo_id=? OR origin_repo=?",
                             2, "string", repo_id, "string", repo_id);

out:
    g_free (orig_owner);
    return ret;
}

static gboolean
get_owner (SeafDBRow *row, void *data)
{
    char **owner_id = data;

    const char *owner = (const char *) seaf_db_row_get_column_text (row, 0);
    *owner_id = g_ascii_strdown (owner, -1);
    /* There should be only one result. */
    return FALSE;
}

char *
seaf_repo_manager_get_repo_owner (SeafRepoManager *mgr,
                                  const char *repo_id)
{
    char *sql;
    char *ret = NULL;

    sql = "SELECT owner_id FROM RepoOwner WHERE repo_id=?";
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                       get_owner, &ret,
                                       1, "string", repo_id) < 0) {
        seaf_warning ("Failed to get owner id for repo %s.\n", repo_id);
        return NULL;
    }

    return ret;
}

static gboolean
collect_repo_id (SeafDBRow *row, void *data)
{
    GList **p_ids = data;
    const char *repo_id;

    repo_id = seaf_db_row_get_column_text (row, 0);
    *p_ids = g_list_prepend (*p_ids, g_strdup(repo_id));

    return TRUE;
}

GList *
seaf_repo_manager_get_orphan_repo_list (SeafRepoManager *mgr)
{
    GList *id_list = NULL, *ptr;
    GList *ret = NULL;
    char sql[256];

    snprintf (sql, sizeof(sql), "SELECT Repo.repo_id FROM Repo LEFT JOIN "
              "RepoOwner ON Repo.repo_id = RepoOwner.repo_id WHERE "
              "RepoOwner.owner_id is NULL");

    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql,
                                      collect_repo_id, &id_list) < 0)
        return NULL;

    for (ptr = id_list; ptr; ptr = ptr->next) {
        char *repo_id = ptr->data;
        SeafRepo *repo = seaf_repo_manager_get_repo (mgr, repo_id);
        if (repo != NULL)
            ret = g_list_prepend (ret, repo);
    }

    string_list_free (id_list);

    return ret;
}

gboolean
collect_repos_fill_size_commit (SeafDBRow *row, void *data)
{
    GList **prepos = data;
    SeafRepo *repo;
    SeafBranch *head;

    const char *repo_id = seaf_db_row_get_column_text (row, 0);
    gint64 size = seaf_db_row_get_column_int64 (row, 1);
    const char *commit_id = seaf_db_row_get_column_text (row, 2);
    const char *repo_name = seaf_db_row_get_column_text (row, 3);
    gint64 update_time = seaf_db_row_get_column_int64 (row, 4);
    int version = seaf_db_row_get_column_int (row, 5);
    gboolean is_encrypted = seaf_db_row_get_column_int (row, 6) ? TRUE : FALSE;
    const char *last_modifier = seaf_db_row_get_column_text (row, 7);
    int status = seaf_db_row_get_column_int (row, 8);
    const char *type = seaf_db_row_get_column_text (row, 9);

    repo = seaf_repo_new (repo_id, NULL, NULL);
    if (!repo)
        return TRUE;

    if (!commit_id) {
        repo->is_corrupted = TRUE;
        goto out;
    }

    repo->size = size;
    if (seaf_db_row_get_column_count (row) == 11) {
        gint64 file_count = seaf_db_row_get_column_int64 (row, 10);
        repo->file_count = file_count;
    }
    head = seaf_branch_new ("master", repo_id, commit_id);
    repo->head = head;
    if (repo_name) {
        repo->name = g_strdup (repo_name);
        repo->last_modify = update_time;
        repo->version = version;
        repo->encrypted = is_encrypted;
        repo->last_modifier = g_strdup (last_modifier);
        repo->status = status;
    }
    if (type) {
        repo->type = g_strdup(type);
    }

out:
    *prepos = g_list_prepend (*prepos, repo);

    return TRUE;
}

GList *
seaf_repo_manager_get_repos_by_owner (SeafRepoManager *mgr,
                                      const char *email,
                                      int ret_corrupted,
                                      int start,
                                      int limit,
                                      gboolean *db_err)
{
    GList *repo_list = NULL, *ptr;
    GList *ret = NULL;
    char *sql;
    SeafRepo *repo = NULL;
    int db_type = seaf_db_type(mgr->seaf->db);

    if (start == -1 && limit == -1) {
        if (db_type != SEAF_DB_TYPE_PGSQL)
            sql = "SELECT o.repo_id, s.size, b.commit_id, i.name, i.update_time, "
                "i.version, i.is_encrypted, i.last_modifier, i.status, i.type FROM "
                "RepoOwner o LEFT JOIN RepoSize s ON o.repo_id = s.repo_id "
                "LEFT JOIN Branch b ON o.repo_id = b.repo_id "
                "LEFT JOIN RepoInfo i ON o.repo_id = i.repo_id "
                "LEFT JOIN VirtualRepo v ON o.repo_id = v.repo_id "
                "WHERE owner_id=? AND "
                "v.repo_id IS NULL "
                "ORDER BY i.update_time DESC, o.repo_id";
        else
            sql = "SELECT o.repo_id, s.\"size\", b.commit_id, i.name, i.update_time, "
                "i.version, i.is_encrypted, i.last_modifier, i.status FROM "
                "RepoOwner o LEFT JOIN RepoSize s ON o.repo_id = s.repo_id "
                "LEFT JOIN Branch b ON o.repo_id = b.repo_id "
                "LEFT JOIN RepoInfo i ON o.repo_id = i.repo_id "
                "WHERE owner_id=? AND "
                "o.repo_id NOT IN (SELECT v.repo_id FROM VirtualRepo v) "
                "ORDER BY i.update_time DESC, o.repo_id";

        if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, 
                                           collect_repos_fill_size_commit, &repo_list,
                                           1, "string", email) < 0) {
            if (db_err)
                *db_err = TRUE;
            return NULL;
        }
    } else {
        if (db_type != SEAF_DB_TYPE_PGSQL)
            sql = "SELECT o.repo_id, s.size, b.commit_id, i.name, i.update_time, "
                "i.version, i.is_encrypted, i.last_modifier, i.status, i.type FROM "
                "RepoOwner o LEFT JOIN RepoSize s ON o.repo_id = s.repo_id "
                "LEFT JOIN Branch b ON o.repo_id = b.repo_id "
                "LEFT JOIN RepoInfo i ON o.repo_id = i.repo_id "
                "LEFT JOIN VirtualRepo v ON o.repo_id = v.repo_id "
                "WHERE owner_id=? AND "
                "v.repo_id IS NULL "
                "ORDER BY i.update_time DESC, o.repo_id "
                "LIMIT ? OFFSET ?";
        else
            sql = "SELECT o.repo_id, s.\"size\", b.commit_id, i.name, i.update_time, "
                "i.version, i.is_encrypted, i.last_modifier, i.status FROM "
                "RepoOwner o LEFT JOIN RepoSize s ON o.repo_id = s.repo_id "
                "LEFT JOIN Branch b ON o.repo_id = b.repo_id "
                "LEFT JOIN RepoInfo i ON o.repo_id = i.repo_id "
                "WHERE owner_id=? AND "
                "o.repo_id NOT IN (SELECT v.repo_id FROM VirtualRepo v) "
                "ORDER BY i.update_time DESC, o.repo_id "
                "LIMIT ? OFFSET ?";

        if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, 
                                           collect_repos_fill_size_commit,
                                           &repo_list,
                                           3, "string", email,
                                           "int", limit,
                                           "int", start) < 0) {
            if (db_err)
                *db_err = TRUE;
            return NULL;
        }
    }

    for (ptr = repo_list; ptr; ptr = ptr->next) {
        repo = ptr->data;
        if (ret_corrupted) {
            if (!repo->is_corrupted && (!repo->name || !repo->last_modifier)) {
                load_mini_repo (mgr, repo);
                if (!repo->is_corrupted)
                    set_repo_commit_to_db (repo->id, repo->name, repo->last_modify,
                                           repo->version, (repo->encrypted ? 1 : 0),
                                           repo->last_modifier);
            }
        } else {
            if (repo->is_corrupted) {
                seaf_repo_unref (repo);
                continue;
            }
            if (!repo->name || !repo->last_modifier) {
                load_mini_repo (mgr, repo);
                if (!repo->is_corrupted)
                    set_repo_commit_to_db (repo->id, repo->name, repo->last_modify,
                                           repo->version, (repo->encrypted ? 1 : 0),
                                           repo->last_modifier);
            }
            if (repo->is_corrupted) {
                seaf_repo_unref (repo);
                continue;
            }
        }
        if (repo != NULL)
            ret = g_list_prepend (ret, repo);
    }
    g_list_free (repo_list);

    return ret;
}

GList *
seaf_repo_manager_get_repos_by_id_prefix (SeafRepoManager *mgr,
                                          const char *id_prefix,
                                          int start,
                                          int limit)
{
    GList *repo_list = NULL, *ptr;
    char *sql;
    SeafRepo *repo = NULL;
    int len = strlen(id_prefix);

    if (len >= 37)
        return NULL;

    int db_type = seaf_db_type(mgr->seaf->db);
    char *db_patt = g_strdup_printf ("%s%%", id_prefix);

    if (start == -1 && limit == -1) {
        if (db_type != SEAF_DB_TYPE_PGSQL)
            sql = "SELECT i.repo_id, s.size, b.commit_id, i.name, i.update_time, "
                "i.version, i.is_encrypted, i.last_modifier, i.status, i.type FROM "
                "RepoInfo i LEFT JOIN RepoSize s ON i.repo_id = s.repo_id "
                "LEFT JOIN Branch b ON i.repo_id = b.repo_id "
                "LEFT JOIN VirtualRepo v ON i.repo_id = v.repo_id "
                "WHERE i.repo_id LIKE ? AND "
                "v.repo_id IS NULL "
                "ORDER BY i.update_time DESC, i.repo_id";
        else
            sql = "SELECT i.repo_id, s.\"size\", b.commit_id, i.name, i.update_time, "
                "i.version, i.is_encrypted, i.last_modifier, i.status FROM "
                "RepoInfo i LEFT JOIN RepoSize s ON i.repo_id = s.repo_id "
                "LEFT JOIN Branch b ON i.repo_id = b.repo_id "
                "WHERE i.repo_id LIKE ? AND "
                "i.repo_id NOT IN (SELECT v.repo_id FROM VirtualRepo v) "
                "ORDER BY i.update_time DESC, i.repo_id";

        if (seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                           collect_repos_fill_size_commit, &repo_list,
                                           1, "string", db_patt) < 0) {
            g_free(db_patt);
            return NULL;
        }
    } else {
        if (db_type != SEAF_DB_TYPE_PGSQL)
            sql = "SELECT i.repo_id, s.size, b.commit_id, i.name, i.update_time, "
                "i.version, i.is_encrypted, i.last_modifier, i.status, i.type FROM "
                "RepoInfo i LEFT JOIN RepoSize s ON i.repo_id = s.repo_id "
                "LEFT JOIN Branch b ON i.repo_id = b.repo_id "
                "LEFT JOIN VirtualRepo v ON i.repo_id = v.repo_id "
                "WHERE i.repo_id LIKE ? AND "
                "v.repo_id IS NULL "
                "ORDER BY i.update_time DESC, i.repo_id "
                "LIMIT ? OFFSET ?";
        else
            sql = "SELECT i.repo_id, s.\"size\", b.commit_id, i.name, i.update_time, "
                "i.version, i.is_encrypted, i.last_modifier, i.status FROM "
                "RepoInfo i LEFT JOIN RepoSize s ON i.repo_id = s.repo_id "
                "LEFT JOIN Branch b ON i.repo_id = b.repo_id "
                "WHERE i.repo_id LIKE ? AND "
                "i.repo_id NOT IN (SELECT v.repo_id FROM VirtualRepo v) "
                "ORDER BY i.update_time DESC, i.repo_id "
                "LIMIT ? OFFSET ?";

        if (seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                           collect_repos_fill_size_commit,
                                           &repo_list,
                                           3, "string", db_patt,
                                           "int", limit,
                                           "int", start) < 0) {
            g_free(db_patt);
            return NULL;
        }
    }

    g_free(db_patt);

    return repo_list;
}

GList *
seaf_repo_manager_search_repos_by_name (SeafRepoManager *mgr, const char *name)
{
    GList *repo_list = NULL;
    char *sql = NULL;

    char *db_patt = g_strdup_printf ("%%%s%%", name);

    switch (seaf_db_type(seaf->db)) {
    case SEAF_DB_TYPE_MYSQL:
        sql = "SELECT i.repo_id, s.size, b.commit_id, i.name, i.update_time, "
            "i.version, i.is_encrypted, i.last_modifier, i.status, i.type, fc.file_count FROM "
            "RepoInfo i LEFT JOIN RepoSize s ON i.repo_id = s.repo_id "
            "LEFT JOIN Branch b ON i.repo_id = b.repo_id "
            "LEFT JOIN RepoFileCount fc ON i.repo_id = fc.repo_id "
            "LEFT JOIN Repo r ON i.repo_id = r.repo_id "
            "LEFT JOIN VirtualRepo v ON i.repo_id = v.repo_id "
            "WHERE i.name COLLATE UTF8_GENERAL_CI LIKE ? AND "
            "r.repo_id IS NOT NULL AND "
            "v.repo_id IS NULL "
            "ORDER BY i.update_time DESC, i.repo_id";
        break;
    case SEAF_DB_TYPE_PGSQL:
        sql = "SELECT i.repo_id, s.\"size\", b.commit_id, i.name, i.update_time, "
            "i.version, i.is_encrypted, i.last_modifier, i.status, fc.file_count FROM "
            "RepoInfo i LEFT JOIN RepoSize s ON i.repo_id = s.repo_id "
            "LEFT JOIN Branch b ON i.repo_id = b.repo_id "
            "LEFT JOIN RepoFileCount fc ON i.repo_id = fc.repo_id "
            "WHERE i.name ILIKE ? AND "
            "i.repo_id IN (SELECT r.repo_id FROM Repo r) AND "
            "i.repo_id NOT IN (SELECT v.repo_id FROM VirtualRepo v) "
            "ORDER BY i.update_time DESC, i.repo_id";
        break;
    case SEAF_DB_TYPE_SQLITE:
        sql = "SELECT i.repo_id, s.size, b.commit_id, i.name, i.update_time, "
            "i.version, i.is_encrypted, i.last_modifier, i.status, i.type, fc.file_count FROM "
            "RepoInfo i LEFT JOIN RepoSize s ON i.repo_id = s.repo_id "
            "LEFT JOIN Branch b ON i.repo_id = b.repo_id "
            "LEFT JOIN RepoFileCount fc ON i.repo_id = fc.repo_id "
            "LEFT JOIN Repo r ON i.repo_id = r.repo_id "
            "LEFT JOIN VirtualRepo v ON i.repo_id = v.repo_id "
            "WHERE i.name LIKE ? COLLATE NOCASE AND "
            "r.repo_id IS NOT NULL AND "
            "v.repo_id IS NULL "
            "ORDER BY i.update_time DESC, i.repo_id";
        break;
    default:
        g_free (db_patt);
        return NULL;
    }

    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                       collect_repos_fill_size_commit, &repo_list,
                                       1, "string", db_patt) < 0) {
        g_free (db_patt);
        return NULL;
    }

    g_free (db_patt);
    return repo_list;
}

GList *
seaf_repo_manager_get_repo_id_list (SeafRepoManager *mgr)
{
    GList *ret = NULL;
    char sql[256];

    snprintf (sql, 256, "SELECT repo_id FROM Repo");

    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql, 
                                      collect_repo_id, &ret) < 0)
        return NULL;

    return ret;
}

GList *
seaf_repo_manager_get_repo_list (SeafRepoManager *mgr, int start, int limit, const char *order_by, int ret_virt_repo)
{
    GList *ret = NULL;
    int rc;
    GString *sql = g_string_new ("");

    if (start == -1 && limit == -1) {
        switch (seaf_db_type(mgr->seaf->db)) {
        case SEAF_DB_TYPE_MYSQL:
            g_string_append (sql, "SELECT i.repo_id, s.size, b.commit_id, i.name, i.update_time, "
                "i.version, i.is_encrypted, i.last_modifier, i.status, i.type, f.file_count FROM "
                "RepoInfo i LEFT JOIN RepoSize s ON i.repo_id = s.repo_id "
                "LEFT JOIN Branch b ON i.repo_id = b.repo_id "
                "LEFT JOIN RepoFileCount f ON i.repo_id = f.repo_id "
                "LEFT JOIN Repo r ON i.repo_id = r.repo_id "
                "LEFT JOIN VirtualRepo v ON i.repo_id = v.repo_id "
                "WHERE r.repo_id IS NOT NULL ");
            if (!ret_virt_repo)
                g_string_append_printf (sql, "AND v.repo_id IS NULL ");
            if (g_strcmp0 (order_by, "size") == 0)
                g_string_append_printf (sql, "ORDER BY s.size DESC, i.repo_id");
            else if (g_strcmp0 (order_by, "file_count") == 0)
                g_string_append_printf (sql, "ORDER BY f.file_count DESC, i.repo_id");
            else
                g_string_append_printf (sql, "ORDER BY i.update_time DESC, i.repo_id");
            break;
        case SEAF_DB_TYPE_SQLITE:
            g_string_append (sql, "SELECT i.repo_id, s.size, b.commit_id, i.name, i.update_time, "
                "i.version, i.is_encrypted, i.last_modifier, i.status, i.type, f.file_count FROM "
                "RepoInfo i LEFT JOIN RepoSize s ON i.repo_id = s.repo_id "
                "LEFT JOIN Branch b ON i.repo_id = b.repo_id "
                "LEFT JOIN RepoFileCount f ON i.repo_id = f.repo_id "
                "LEFT JOIN Repo r ON i.repo_id = r.repo_id "
                "LEFT JOIN VirtualRepo v ON i.repo_id = v.repo_id "
                "WHERE r.repo_id IS NOT NULL ");
            if (!ret_virt_repo)
                g_string_append_printf (sql, "AND v.repo_id IS NULL ");
            if (g_strcmp0 (order_by, "size") == 0)
                g_string_append_printf (sql, "ORDER BY s.size DESC, i.repo_id");
            else if (g_strcmp0 (order_by, "file_count") == 0)
                g_string_append_printf (sql, "ORDER BY f.file_count DESC, i.repo_id");
            else
                g_string_append_printf (sql, "ORDER BY i.update_time DESC, i.repo_id");
            break;
        default:
            g_string_free (sql, TRUE);
            return NULL;
        }

        rc = seaf_db_statement_foreach_row (mgr->seaf->db, sql->str,
                                            collect_repos_fill_size_commit, &ret,
                                            0);
    } else {
        switch (seaf_db_type(mgr->seaf->db)) {
        case SEAF_DB_TYPE_MYSQL:
            g_string_append (sql, "SELECT i.repo_id, s.size, b.commit_id, i.name, i.update_time, "
                "i.version, i.is_encrypted, i.last_modifier, i.status, i.type, f.file_count FROM "
                "RepoInfo i LEFT JOIN RepoSize s ON i.repo_id = s.repo_id "
                "LEFT JOIN Branch b ON i.repo_id = b.repo_id "
                "LEFT JOIN RepoFileCount f ON i.repo_id = f.repo_id "
                "LEFT JOIN Repo r ON i.repo_id = r.repo_id "
                "LEFT JOIN VirtualRepo v ON i.repo_id = v.repo_id "
                "WHERE r.repo_id IS NOT NULL ");
            if (!ret_virt_repo)
                g_string_append_printf (sql, "AND v.repo_id IS NULL ");
            if (g_strcmp0 (order_by, "size") == 0)
                g_string_append_printf (sql, "ORDER BY s.size DESC, i.repo_id LIMIT ? OFFSET ?");
            else if (g_strcmp0 (order_by, "file_count") == 0)
                g_string_append_printf (sql, "ORDER BY f.file_count DESC, i.repo_id LIMIT ? OFFSET ?");
            else
                g_string_append_printf (sql, "ORDER BY i.update_time DESC, i.repo_id LIMIT ? OFFSET ?");
            break;
        case SEAF_DB_TYPE_SQLITE:
            g_string_append (sql, "SELECT i.repo_id, s.size, b.commit_id, i.name, i.update_time, "
                "i.version, i.is_encrypted, i.last_modifier, i.status, i.type, f.file_count FROM "
                "RepoInfo i LEFT JOIN RepoSize s ON i.repo_id = s.repo_id "
                "LEFT JOIN Branch b ON i.repo_id = b.repo_id "
                "LEFT JOIN RepoFileCount f ON i.repo_id = f.repo_id "
                "LEFT JOIN Repo r ON i.repo_id = r.repo_id "
                "LEFT JOIN VirtualRepo v ON i.repo_id = v.repo_id "
                "WHERE r.repo_id IS NOT NULL ");
            if (!ret_virt_repo)
                g_string_append_printf (sql, "AND v.repo_id IS NULL ");
            if (g_strcmp0 (order_by, "size") == 0)
                g_string_append_printf (sql, "ORDER BY s.size DESC, i.repo_id LIMIT ? OFFSET ?");
            else if (g_strcmp0 (order_by, "file_count") == 0)
                g_string_append_printf (sql, "ORDER BY f.file_count DESC, i.repo_id LIMIT ? OFFSET ?");
            else
                g_string_append_printf (sql, "ORDER BY i.update_time DESC, i.repo_id LIMIT ? OFFSET ?");
            break;
        default:
            g_string_free (sql, TRUE);
            return NULL;
        }

        rc = seaf_db_statement_foreach_row (mgr->seaf->db, sql->str,
                                            collect_repos_fill_size_commit, &ret,
                                            2, "int", limit, "int", start);
    }

    g_string_free (sql, TRUE);

    if (rc < 0)
        return NULL;

    return g_list_reverse (ret);
}

gint64
seaf_repo_manager_count_repos (SeafRepoManager *mgr, GError **error)
{
    gint64 num = seaf_db_get_int64 (mgr->seaf->db,
                                    "SELECT COUNT(repo_id) FROM Repo");
    if (num < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to count repos from db");
    }

    return num;
}

GList *
seaf_repo_manager_get_repo_ids_by_owner (SeafRepoManager *mgr,
                                         const char *email)
{
    GList *ret = NULL;
    char *sql;

    sql = "SELECT repo_id FROM RepoOwner WHERE owner_id=?";

    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, 
                                       collect_repo_id, &ret,
                                       1, "string", email) < 0) {
        string_list_free (ret);
        return NULL;
    }

    return ret;
}

static gboolean
collect_trash_repo (SeafDBRow *row, void *data)
{
    GList **trash_repos = data;
    const char *repo_id;
    const char *repo_name;
    const char *head_id;
    const char *owner_id;
    gint64 size;
    gint64 del_time;

    repo_id = seaf_db_row_get_column_text (row, 0);
    repo_name = seaf_db_row_get_column_text (row, 1);
    head_id = seaf_db_row_get_column_text (row, 2);
    owner_id = seaf_db_row_get_column_text (row, 3);
    size = seaf_db_row_get_column_int64 (row, 4);
    del_time = seaf_db_row_get_column_int64 (row, 5);


    if (!repo_id || !repo_name || !head_id || !owner_id)
        return TRUE;

    SeafileTrashRepo *trash_repo = g_object_new (SEAFILE_TYPE_TRASH_REPO,
                                                 "repo_id", repo_id,
                                                 "repo_name", repo_name,
                                                 "head_id", head_id,
                                                 "owner_id", owner_id,
                                                 "size", size,
                                                 "del_time", del_time,
                                                 NULL);
    if (!trash_repo)
        return FALSE;

    SeafCommit *commit = seaf_commit_manager_get_commit_compatible (seaf->commit_mgr,
                                                                    repo_id, head_id);
    if (!commit) {
        seaf_warning ("Commit %s not found in repo %s\n", head_id, repo_id);
        g_object_unref (trash_repo);
        return TRUE;
    }
    g_object_set (trash_repo, "encrypted", commit->encrypted, NULL);
    seaf_commit_unref (commit);

    *trash_repos = g_list_prepend (*trash_repos, trash_repo);

    return TRUE;
}

GList *
seaf_repo_manager_get_trash_repo_list (SeafRepoManager *mgr,
                                       int start,
                                       int limit,
                                       GError **error)
{
    GList *trash_repos = NULL;
    int rc;

    if (start == -1 && limit == -1)
        rc = seaf_db_statement_foreach_row (mgr->seaf->db,
                                            "SELECT repo_id, repo_name, head_id, owner_id, "
                                            "size, del_time FROM RepoTrash ORDER BY del_time DESC",
                                            collect_trash_repo, &trash_repos,
                                            0);
    else
        rc = seaf_db_statement_foreach_row (mgr->seaf->db,
                                            "SELECT repo_id, repo_name, head_id, owner_id, "
                                            "size, del_time FROM RepoTrash "
                                            "ORDER BY del_time DESC LIMIT ? OFFSET ?",
                                            collect_trash_repo, &trash_repos,
                                            2, "int", limit, "int", start);

    if (rc < 0) {
        while (trash_repos) {
            g_object_unref (trash_repos->data);
            trash_repos = g_list_delete_link (trash_repos, trash_repos);
        }
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to get trashed repo from db.");
        return NULL;
    }

    return g_list_reverse (trash_repos);
}

GList *
seaf_repo_manager_get_trash_repos_by_owner (SeafRepoManager *mgr,
                                            const char *owner,
                                            GError **error)
{
    GList *trash_repos = NULL;
    int rc;

    rc = seaf_db_statement_foreach_row (mgr->seaf->db,
                                        "SELECT repo_id, repo_name, head_id, owner_id, "
                                        "size, del_time FROM RepoTrash WHERE owner_id = ?",
                                        collect_trash_repo, &trash_repos,
                                        1, "string", owner);

    if (rc < 0) {
        while (trash_repos) {
            g_object_unref (trash_repos->data);
            trash_repos = g_list_delete_link (trash_repos, trash_repos);
        }
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to get trashed repo from db.");
        return NULL;
    }

    return trash_repos;
}

SeafileTrashRepo *
seaf_repo_manager_get_repo_from_trash (SeafRepoManager *mgr,
                                       const char *repo_id)
{
    SeafileTrashRepo *ret = NULL;
    GList *trash_repos = NULL;
    char *sql;
    int rc;

    sql = "SELECT repo_id, repo_name, head_id, owner_id, size, del_time FROM RepoTrash "
        "WHERE repo_id = ?";
    rc = seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                        collect_trash_repo, &trash_repos,
                                        1, "string", repo_id);
    if (rc < 0)
        return NULL;

    /* There should be only one results, since repo_id is a PK. */
    if (trash_repos)
        ret = trash_repos->data;

    g_list_free (trash_repos);
    return ret;
}

int
seaf_repo_manager_del_repo_from_trash (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       GError **error)
{
    /* As long as the repo is successfully moved into GarbageRepo table,
     * we consider this operation successful.
     */
    if (add_deleted_repo_record (mgr, repo_id) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "DB error: Add deleted record");
        return -1;
    }

    seaf_db_statement_query (mgr->seaf->db,
                             "DELETE FROM RepoFileCount WHERE repo_id = ?",
                             1, "string", repo_id);

    seaf_db_statement_query (mgr->seaf->db,
                             "DELETE FROM RepoTrash WHERE repo_id = ?",
                             1, "string", repo_id);

    seaf_db_statement_query (mgr->seaf->db,
                             "DELETE FROM RepoInfo WHERE repo_id = ?",
                             1, "string", repo_id);

    return 0;
}

int
seaf_repo_manager_empty_repo_trash (SeafRepoManager *mgr, GError **error)
{
    GList *trash_repos = NULL, *ptr;
    SeafileTrashRepo *repo;

    trash_repos = seaf_repo_manager_get_trash_repo_list (mgr, -1, -1, error);
    if (*error)
        return -1;

    for (ptr = trash_repos; ptr; ptr = ptr->next) {
        repo = ptr->data;
        seaf_repo_manager_del_repo_from_trash (mgr,
                                               seafile_trash_repo_get_repo_id(repo),
                                               NULL);
        g_object_unref (repo);
    }

    g_list_free (trash_repos);
    return 0;
}

int
seaf_repo_manager_empty_repo_trash_by_owner (SeafRepoManager *mgr,
                                             const char *owner,
                                             GError **error)
{
    GList *trash_repos = NULL, *ptr;
    SeafileTrashRepo *repo;

    trash_repos = seaf_repo_manager_get_trash_repos_by_owner (mgr, owner, error);
    if (*error)
        return -1;

    for (ptr = trash_repos; ptr; ptr = ptr->next) {
        repo = ptr->data;
        seaf_repo_manager_del_repo_from_trash (mgr,
                                               seafile_trash_repo_get_repo_id(repo),
                                               NULL);
        g_object_unref (repo);
    }

    g_list_free (trash_repos);
    return 0;
}

int
seaf_repo_manager_restore_repo_from_trash (SeafRepoManager *mgr,
                                           const char *repo_id,
                                           GError **error)
{
    SeafileTrashRepo *repo = NULL;
    int ret = 0;
    gboolean exists = FALSE;
    gboolean db_err;
    const char *head_id = NULL;
    SeafCommit *commit = NULL;

    repo = seaf_repo_manager_get_repo_from_trash (mgr, repo_id);
    if (!repo) {
        seaf_warning ("Repo %.8s not found in trash.\n", repo_id);
        return -1;
    }

    SeafDBTrans *trans = seaf_db_begin_transaction (mgr->seaf->db);

    exists = seaf_db_trans_check_for_existence (trans,
                                                "SELECT 1 FROM Repo WHERE repo_id=?",
                                                &db_err, 1, "string", repo_id);

    if (!exists) {
        ret = seaf_db_trans_query (trans,
                                   "INSERT INTO Repo(repo_id) VALUES (?)",
                                   1, "string", repo_id) < 0;
        if (ret < 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "DB error: Insert Repo.");
            seaf_db_rollback (trans);
            seaf_db_trans_close (trans);
            goto out;
        }
    }

    exists = seaf_db_trans_check_for_existence (trans,
                                                "SELECT 1 FROM RepoOwner WHERE repo_id=?",
                                                &db_err, 1, "string", repo_id);

    if (!exists) {
        ret = seaf_db_trans_query (trans,
                                   "INSERT INTO RepoOwner (repo_id, owner_id) VALUES (?, ?)",
                                   2, "string", repo_id,
                                   "string", seafile_trash_repo_get_owner_id(repo));
        if (ret < 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "DB error: Insert Repo Owner.");
            seaf_db_rollback (trans);
            seaf_db_trans_close (trans);
            goto out;
        }
    }

    exists = seaf_db_trans_check_for_existence (trans,
                                                "SELECT 1 FROM Branch WHERE repo_id=?",
                                                &db_err, 1, "string", repo_id);
    if (!exists) {
        ret = seaf_db_trans_query (trans,
                                   "INSERT INTO Branch (name, repo_id, commit_id) VALUES ('master', ?, ?)",
                                   2, "string", repo_id,
                                   "string", seafile_trash_repo_get_head_id(repo));
        if (ret < 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "DB error: Insert Branch.");
            seaf_db_rollback (trans);
            seaf_db_trans_close (trans);
            goto out;
        }
    }

    exists = seaf_db_trans_check_for_existence (trans,
                                                "SELECT 1 FROM RepoHead WHERE repo_id=?",
                                                &db_err, 1, "string", repo_id);
    if (!exists) {
        ret = seaf_db_trans_query (trans,
                                   "INSERT INTO RepoHead (repo_id, branch_name) VALUES (?, 'master')",
                                   1, "string", repo_id);
        if (ret < 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "DB error: Set RepoHead.");
            seaf_db_rollback (trans);
            seaf_db_trans_close (trans);
            goto out;
        }
    }

    // Restore repo size
    exists = seaf_db_trans_check_for_existence (trans,
                                                "SELECT 1 FROM RepoSize WHERE repo_id=?",
                                                &db_err, 1, "string", repo_id);

    if (!exists) {
        ret = seaf_db_trans_query (trans,
                                   "INSERT INTO RepoSize (repo_id, size, head_id) VALUES (?, ?, ?)",
                                   3, "string", repo_id,
                                   "int64", seafile_trash_repo_get_size (repo),
                                   "string", seafile_trash_repo_get_head_id (repo));
        if (ret < 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "DB error: Insert Repo Size.");
            seaf_db_rollback (trans);
            seaf_db_trans_close (trans);
            goto out;
        }
    }

    // Restore repo info
    exists = seaf_db_trans_check_for_existence (trans,
                                                "SELECT 1 FROM RepoInfo WHERE repo_id=?",
                                                &db_err, 1, "string", repo_id);

    if (!exists) {
        head_id = seafile_trash_repo_get_head_id (repo);
        commit = seaf_commit_manager_get_commit_compatible (seaf->commit_mgr,
                                                            repo_id, head_id);
        if (!commit) {
            seaf_warning ("Commit %.8s of repo %.8s not found.\n", repo_id, head_id);
            seaf_db_rollback (trans);
            seaf_db_trans_close (trans);
            ret = -1;
            goto out;
        }
        ret = seaf_db_trans_query (trans,
                                   "INSERT INTO RepoInfo (repo_id, name, update_time, version, is_encrypted, last_modifier) VALUES (?, ?, ?, ?, ?, ?)",
                                   6, "string", repo_id,
                                   "string", seafile_trash_repo_get_repo_name (repo),
                                   "int64", commit->ctime,
                                   "int", commit->version,
                                   "int", commit->encrypted,
                                   "string", commit->creator_name);
        if (ret < 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "DB error: Insert Repo Info.");
            seaf_db_rollback (trans);
            seaf_db_trans_close (trans);
            goto out;
        }
    }

    ret = seaf_db_trans_query (trans,
                               "DELETE FROM RepoTrash WHERE repo_id = ?",
                               1, "string", repo_id);
    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "DB error: delete from RepoTrash.");
        seaf_db_rollback (trans);
        seaf_db_trans_close (trans);
        goto out;
    }

    if (seaf_db_commit (trans) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "DB error: Failed to commit.");
        seaf_db_rollback (trans);
        ret = -1;
    }

    seaf_db_trans_close (trans);

out:
    seaf_commit_unref (commit);
    g_object_unref (repo);
    return ret;
}

/* Web access permission. */

int
seaf_repo_manager_set_access_property (SeafRepoManager *mgr, const char *repo_id,
                                       const char *ap)
{
    int rc;

    if (seaf_repo_manager_query_access_property (mgr, repo_id) == NULL) {
        rc = seaf_db_statement_query (mgr->seaf->db,
                                      "INSERT INTO WebAP (repo_id, access_property) VALUES (?, ?)",
                                      2, "string", repo_id, "string", ap);
    } else {
        rc = seaf_db_statement_query (mgr->seaf->db,
                                      "UPDATE WebAP SET access_property=? "
                                      "WHERE repo_id=?",
                                      2, "string", ap, "string", repo_id);
    }

    if (rc < 0) {
        seaf_warning ("DB error when set access property for repo %s, %s.\n", repo_id, ap);
        return -1;
    }
    
    return 0;
}

static gboolean
get_ap (SeafDBRow *row, void *data)
{
    char **ap = data;

    *ap = g_strdup (seaf_db_row_get_column_text (row, 0));

    return FALSE;
}

char *
seaf_repo_manager_query_access_property (SeafRepoManager *mgr, const char *repo_id)
{
    char *sql;
    char *ret = NULL;

    sql =  "SELECT access_property FROM WebAP WHERE repo_id=?";
 
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, get_ap, &ret,
                                       1, "string", repo_id) < 0) {
        seaf_warning ("DB error when get access property for repo %s.\n", repo_id);
        return NULL;
    }

    return ret;
}

/* Group repos. */

int
seaf_repo_manager_add_group_repo (SeafRepoManager *mgr,
                                  const char *repo_id,
                                  int group_id,
                                  const char *owner,
                                  const char *permission,
                                  GError **error)
{
    if (seaf_db_statement_query (mgr->seaf->db,
                                 "INSERT INTO RepoGroup (repo_id, group_id, user_name, permission) VALUES (?, ?, ?, ?)",
                                 4, "string", repo_id, "int", group_id,
                                 "string", owner, "string", permission) < 0)
        return -1;

    return 0;
}

int
seaf_repo_manager_del_group_repo (SeafRepoManager *mgr,
                                  const char *repo_id,
                                  int group_id,
                                  GError **error)
{
    return seaf_db_statement_query (mgr->seaf->db,
                                    "DELETE FROM RepoGroup WHERE group_id=? "
                                    "AND repo_id=?",
                                    2, "int", group_id, "string", repo_id);
}

static gboolean
get_group_ids_cb (SeafDBRow *row, void *data)
{
    GList **plist = data;

    int group_id = seaf_db_row_get_column_int (row, 0);

    *plist = g_list_prepend (*plist, (gpointer)(long)group_id);

    return TRUE;
}

GList *
seaf_repo_manager_get_groups_by_repo (SeafRepoManager *mgr,
                                      const char *repo_id,
                                      GError **error)
{
    char *sql;
    GList *group_ids = NULL;
    
    sql =  "SELECT group_id FROM RepoGroup WHERE repo_id = ?";
    
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, get_group_ids_cb,
                                       &group_ids, 1, "string", repo_id) < 0) {
        g_list_free (group_ids);
        return NULL;
    }

    return g_list_reverse (group_ids);
}

static gboolean
get_group_perms_cb (SeafDBRow *row, void *data)
{
    GList **plist = data;
    GroupPerm *perm = g_new0 (GroupPerm, 1);

    perm->group_id = seaf_db_row_get_column_int (row, 0);
    const char *permission = seaf_db_row_get_column_text(row, 1);
    g_strlcpy (perm->permission, permission, sizeof(perm->permission));

    *plist = g_list_prepend (*plist, perm);

    return TRUE;
}

GList *
seaf_repo_manager_get_group_perm_by_repo (SeafRepoManager *mgr,
                                          const char *repo_id,
                                          GError **error)
{
    char *sql;
    GList *group_perms = NULL, *p;
    
    sql = "SELECT group_id, permission FROM RepoGroup WHERE repo_id = ?";
    
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, get_group_perms_cb,
                                       &group_perms, 1, "string", repo_id) < 0) {
        for (p = group_perms; p != NULL; p = p->next)
            g_free (p->data);
        g_list_free (group_perms);
        return NULL;
    }

    return g_list_reverse (group_perms);
}

int
seaf_repo_manager_set_group_repo_perm (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       int group_id,
                                       const char *permission,
                                       GError **error)
{
    return seaf_db_statement_query (mgr->seaf->db,
                                    "UPDATE RepoGroup SET permission=? WHERE "
                                    "repo_id=? AND group_id=?",
                                    3, "string", permission, "string", repo_id,
                                    "int", group_id);
}

int
seaf_repo_manager_set_subdir_group_perm_by_path (SeafRepoManager *mgr,
                                                 const char *repo_id,
                                                 const char *username,
                                                 int group_id,
                                                 const char *permission,
                                                 const char *path)
{
    return seaf_db_statement_query (mgr->seaf->db,
                                    "UPDATE RepoGroup SET permission=? WHERE repo_id IN "
                                    "(SELECT repo_id FROM VirtualRepo WHERE origin_repo=? AND path=?) "
                                    "AND group_id=? AND user_name=?",
                                    5, "string", permission,
                                    "string", repo_id,
                                    "string", path,
                                    "int", group_id,
                                    "string", username);
}
static gboolean
get_group_repoids_cb (SeafDBRow *row, void *data)
{
    GList **p_list = data;

    char *repo_id = g_strdup ((const char *)seaf_db_row_get_column_text (row, 0));

    *p_list = g_list_prepend (*p_list, repo_id);

    return TRUE;
}

GList *
seaf_repo_manager_get_group_repoids (SeafRepoManager *mgr,
                                     int group_id,
                                     GError **error)
{
    char *sql;
    GList *repo_ids = NULL;

    sql =  "SELECT repo_id FROM RepoGroup WHERE group_id = ?";
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, get_group_repoids_cb,
                                       &repo_ids, 1, "int", group_id) < 0)
        return NULL;

    return g_list_reverse (repo_ids);
}

static gboolean
get_group_repos_cb (SeafDBRow *row, void *data)
{
    GList **p_list = data;
    SeafileRepo *srepo = NULL;

    const char *repo_id = seaf_db_row_get_column_text (row, 0);
    const char *vrepo_id = seaf_db_row_get_column_text (row, 1);
    int group_id = seaf_db_row_get_column_int (row, 2);
    const char *user_name = seaf_db_row_get_column_text (row, 3);
    const char *permission = seaf_db_row_get_column_text (row, 4);
    const char *commit_id = seaf_db_row_get_column_text (row, 5);
    gint64 size = seaf_db_row_get_column_int64 (row, 6);
    const char *repo_name = seaf_db_row_get_column_text (row, 9);
    gint64 update_time = seaf_db_row_get_column_int64 (row, 10);
    int version = seaf_db_row_get_column_int (row, 11);
    gboolean is_encrypted = seaf_db_row_get_column_int (row, 12) ? TRUE : FALSE;
    const char *last_modifier = seaf_db_row_get_column_text (row, 13);
    int status = seaf_db_row_get_column_int (row, 14);
    const char *type = seaf_db_row_get_column_text (row, 15);

    char *user_name_l = g_ascii_strdown (user_name, -1);

    srepo = g_object_new (SEAFILE_TYPE_REPO,
                          "share_type", "group",
                          "repo_id", repo_id,
                          "id", repo_id,
                          "head_cmmt_id", commit_id,
                          "group_id", group_id,
                          "user", user_name_l,
                          "permission", permission,
                          "is_virtual", (vrepo_id != NULL),
                          "size", size,
                          "status", status,
                          NULL);
    g_free (user_name_l);

    if (srepo != NULL) {
        if (vrepo_id) {
            const char *origin_repo_id = seaf_db_row_get_column_text (row, 7);
            const char *origin_path = seaf_db_row_get_column_text (row, 8);
            const char *origin_repo_name = seaf_db_row_get_column_text (row, 16);
            g_object_set (srepo, "store_id", origin_repo_id,
                          "origin_repo_id", origin_repo_id,
                          "origin_repo_name", origin_repo_name,
                          "origin_path", origin_path, NULL);
        } else {
            g_object_set (srepo, "store_id", repo_id, NULL);
        }
        if (repo_name) {
            g_object_set (srepo, "name", repo_name,
                          "repo_name", repo_name,
                          "last_modify", update_time,
                          "last_modified", update_time,
                          "version", version,
                          "encrypted", is_encrypted,
                          "last_modifier", last_modifier, NULL);
        }
        if (type) {
            g_object_set (srepo, "repo_type", type, NULL);
        }
        *p_list = g_list_prepend (*p_list, srepo);
    }

    return TRUE;
}

void
seaf_fill_repo_obj_from_commit (GList **repos)
{
    SeafileRepo *repo;
    SeafCommit *commit;
    char *repo_id;
    char *commit_id;
    char *repo_name = NULL;
    char *last_modifier = NULL;
    GList *p = *repos;
    GList *next;

    while (p) {
        repo = p->data;
        g_object_get (repo, "name", &repo_name, NULL);
        g_object_get (repo, "last_modifier", &last_modifier, NULL);
        if (!repo_name || !last_modifier) {
            g_object_get (repo, "repo_id", &repo_id, "head_cmmt_id", &commit_id, NULL);
            commit = seaf_commit_manager_get_commit_compatible (seaf->commit_mgr,
                                                                repo_id, commit_id);
            if (!commit) {
                seaf_warning ("Commit %s not found in repo %s\n", commit_id, repo_id);
                g_object_unref (repo);
                next = p->next;
                *repos = g_list_delete_link (*repos, p);
                p = next;
                if (repo_name)
                    g_free (repo_name);
                if (last_modifier)
                    g_free (last_modifier);
            } else {
                g_object_set (repo, "name", commit->repo_name,
                              "repo_name", commit->repo_name,
                              "last_modify", commit->ctime,
                              "last_modified", commit->ctime,
                              "version", commit->version,
                              "encrypted", commit->encrypted,
                              "last_modifier", commit->creator_name,
                              NULL);

                /* Set to database */
                set_repo_commit_to_db (repo_id, commit->repo_name, commit->ctime, commit->version,
                                       commit->encrypted, commit->creator_name);
                seaf_commit_unref (commit);
            }
            g_free (repo_id);
            g_free (commit_id);
        }
        if (repo_name)
            g_free (repo_name);
        if (last_modifier)
            g_free (last_modifier);

        p = p->next;
    }
}

GList *
seaf_repo_manager_get_repos_by_group (SeafRepoManager *mgr,
                                      int group_id,
                                      GError **error)
{
    char *sql;
    GList *repos = NULL;
    GList *p;

    sql = "SELECT RepoGroup.repo_id, v.repo_id, "
        "group_id, user_name, permission, commit_id, s.size, "
        "v.origin_repo, v.path, i.name, "
        "i.update_time, i.version, i.is_encrypted, i.last_modifier, i.status, i.type, i2.name "
        "FROM RepoGroup LEFT JOIN VirtualRepo v ON "
        "RepoGroup.repo_id = v.repo_id "
        "LEFT JOIN RepoInfo i ON RepoGroup.repo_id = i.repo_id "
        "LEFT JOIN RepoInfo i2 ON v.origin_repo = i2.repo_id "
        "LEFT JOIN RepoSize s ON RepoGroup.repo_id = s.repo_id, "
        "Branch WHERE group_id = ? AND "
        "RepoGroup.repo_id = Branch.repo_id AND "
        "Branch.name = 'master'";

    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, get_group_repos_cb,
                                       &repos, 1, "int", group_id) < 0) {
        for (p = repos; p; p = p->next) {
            g_object_unref (p->data);
        }
        g_list_free (repos);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to get repos by group from db.");
        return NULL;
    }

    seaf_fill_repo_obj_from_commit (&repos);

    return g_list_reverse (repos);
}

GList *
seaf_repo_manager_get_group_repos_by_owner (SeafRepoManager *mgr,
                                            const char *owner,
                                            GError **error)
{
    char *sql;
    GList *repos = NULL;
    GList *p;

    sql = "SELECT RepoGroup.repo_id, v.repo_id, "
        "group_id, user_name, permission, commit_id, s.size, "
        "v.origin_repo, v.path, i.name, "
        "i.update_time, i.version, i.is_encrypted, i.last_modifier, i.status, i.type, i2.name "
        "FROM RepoGroup LEFT JOIN VirtualRepo v ON "
        "RepoGroup.repo_id = v.repo_id "
        "LEFT JOIN RepoInfo i ON RepoGroup.repo_id = i.repo_id "
        "LEFT JOIN RepoInfo i2 ON v.origin_repo = i2.repo_id "
        "LEFT JOIN RepoSize s ON RepoGroup.repo_id = s.repo_id, "
        "Branch WHERE user_name = ? AND "
        "RepoGroup.repo_id = Branch.repo_id AND "
        "Branch.name = 'master'";
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, get_group_repos_cb,
                                       &repos, 1, "string", owner) < 0) {
        for (p = repos; p; p = p->next) {
            g_object_unref (p->data);
        }
        g_list_free (repos);
        return NULL;
    }

    seaf_fill_repo_obj_from_commit (&repos);

    return g_list_reverse (repos);
}

static gboolean
get_group_repo_owner (SeafDBRow *row, void *data)
{
    char **share_from = data;

    const char *owner = (const char *) seaf_db_row_get_column_text (row, 0);
    *share_from = g_ascii_strdown (owner, -1);
    /* There should be only one result. */
    return FALSE;
}

char *
seaf_repo_manager_get_group_repo_owner (SeafRepoManager *mgr,
                                        const char *repo_id,
                                        GError **error)
{
    char *sql;
    char *ret = NULL;

    sql = "SELECT user_name FROM RepoGroup WHERE repo_id = ?";
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                       get_group_repo_owner, &ret,
                                       1, "string", repo_id) < 0) {
        seaf_warning ("DB error when get repo share from for repo %s.\n",
                   repo_id);
        return NULL;
    }

    return ret;
}

int
seaf_repo_manager_remove_group_repos (SeafRepoManager *mgr,
                                      int group_id,
                                      const char *owner,
                                      GError **error)
{
    SeafDB *db = mgr->seaf->db;
    int rc;

    if (!owner) {
        rc = seaf_db_statement_query (db, "DELETE FROM RepoGroup WHERE group_id=?",
                                      1, "int", group_id);
    } else {
        rc = seaf_db_statement_query (db,
                                      "DELETE FROM RepoGroup WHERE group_id=? AND "
                                      "user_name = ?",
                                      2, "int", group_id, "string", owner);
    }

    return rc;
}

/* Inner public repos */

int
seaf_repo_manager_set_inner_pub_repo (SeafRepoManager *mgr,
                                      const char *repo_id,
                                      const char *permission)
{
    SeafDB *db = mgr->seaf->db;
    char sql[256];

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL) {
        gboolean err;
        snprintf(sql, sizeof(sql),
                 "SELECT repo_id FROM InnerPubRepo WHERE repo_id=?");
        if (seaf_db_statement_exists (db, sql, &err,
                                      1, "string", repo_id))
            snprintf(sql, sizeof(sql),
                     "UPDATE InnerPubRepo SET permission='%s' "
                     "WHERE repo_id='%s'", permission, repo_id);
        else
            snprintf(sql, sizeof(sql),
                     "INSERT INTO InnerPubRepo (repo_id, permission) VALUES "
                     "('%s', '%s')", repo_id, permission);
        if (err)
            return -1;
        return seaf_db_query (db, sql);
    } else {
        return seaf_db_statement_query (db,
                                        "REPLACE INTO InnerPubRepo (repo_id, permission) VALUES (?, ?)",
                                        2, "string", repo_id, "string", permission);
    }

    return -1;
}

int
seaf_repo_manager_unset_inner_pub_repo (SeafRepoManager *mgr,
                                        const char *repo_id)
{
    return seaf_db_statement_query (mgr->seaf->db,
                                    "DELETE FROM InnerPubRepo WHERE repo_id = ?",
                                    1, "string", repo_id);
}

gboolean
seaf_repo_manager_is_inner_pub_repo (SeafRepoManager *mgr,
                                     const char *repo_id)
{
    gboolean db_err = FALSE;

    return seaf_db_statement_exists (mgr->seaf->db,
                                     "SELECT repo_id FROM InnerPubRepo WHERE repo_id=?",
                                     &db_err, 1, "string", repo_id);
}

static gboolean
collect_public_repos (SeafDBRow *row, void *data)
{
    GList **ret = (GList **)data;
    SeafileRepo *srepo;
    const char *repo_id, *vrepo_id, *owner, *permission, *commit_id;
    gint64 size;

    repo_id = seaf_db_row_get_column_text (row, 0);
    vrepo_id = seaf_db_row_get_column_text (row, 1);
    owner = seaf_db_row_get_column_text (row, 2);
    permission = seaf_db_row_get_column_text (row, 3);
    commit_id = seaf_db_row_get_column_text (row, 4);
    size = seaf_db_row_get_column_int64 (row, 5);
    const char *repo_name = seaf_db_row_get_column_text (row, 8);
    gint64 update_time = seaf_db_row_get_column_int64 (row, 9);
    int version = seaf_db_row_get_column_int (row, 10);
    gboolean is_encrypted = seaf_db_row_get_column_int (row, 11) ? TRUE : FALSE;
    const char *last_modifier = seaf_db_row_get_column_text (row, 12);
    int status = seaf_db_row_get_column_int (row, 13);
    const char *type = seaf_db_row_get_column_text (row, 14);

    char *owner_l = g_ascii_strdown (owner, -1);

    srepo = g_object_new (SEAFILE_TYPE_REPO,
                          "share_type", "public",
                          "repo_id", repo_id,
                          "id", repo_id,
                          "head_cmmt_id", commit_id,
                          "permission", permission,
                          "user", owner_l,
                          "is_virtual", (vrepo_id != NULL),
                          "size", size,
                          "status", status,
                          NULL);
    g_free (owner_l);

    if (srepo) {
        if (vrepo_id) {
            const char *origin_repo_id = seaf_db_row_get_column_text (row, 6);
            const char *origin_path = seaf_db_row_get_column_text (row, 7);
            g_object_set (srepo, "store_id", origin_repo_id,
                          "origin_repo_id", origin_repo_id,
                          "origin_path", origin_path, NULL);
        } else {
            g_object_set (srepo, "store_id", repo_id, NULL);
        }

        if (repo_name) {
            g_object_set (srepo, "name", repo_name,
                          "repo_name", repo_name,
                          "last_modify", update_time,
                          "last_modified", update_time,
                          "version", version,
                          "encrypted", is_encrypted,
                          "last_modifier", last_modifier, NULL);
        }
        if (type) {
            g_object_set (srepo, "repo_type", type, NULL);
        }

        *ret = g_list_prepend (*ret, srepo);
    }

    return TRUE;
}

GList *
seaf_repo_manager_list_inner_pub_repos (SeafRepoManager *mgr, gboolean *db_err)
{
    GList *ret = NULL, *p;
    char *sql;

    sql = "SELECT InnerPubRepo.repo_id, VirtualRepo.repo_id, "
        "owner_id, permission, commit_id, s.size, "
        "VirtualRepo.origin_repo, VirtualRepo.path, i.name, "
        "i.update_time, i.version, i.is_encrypted, i.last_modifier, i.status, i.type "
        "FROM InnerPubRepo LEFT JOIN VirtualRepo ON "
        "InnerPubRepo.repo_id=VirtualRepo.repo_id "
        "LEFT JOIN RepoInfo i ON InnerPubRepo.repo_id = i.repo_id "
        "LEFT JOIN RepoSize s ON InnerPubRepo.repo_id = s.repo_id, RepoOwner, Branch "
        "WHERE InnerPubRepo.repo_id=RepoOwner.repo_id AND "
        "InnerPubRepo.repo_id = Branch.repo_id AND Branch.name = 'master'";

    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                       collect_public_repos, &ret,
                                       0) < 0) {
        for (p = ret; p != NULL; p = p->next)
            g_object_unref (p->data);
        g_list_free (ret);
        if (db_err)
            *db_err = TRUE;
        return NULL;
    }

    seaf_fill_repo_obj_from_commit (&ret);

    return g_list_reverse (ret);
}

gint64
seaf_repo_manager_count_inner_pub_repos (SeafRepoManager *mgr)
{
    char sql[256];

    snprintf (sql, 256, "SELECT COUNT(*) FROM InnerPubRepo");

    return seaf_db_get_int64(mgr->seaf->db, sql);
}

GList *
seaf_repo_manager_list_inner_pub_repos_by_owner (SeafRepoManager *mgr,
                                                 const char *user)
{
    GList *ret = NULL, *p;
    char *sql;

    sql = "SELECT InnerPubRepo.repo_id, VirtualRepo.repo_id, "
        "owner_id, permission, commit_id, s.size, "
        "VirtualRepo.origin_repo, VirtualRepo.path, i.name, "
        "i.update_time, i.version, i.is_encrypted, i.last_modifier, i.status, i.type "
        "FROM InnerPubRepo LEFT JOIN VirtualRepo ON "
        "InnerPubRepo.repo_id=VirtualRepo.repo_id "
        "LEFT JOIN RepoInfo i ON InnerPubRepo.repo_id = i.repo_id "
        "LEFT JOIN RepoSize s ON InnerPubRepo.repo_id = s.repo_id, RepoOwner, Branch "
        "WHERE InnerPubRepo.repo_id=RepoOwner.repo_id AND owner_id=? "
        "AND InnerPubRepo.repo_id = Branch.repo_id AND Branch.name = 'master'";

    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                       collect_public_repos, &ret,
                                       1, "string", user) < 0) {
        for (p = ret; p != NULL; p = p->next)
            g_object_unref (p->data);
        g_list_free (ret);
        return NULL;
    }

    seaf_fill_repo_obj_from_commit (&ret);

    return g_list_reverse (ret);
}

char *
seaf_repo_manager_get_inner_pub_repo_perm (SeafRepoManager *mgr,
                                           const char *repo_id)
{
    char *sql;

    sql = "SELECT permission FROM InnerPubRepo WHERE repo_id=?";
    return seaf_db_statement_get_string(mgr->seaf->db, sql, 1, "string", repo_id);
}


int
seaf_repo_manager_is_valid_filename (SeafRepoManager *mgr,
                                     const char *repo_id,
                                     const char *filename,
                                     GError **error)
{
    if (should_ignore_file(filename, NULL))
        return 0;
    else
        return 1;
}

typedef struct _RepoCryptCompat {
    const char *magic;
    const char *pwd_hash;
    const char *pwd_hash_algo;
    const char *pwd_hash_params;
} RepoCryptInfo;

static
RepoCryptInfo *
repo_crypt_info_new (const char *magic, const char *pwd_hash,
                       const char *algo, const char *params)
{
    RepoCryptInfo *crypt_info = g_new0 (RepoCryptInfo, 1);
    crypt_info->magic = magic;
    crypt_info->pwd_hash = pwd_hash;
    crypt_info->pwd_hash_algo = algo;
    crypt_info->pwd_hash_params = params;

    return crypt_info;
}

static int
create_repo_common (SeafRepoManager *mgr,
                    const char *repo_id,
                    const char *repo_name,
                    const char *repo_desc,
                    const char *user,
                    const char *random_key,
                    const char *salt,
                    int enc_version,
                    RepoCryptInfo *crypt_info,
                    GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *commit = NULL;
    SeafBranch *master = NULL;
    int ret = -1;

    if (enc_version != 4 && enc_version != 3 && enc_version != 2 && enc_version != -1) {
        seaf_warning ("Unsupported enc version %d.\n", enc_version);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Unsupported encryption version");
        return -1;
    }
    
    if (crypt_info && crypt_info->pwd_hash_algo) {
        if (g_strcmp0 (crypt_info->pwd_hash_algo, PWD_HASH_PDKDF2) != 0 &&
            g_strcmp0 (crypt_info->pwd_hash_algo, PWD_HASH_ARGON2ID) !=0)
        {
            seaf_warning ("Unsupported enc algothrims %s.\n", crypt_info->pwd_hash_algo);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                         "Unsupported encryption algothrims");
            return -1;
        }

        if (!crypt_info->pwd_hash || strlen(crypt_info->pwd_hash) != 64) {
            seaf_warning ("Bad pwd_hash.\n");
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                         "Bad pwd_hash");
            return -1;
        }
    }

    if (enc_version >= 2) {
        if (!crypt_info->pwd_hash_algo && (!crypt_info->magic || strlen(crypt_info->magic) != 64)) {
            seaf_warning ("Bad magic.\n");
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                         "Bad magic");
            return -1;
        }
        if (!random_key || strlen(random_key) != 96) {
            seaf_warning ("Bad random key.\n");
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                         "Bad random key");
            return -1;
        }
    }
    if (enc_version >= 3) {
        if (!salt || strlen(salt) != 64) {
            seaf_warning ("Bad salt.\n");
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                         "Bad salt");
            return -1;
        }
    }

    repo = seaf_repo_new (repo_id, repo_name, repo_desc);

    repo->no_local_history = TRUE;

    if (enc_version >= 2) {
        repo->encrypted = TRUE;
        repo->enc_version = enc_version;
        if (!crypt_info->pwd_hash_algo)
            memcpy (repo->magic, crypt_info->magic, 64);
        memcpy (repo->random_key, random_key, 96);
    }
    if (enc_version >= 3)
        memcpy (repo->salt, salt, 64);

    if (crypt_info && crypt_info->pwd_hash_algo) {
        // set pwd_hash fields here.
        memcpy (repo->pwd_hash, crypt_info->pwd_hash, 64);
        repo->pwd_hash_algo = g_strdup (crypt_info->pwd_hash_algo);
        repo->pwd_hash_params = g_strdup (crypt_info->pwd_hash_params);
    }

    repo->version = CURRENT_REPO_VERSION;
    memcpy (repo->store_id, repo_id, 36);

    commit = seaf_commit_new (NULL, repo->id,
                              EMPTY_SHA1, /* root id */
                              user, /* creator */
                              EMPTY_SHA1, /* creator id */
                              "Created library",  /* description */
                              0);         /* ctime */

    seaf_repo_to_commit (repo, commit);
    if (seaf_commit_manager_add_commit (seaf->commit_mgr, commit) < 0) {
        seaf_warning ("Failed to add commit.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to add commit");
        goto out;
    }

    master = seaf_branch_new ("master", repo->id, commit->commit_id);
    if (seaf_branch_manager_add_branch (seaf->branch_mgr, master) < 0) {
        seaf_warning ("Failed to add branch.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to add branch");
        goto out;
    }

    if (seaf_repo_set_head (repo, master) < 0) {
        seaf_warning ("Failed to set repo head.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to set repo head.");
        goto out;
    }

    if (seaf_repo_manager_add_repo (mgr, repo) < 0) {
        seaf_warning ("Failed to add repo.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to add repo.");
        goto out;
    }

    seaf_repo_manager_update_repo_info (mgr, repo->id, repo->head->commit_id);

    ret = 0;
out:
    if (repo)
        seaf_repo_unref (repo);
    if (commit)
        seaf_commit_unref (commit);
    if (master)
        seaf_branch_unref (master);
    
    return ret;    
}

char *
seaf_repo_manager_create_new_repo (SeafRepoManager *mgr,
                                   const char *repo_name,
                                   const char *repo_desc,
                                   const char *owner_email,
                                   const char *passwd,
                                   int enc_version,
                                   const char *pwd_hash_algo,
                                   const char *pwd_hash_params,
                                   GError **error)
{
    char *repo_id = NULL;
    char salt[65], magic[65], pwd_hash[65], random_key[97];
    const char *algo = pwd_hash_algo;
    const char *params = pwd_hash_params;

    repo_id = gen_uuid ();

    if (passwd && passwd[0] != 0) {
        if (seafile_generate_repo_salt (salt) < 0) {
            goto bad;
        }
        if (algo != NULL) {
            seafile_generate_pwd_hash (enc_version, repo_id, passwd, salt, algo, params, pwd_hash);
        } else {
            seafile_generate_magic (enc_version, repo_id, passwd, salt, magic);
        }
        if (seafile_generate_random_key (passwd, enc_version, salt, random_key) < 0) {
            goto bad;
        }
    }

    int rc;
    if (passwd) {
        RepoCryptInfo *crypt_info = repo_crypt_info_new (magic, pwd_hash, algo, params);
        rc = create_repo_common (mgr, repo_id, repo_name, repo_desc, owner_email,
                                 random_key, salt, enc_version, crypt_info, error);
        g_free (crypt_info);
    }
    else
        rc = create_repo_common (mgr, repo_id, repo_name, repo_desc, owner_email,
                                 NULL, NULL, -1, NULL, error);
    if (rc < 0)
        goto bad;

    if (seaf_repo_manager_set_repo_owner (mgr, repo_id, owner_email) < 0) {
        seaf_warning ("Failed to set repo owner.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to set repo owner.");
        goto bad;
    }

    return repo_id;
    
bad:
    if (repo_id)
        g_free (repo_id);
    return NULL;
}

char *
seaf_repo_manager_create_enc_repo (SeafRepoManager *mgr,
                                   const char *repo_id,
                                   const char *repo_name,
                                   const char *repo_desc,
                                   const char *owner_email,
                                   const char *magic,
                                   const char *random_key,
                                   const char *salt,
                                   int enc_version,
                                   const char *pwd_hash,
                                   const char *pwd_hash_algo,
                                   const char *pwd_hash_params,
                                   GError **error)
{
    if (!repo_id || !is_uuid_valid (repo_id)) {
        seaf_warning ("Invalid repo_id.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid repo id");
        return NULL;
    }

    if (seaf_repo_manager_repo_exists (mgr, repo_id)) {
        seaf_warning ("Repo %s exists, refuse to create.\n", repo_id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Repo already exists");
        return NULL;
    }

    RepoCryptInfo *crypt_info = repo_crypt_info_new (magic, pwd_hash, pwd_hash_algo, pwd_hash_params);
    if (create_repo_common (mgr, repo_id, repo_name, repo_desc, owner_email,
                            random_key, salt, enc_version, crypt_info, error) < 0) {
        g_free (crypt_info);
        return NULL;
    }
    g_free (crypt_info);

    if (seaf_repo_manager_set_repo_owner (mgr, repo_id, owner_email) < 0) {
        seaf_warning ("Failed to set repo owner.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to set repo owner.");
        return NULL;
    }

    return g_strdup (repo_id);
}

static int reap_token (void *data)
{
    SeafRepoManager *mgr = data;
    GHashTableIter iter;
    gpointer key, value;
    DecryptedToken *t;

    pthread_rwlock_wrlock (&mgr->priv->lock);

    gint64 now = (gint64)time(NULL);

    g_hash_table_iter_init (&iter, mgr->priv->decrypted_tokens);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        t = value;
        if (now >= t->reap_time)
            g_hash_table_iter_remove (&iter);
    }

    pthread_rwlock_unlock (&mgr->priv->lock);

    return TRUE;
}

static void decrypted_token_free (DecryptedToken *token)
{
    if (!token)
        return;
    g_free (token->token);
    g_free (token);
}

void
seaf_repo_manager_add_decrypted_token (SeafRepoManager *mgr,
                                       const char *encrypted_token,
                                       const char *session_key,
                                       const char *decrypted_token)
{
    char key[256];
    DecryptedToken *token;

    snprintf (key, sizeof(key), "%s%s", encrypted_token, session_key);
    key[255] = 0;

    pthread_rwlock_wrlock (&mgr->priv->lock);

    token = g_new0 (DecryptedToken, 1);
    token->token = g_strdup(decrypted_token);
    token->reap_time = (gint64)time(NULL) + DECRYPTED_TOKEN_TTL;

    g_hash_table_insert (mgr->priv->decrypted_tokens,
                         g_strdup(key),
                         token);

    pthread_rwlock_unlock (&mgr->priv->lock);
}

char *
seaf_repo_manager_get_decrypted_token (SeafRepoManager *mgr,
                                       const char *encrypted_token,
                                       const char *session_key)
{
    char key[256];
    DecryptedToken *token;

    snprintf (key, sizeof(key), "%s%s", encrypted_token, session_key);
    key[255] = 0;

    pthread_rwlock_rdlock (&mgr->priv->lock);
    token = g_hash_table_lookup (mgr->priv->decrypted_tokens, key);
    pthread_rwlock_unlock (&mgr->priv->lock);

    if (token)
        return g_strdup(token->token);
    return NULL;
}

static gboolean
get_shared_users (SeafDBRow *row, void *data)
{
    GList **shared_users = data;
    const char *user = seaf_db_row_get_column_text (row, 0);
    const char *perm = seaf_db_row_get_column_text (row, 1);
    const char *repo_id = seaf_db_row_get_column_text (row, 2);

    SeafileSharedUser *uobj = g_object_new (SEAFILE_TYPE_SHARED_USER,
                                            "repo_id", repo_id,
                                            "user", user,
                                            "perm", perm,
                                            NULL);
    *shared_users = g_list_prepend (*shared_users, uobj);

    return TRUE;
}

GList *
seaf_repo_manager_get_shared_users_for_subdir (SeafRepoManager *mgr,
                                               const char *repo_id,
                                               const char *path,
                                               const char *from_user,
                                               GError **error)
{
    GList *shared_users = NULL;
    int ret = seaf_db_statement_foreach_row (mgr->seaf->db,
                                             "SELECT to_email, permission, v.repo_id "
                                             "FROM SharedRepo s, VirtualRepo v "
                                             "WHERE s.repo_id = v.repo_id AND v.origin_repo = ? "
                                             "AND v.path = ? AND s.from_email = ?",
                                             get_shared_users, &shared_users, 3, "string", repo_id,
                                             "string", path, "string", from_user);
    if (ret < 0) {
        seaf_warning ("Failed to get shared users for %.8s(%s).\n", repo_id, path);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to get shared users for subdir from db");
        while (shared_users) {
            g_object_unref (shared_users->data);
            shared_users = g_list_delete_link (shared_users, shared_users);
        }
        return NULL;
    }

    return shared_users;
}

static gboolean
get_shared_groups (SeafDBRow *row, void *data)
{
    GList **shared_groups = data;
    int group = seaf_db_row_get_column_int (row, 0);
    const char *perm = seaf_db_row_get_column_text (row, 1);
    const char *repo_id = seaf_db_row_get_column_text (row, 2);

    SeafileSharedGroup *gobj = g_object_new (SEAFILE_TYPE_SHARED_GROUP,
                                             "repo_id", repo_id,
                                             "group_id", group,
                                             "perm", perm,
                                             NULL);

    *shared_groups = g_list_prepend (*shared_groups, gobj);

    return TRUE;
}

GList *
seaf_repo_manager_get_shared_groups_for_subdir (SeafRepoManager *mgr,
                                                const char *repo_id,
                                                const char *path,
                                                const char *from_user,
                                                GError **error)
{
    GList *shared_groups = NULL;
    int ret = seaf_db_statement_foreach_row (mgr->seaf->db,
                                             "SELECT group_id, permission, v.repo_id "
                                             "FROM RepoGroup r, VirtualRepo v "
                                             "WHERE r.repo_id = v.repo_id AND v.origin_repo = ? "
                                             "AND v.path = ? AND r.user_name = ?",
                                             get_shared_groups, &shared_groups, 3, "string", repo_id,
                                             "string", path, "string", from_user);
    if (ret < 0) {
        seaf_warning ("Failed to get shared groups for %.8s(%s).\n", repo_id, path);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to get shared groups fro subdir from db");
        while (shared_groups) {
            g_object_unref (shared_groups->data);
            shared_groups = g_list_delete_link (shared_groups, shared_groups);
        }
        return NULL;
    }

    return shared_groups;
}
int
seaf_repo_manager_edit_repo (const char *repo_id,
                             const char *name,
                             const char *description,
                             const char *user,
                             GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *commit = NULL, *parent = NULL;
    int ret = 0;

    if (!name && !description) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "At least one argument should be non-null");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

retry:
    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "No such library");
        return -1;
    }
    if (!name)
        name = repo->name;
    if (!description)
        description = repo->desc;

    /*
     * We only change repo_name or repo_desc, so just copy the head commit
     * and change these two fields.
     */
    parent = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             repo->id, repo->version,
                                             repo->head->commit_id);
    if (!parent) {
        seaf_warning ("Failed to get commit %s:%s.\n",
                      repo->id, repo->head->commit_id);
        ret = -1;
        goto out;
    }
    if (!user) {
        user = parent->creator_name;
    }

    commit = seaf_commit_new (NULL,
                              repo->id,
                              parent->root_id,
                              user,
                              EMPTY_SHA1,
                              "Changed library name or description",
                              0);
    commit->parent_id = g_strdup(parent->commit_id);
    seaf_repo_to_commit (repo, commit);

    g_free (commit->repo_name);
    commit->repo_name = g_strdup(name);
    g_free (commit->repo_desc);
    commit->repo_desc = g_strdup(description);

    if (seaf_commit_manager_add_commit (seaf->commit_mgr, commit) < 0) {
        ret = -1;
        goto out;
    }

    seaf_branch_set_commit (repo->head, commit->commit_id);
    if (seaf_branch_manager_test_and_update_branch (seaf->branch_mgr,
                                                    repo->head,
                                                    parent->commit_id,
                                                    FALSE, NULL, NULL, NULL) < 0) {
        seaf_repo_unref (repo);
        seaf_commit_unref (commit);
        seaf_commit_unref (parent);
        repo = NULL;
        commit = NULL;
        parent = NULL;
        goto retry;
    }

    seaf_repo_manager_update_repo_info (seaf->repo_mgr, repo_id, repo->head->commit_id);

out:
    seaf_commit_unref (commit);
    seaf_commit_unref (parent);
    seaf_repo_unref (repo);

    return ret;
}

gboolean
get_total_file_number_cb (SeafDBRow *row, void *vdata)
{
    gint64 *data = (gint64 *)vdata;
    gint64 count = seaf_db_row_get_column_int64 (row, 0);
    *data = count;

    return FALSE;
}

gint64
seaf_get_total_file_number (GError **error)
{
    gint64 count = 0;
    int ret = seaf_db_statement_foreach_row (seaf->db,
                                             "SELECT SUM(file_count) FROM RepoFileCount f "
                                             "LEFT JOIN VirtualRepo v "
                                             "ON f.repo_id=v.repo_id,"
                                             "Repo r "
                                             "WHERE v.repo_id IS NULL AND "
                                             "f.repo_id=r.repo_id",
                                             get_total_file_number_cb,
                                             &count, 0);
    if (ret < 0) { 
        seaf_warning ("Failed to get total file number.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to get total file number from db.");
        return -1;
    }

    return count;
}

gboolean
get_total_storage_cb(SeafDBRow *row, void *vdata)
{
    gint64 *data = (gint64 *)vdata;
    gint64 size = seaf_db_row_get_column_int64 (row, 0);
    *data = size;

    return FALSE;
}

gint64
seaf_get_total_storage (GError **error)
{
    gint64 size = 0;
    int ret;
    if (seaf_db_type(seaf->db) == SEAF_DB_TYPE_PGSQL) {
        ret = seaf_db_statement_foreach_row (seaf->db,
                                             "SELECT SUM(\"size\") FROM RepoSize s "
                                             "LEFT JOIN VirtualRepo v "
                                             "ON s.repo_id=v.repo_id "
                                             "WHERE v.repo_id IS NULL",
                                             get_total_storage_cb,
                                             &size, 0);
    } else {
        ret = seaf_db_statement_foreach_row (seaf->db,
                                             "SELECT SUM(size) FROM RepoSize s "
                                             "LEFT JOIN VirtualRepo v "
                                             "ON s.repo_id=v.repo_id "
                                             "WHERE v.repo_id IS NULL",
                                             get_total_storage_cb,
                                             &size, 0);
    }
    if (ret < 0) {
        seaf_warning ("Failed to get total storage occupation.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to get total storage occupation from db.");
        return -1;
    }

    return size;
}

/* Online GC related */

char *
seaf_repo_get_current_gc_id (SeafRepo *repo)
{
    if (seaf_db_type(seaf->db) == SEAF_DB_TYPE_SQLITE)
        return NULL;

    char *sql = "SELECT gc_id FROM GCID WHERE repo_id = ?";
    char *gc_id;

    if (!repo->virtual_info)
        gc_id = seaf_db_statement_get_string (seaf->db, sql, 1, "string", repo->id);
    else {
        gc_id = seaf_db_statement_get_string (seaf->db, sql, 1, "string", repo->store_id);
    }

    return gc_id;
}

char *
seaf_repo_get_last_gc_id (SeafRepo *repo, const char *client_id)
{
    if (seaf_db_type(seaf->db) == SEAF_DB_TYPE_SQLITE)
        return NULL;

    char *sql = "SELECT gc_id FROM LastGCID WHERE repo_id = ? AND client_id = ?";
    char *gc_id;

    gc_id = seaf_db_statement_get_string (seaf->db, sql,
                                          2, "string", repo->id,
                                          "string", client_id);

    return gc_id;
}

gboolean
seaf_repo_has_last_gc_id (SeafRepo *repo, const char *client_id)
{
    if (seaf_db_type(seaf->db) == SEAF_DB_TYPE_SQLITE)
        return FALSE;

    char *sql = "SELECT 1 FROM LastGCID WHERE repo_id = ? AND client_id = ?";
    gboolean db_err;

    return seaf_db_statement_exists (seaf->db, sql, &db_err,
                                     2, "string", repo->id, "string", client_id);
}

int
seaf_repo_set_last_gc_id (SeafRepo *repo,
                          const char *client_id,
                          const char *gc_id)
{
    if (seaf_db_type(seaf->db) == SEAF_DB_TYPE_SQLITE)
        return 0;

    gboolean id_exists, db_err = FALSE;
    char *sql;
    int ret = 0;

    sql = "SELECT 1 FROM LastGCID WHERE repo_id = ? AND client_id = ?";
    id_exists = seaf_db_statement_exists (seaf->db, sql, &db_err,
                                          2, "string", repo->id, "string", client_id);
    if (id_exists) {
        sql = "UPDATE LastGCID SET gc_id = ? WHERE repo_id = ? AND client_id = ?";
        ret = seaf_db_statement_query (seaf->db, sql,
                                       3, "string", gc_id,
                                       "string", repo->id, "string", client_id);
    } else {
        sql = "INSERT INTO LastGCID (repo_id, client_id, gc_id) VALUES (?, ?, ?)";
        ret = seaf_db_statement_query (seaf->db, sql,
                                       3, "string", repo->id,
                                       "string", client_id, "string", gc_id);
    }

    return ret;
}

int
seaf_repo_remove_last_gc_id (SeafRepo *repo,
                             const char *client_id)
{
    if (seaf_db_type(seaf->db) == SEAF_DB_TYPE_SQLITE)
        return 0;

    char *sql = "DELETE FROM LastGCID WHERE repo_id = ? AND client_id = ?";
    seaf_db_statement_query (seaf->db, sql, 2, "string", repo->id, "string", client_id);
    return 0;
}

int
seaf_repo_manager_add_upload_tmp_file (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       const char *file_path,
                                       const char *tmp_file,
                                       GError **error)
{
    char *file_path_with_slash = NULL;

    if (file_path[0] == '/') {
        file_path_with_slash = g_strdup(file_path);
    } else {
        file_path_with_slash = g_strconcat("/", file_path, NULL);
    }

    int ret = seaf_db_statement_query (mgr->seaf->db,
                                       "INSERT INTO WebUploadTempFiles "
                                       "(repo_id, file_path, tmp_file_path) "
                                       "VALUES (?, ?, ?)", 3, "string", repo_id,
                                       "string", file_path_with_slash, "string", tmp_file);

    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to add upload tmp file record to db.");
    }

    g_free (file_path_with_slash);
    return ret;
}

int
seaf_repo_manager_del_upload_tmp_file (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       const char *file_path,
                                       GError **error)
{
    char *file_path_with_slash = NULL, *file_path_no_slash = NULL;

    /* Due to a bug in early versions of 7.0, some file_path may be stored in the db without
     * a leading slash. To be compatible with those records, we need to check the path
     * with and without leading slash.
     */
    if (file_path[0] == '/') {
        file_path_with_slash = g_strdup(file_path);
        file_path_no_slash = g_strdup(file_path+1);
    } else {
        file_path_with_slash = g_strconcat("/", file_path, NULL);
        file_path_no_slash = g_strdup(file_path);
    }

    int ret = seaf_db_statement_query (mgr->seaf->db,
                                       "DELETE FROM WebUploadTempFiles WHERE "
                                       "repo_id = ? AND file_path IN (?, ?)",
                                       3, "string", repo_id,
                                       "string", file_path_with_slash,
                                       "string", file_path_no_slash);
    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to delete upload tmp file record from db.");
    }

    g_free (file_path_with_slash);
    g_free (file_path_no_slash);
    return ret;
}

static gboolean
get_tmp_file_path (SeafDBRow *row, void *data)
{
    char **path = data;

    *path = g_strdup (seaf_db_row_get_column_text (row, 0));

    return FALSE;
}

char *
seaf_repo_manager_get_upload_tmp_file (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       const char *file_path,
                                       GError **error)
{
    char *tmp_file_path = NULL;
    char *file_path_with_slash = NULL, *file_path_no_slash = NULL;

    /* Due to a bug in early versions of 7.0, some file_path may be stored in the db without
     * a leading slash. To be compatible with those records, we need to check the path
     * with and without leading slash.
     * The correct file_path in db should be with a leading slash.
     */
    if (file_path[0] == '/') {
        file_path_with_slash = g_strdup(file_path);
        file_path_no_slash = g_strdup(file_path+1);
    } else {
        file_path_with_slash = g_strconcat("/", file_path, NULL);
        file_path_no_slash = g_strdup(file_path);
    }

    int ret = seaf_db_statement_foreach_row (mgr->seaf->db,
                                             "SELECT tmp_file_path FROM WebUploadTempFiles "
                                             "WHERE repo_id = ? AND file_path = ?",
                                             get_tmp_file_path, &tmp_file_path,
                                             2, "string", repo_id,
                                             "string", file_path_with_slash);
    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to get upload temp file path from db.");
        goto out;
    }

    if (!tmp_file_path) {
        /* Try file_path without slash. */
        int ret = seaf_db_statement_foreach_row (mgr->seaf->db,
                                                 "SELECT tmp_file_path FROM WebUploadTempFiles "
                                                 "WHERE repo_id = ? AND file_path = ?",
                                                 get_tmp_file_path, &tmp_file_path,
                                                 2, "string", repo_id,
                                                 "string", file_path_no_slash);
        if (ret < 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Failed to get upload temp file path from db.");
            goto out;
        }
    }

out:
    g_free (file_path_with_slash);
    g_free (file_path_no_slash);
    return tmp_file_path;
}

gint64
seaf_repo_manager_get_upload_tmp_file_offset (SeafRepoManager *mgr,
                                              const char *repo_id,
                                              const char *file_path,
                                              GError **error)
{
    char *tmp_file_path = NULL;
    SeafStat file_stat;

    tmp_file_path = seaf_repo_manager_get_upload_tmp_file (mgr, repo_id,
                                                           file_path, error);
    if (*error) {
        return -1;
    }

    if (!tmp_file_path)
        return 0;

    if (seaf_stat (tmp_file_path, &file_stat) < 0) {
        if (errno == ENOENT) {
            seaf_message ("Temp file %s doesn't exist, remove reocrd from db.\n",
                          tmp_file_path);
            if (seaf_repo_manager_del_upload_tmp_file (mgr, repo_id,
                                                       file_path, error) < 0) {
                g_free (tmp_file_path);
                return -1;
            }
            return 0;
        }
        seaf_warning ("Failed to stat temp file %s: %s.\n",
                      tmp_file_path, strerror(errno));
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to stat temp file.");
        g_free (tmp_file_path);
        return -1;
    }

    g_free (tmp_file_path);

    return file_stat.st_size;
}

void
seaf_repo_manager_update_repo_info (SeafRepoManager *mgr,
                                    const char *repo_id, const char *head_commit_id)
{
    SeafCommit *head;

    head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                           repo_id, 1, head_commit_id);
    if (!head) {
        seaf_warning ("Failed to get commit %s:%s.\n", repo_id, head_commit_id);
        return;
    }

    set_repo_commit_to_db (repo_id, head->repo_name, head->ctime, head->version,
                           (head->encrypted ? 1 : 0), head->creator_name);

    seaf_commit_unref (head);
}

char *
seaf_get_trash_repo_owner (const char *repo_id)
{
    char *sql = "SELECT owner_id from RepoTrash WHERE repo_id = ?";
    return seaf_db_statement_get_string(seaf->db, sql, 1, "string", repo_id);
}

GObject *
seaf_get_group_shared_repo_by_path (SeafRepoManager *mgr,
                                    const char *repo_id,
                                    const char *path,
                                    int group_id,
                                    gboolean is_org,
                                    GError **error)
{
    char *sql;
    char *real_repo_id = NULL;
    GList *repo = NULL;
    GObject *ret = NULL;

    /* If path is NULL, 'repo_id' represents for the repo we want,
     * otherwise, 'repo_id' represents for the origin repo,
     * find virtual repo by path first.
     */
    if (path != NULL) {
        real_repo_id = seaf_repo_manager_get_virtual_repo_id (mgr, repo_id, path, NULL);
        if (!real_repo_id) {
            seaf_warning ("Failed to get virtual repo_id by path %s, origin_repo: %s\n", path, repo_id);
            return NULL;
        }
    }
    if (!real_repo_id)
        real_repo_id = g_strdup (repo_id);

    if (!is_org)
        sql = "SELECT RepoGroup.repo_id, v.repo_id, "
              "group_id, user_name, permission, commit_id, s.size, "
              "v.origin_repo, v.path, i.name, "
              "i.update_time, i.version, i.is_encrypted, i.last_modifier, i.status, i.type, i2.name "
              "FROM RepoGroup LEFT JOIN VirtualRepo v ON "
              "RepoGroup.repo_id = v.repo_id "
              "LEFT JOIN RepoInfo i ON RepoGroup.repo_id = i.repo_id "
              "LEFT JOIN RepoInfo i2 ON v.origin_repo = i2.repo_id "
              "LEFT JOIN RepoSize s ON RepoGroup.repo_id = s.repo_id, "
              "Branch WHERE group_id = ? AND "
              "RepoGroup.repo_id = Branch.repo_id AND "
              "RepoGroup.repo_id = ? AND "
              "Branch.name = 'master'";
    else
        sql = "SELECT OrgGroupRepo.repo_id, v.repo_id, "
              "group_id, owner, permission, commit_id, s.size, "
              "v.origin_repo, v.path, i.name, "
              "i.update_time, i.version, i.is_encrypted, i.last_modifier, i.status, i.type, i2.name "
              "FROM OrgGroupRepo LEFT JOIN VirtualRepo v ON "
              "OrgGroupRepo.repo_id = v.repo_id "
              "LEFT JOIN RepoInfo i ON OrgRepoGroup.repo_id = i.repo_id "
              "LEFT JOIN RepoInfo i2 ON v.origin_repo = i2.repo_id "
              "LEFT JOIN RepoSize s ON OrgGroupRepo.repo_id = s.repo_id, "
              "Branch WHERE group_id = ? AND "
              "OrgGroupRepo.repo_id = Branch.repo_id AND "
              "OrgGroupRepo.repo_id = ? AND "
              "Branch.name = 'master'";

    /* The list 'repo' should have only one repo,
     * use existing api get_group_repos_cb() to get it.
     */
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, get_group_repos_cb,
                                       &repo, 2, "int", group_id,
                                       "string", real_repo_id) < 0) {
        g_free (real_repo_id);
        g_list_free (repo);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to get repo by group_id from db.");
        return NULL;
    }
    g_free (real_repo_id);

    if (repo) {
        seaf_fill_repo_obj_from_commit (&repo);
        if (repo)
            ret = (GObject *)(repo->data);
        g_list_free (repo);
    }

    return ret;
}

GList *
seaf_get_group_repos_by_user (SeafRepoManager *mgr,
                              const char *user,
                              int org_id,
                              GError **error)
{
    CcnetGroup *group;
    GList *groups = NULL, *p, *q;
    GList *repos = NULL;
    SeafileRepo *repo = NULL;
    GString *sql = NULL;
    int group_id = 0;

    /* Get the groups this user belongs to. */
    groups = ccnet_group_manager_get_groups_by_user (seaf->group_mgr, user,
                                                     1, NULL);
    if (!groups) {
        goto out;
    }

    sql = g_string_new ("");
    g_string_printf (sql, "SELECT g.repo_id, v.repo_id, "
                          "group_id, %s, permission, commit_id, s.size, "
                          "v.origin_repo, v.path, i.name, "
                          "i.update_time, i.version, i.is_encrypted, i.last_modifier, i.status, i.type, i2.name "
                          "FROM %s g LEFT JOIN VirtualRepo v ON "
                          "g.repo_id = v.repo_id "
                          "LEFT JOIN RepoInfo i ON g.repo_id = i.repo_id "
                          "LEFT JOIN RepoInfo i2 ON v.origin_repo = i2.repo_id "
                          "LEFT JOIN RepoSize s ON g.repo_id = s.repo_id, "
                          "Branch b WHERE g.repo_id = b.repo_id AND "
                          "b.name = 'master' AND group_id IN (",
                          org_id < 0 ? "user_name" : "owner",
                          org_id < 0 ? "RepoGroup" : "OrgGroupRepo");
    for (p = groups; p != NULL; p = p->next) {
        group = p->data;
        g_object_get (group, "id", &group_id, NULL);

        g_string_append_printf (sql, "%d", group_id);
        if (p->next)
            g_string_append_printf (sql, ",");
    }
    g_string_append_printf (sql, " ) ORDER BY group_id");

    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql->str, get_group_repos_cb,
                                       &repos, 0) < 0) {
        for (p = repos; p; p = p->next) {
            g_object_unref (p->data);
        }
        g_list_free (repos);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to get user group repos from db.");
        seaf_warning ("Failed to get user[%s] group repos from db.\n", user);
        goto out;
    }

    int repo_group_id = 0;
    char *group_name = NULL;
    q = repos;

    /* Add group_name to repo. Both groups and repos are listed by group_id in descending order */
    for (p = groups; p; p = p->next) {
        group = p->data;
        g_object_get (group, "id", &group_id, NULL);
        g_object_get (group, "group_name", &group_name, NULL);

        for (; q; q = q->next) {
            repo = q->data;
            g_object_get (repo, "group_id", &repo_group_id, NULL);
            if (repo_group_id == group_id)
                g_object_set (repo, "group_name", group_name, NULL);
            else
                break;
        }
        g_free (group_name);
        if (q == NULL)
            break;
    }

    seaf_fill_repo_obj_from_commit (&repos);

out:
    if (sql)
        g_string_free (sql, TRUE);

    for (p = groups; p != NULL; p = p->next)
        g_object_unref ((GObject *)p->data);
    g_list_free (groups);

    return g_list_reverse (repos);
}

typedef struct RepoPath {
    char *repo_id;
    char *path;
    int group_id;
} RepoPath;


gboolean
convert_repo_path_cb (SeafDBRow *row, void *data)
{
    GList **repo_paths = data;

    const char *repo_id = seaf_db_row_get_column_text (row, 0);
    const char *path = seaf_db_row_get_column_text (row, 1);
    int group_id = seaf_db_row_get_column_int (row, 2);

    RepoPath *rp = g_new0(RepoPath, 1);
    rp->repo_id = g_strdup(repo_id);
    rp->path = g_strdup(path);
    rp->group_id = group_id;
    *repo_paths = g_list_append (*repo_paths, rp);

    return TRUE;
}

static void
free_repo_path (gpointer data)
{
    if (!data)
        return;

    RepoPath *rp = data;
    g_free (rp->repo_id);
    g_free (rp->path);
    g_free (rp);
}

static char *
filter_path (GList *repo_paths, const char *path)
{
    GList *ptr = NULL;
    int len;
    const char *relative_path;
    char *ret = NULL;
    RepoPath *rp = NULL, res;
    res.repo_id = NULL;
    res.path = NULL;
    res.group_id = 0;

    /* Find nearest item which contains @path, */
    for (ptr = repo_paths; ptr; ptr = ptr->next) {
        rp = ptr->data;
        len = strlen(rp->path);
        if (strncmp(rp->path, path, len) == 0 && (path[len] == '/' || path[len] == '\0')) {

            if (g_strcmp0(rp->path, res.path) > 0) {
                res.path = rp->path;
                res.repo_id = rp->repo_id;
                res.group_id = rp->group_id;
            }
        }
    }
    if (res.repo_id && res.path) {
        relative_path = path + strlen(res.path);
        if (relative_path[0] == '\0')
            relative_path = "/";

        json_t *json = json_object ();
        json_object_set_string_member(json, "repo_id", res.repo_id);
        json_object_set_string_member(json, "path", relative_path);
        if (res.group_id > 0)
            json_object_set_int_member(json, "group_id", res.group_id);
        ret = json_dumps (json, 0);
        json_decref (json);
    }

    return ret;
}

/* Convert origin repo and path to virtual repo and relative path */
char *
seaf_repo_manager_convert_repo_path (SeafRepoManager *mgr,
                                     const char *repo_id,
                                     const char *path,
                                     const char *user,
                                     gboolean is_org,
                                     GError **error)
{
    char *ret = NULL;
    int rc;
    int group_id;
    GString *sql;
    CcnetGroup *group;
    GList *groups = NULL, *p1;
    GList *repo_paths = NULL;
    SeafVirtRepo *vinfo = NULL;
    const char *r_repo_id = repo_id;
    char *r_path = NULL;

    vinfo = seaf_repo_manager_get_virtual_repo_info (mgr, repo_id);
    if (vinfo) {
        r_repo_id = vinfo->origin_repo_id;
        r_path = g_strconcat (vinfo->path, path, NULL);
    } else {
        r_path = g_strdup(path);
    }

    sql = g_string_new ("");
    g_string_printf (sql, "SELECT v.repo_id, path, 0 FROM VirtualRepo v, %s s WHERE "
                     "v.origin_repo=? AND v.repo_id=s.repo_id AND s.to_email=?",
                     is_org ? "OrgSharedRepo" : "SharedRepo");
    rc = seaf_db_statement_foreach_row (seaf->db,
                                        sql->str, convert_repo_path_cb,
                                        &repo_paths, 2,
                                        "string", r_repo_id, "string", user);
    if (rc < 0) {
        seaf_warning("Failed to convert repo path [%s:%s] to virtual repo path, db_error.\n",
                     repo_id, path);
        goto out;
    }
    ret = filter_path(repo_paths, r_path);
    g_list_free_full(repo_paths, free_repo_path);
    repo_paths = NULL;
    if (ret)
        goto out;

    /* Get the groups this user belongs to. */

    groups = ccnet_group_manager_get_groups_by_user (seaf->group_mgr, user,
                                                     1, NULL);
    if (!groups) {
        goto out;
    }

    g_string_printf (sql, "SELECT v.repo_id, path, r.group_id FROM VirtualRepo v, %s r WHERE "
                     "v.origin_repo=? AND v.repo_id=r.repo_id AND r.group_id IN(",
                     is_org ? "OrgGroupRepo" : "RepoGroup");
    for (p1 = groups; p1 != NULL; p1 = p1->next) {
        group = p1->data;
        g_object_get (group, "id", &group_id, NULL);

        g_string_append_printf (sql, "%d", group_id);
        if (p1->next)
            g_string_append_printf (sql, ",");
    }
    g_string_append_printf (sql, ")");

    rc = seaf_db_statement_foreach_row (seaf->db,
                                        sql->str, convert_repo_path_cb,
                                        &repo_paths, 1,
                                        "string", r_repo_id);
    if (rc < 0) {
        seaf_warning("Failed to convert repo path [%s:%s] to virtual repo path, db error.\n",
                     repo_id, path);
        g_string_free (sql, TRUE);
        goto out;
    }
    ret = filter_path(repo_paths, r_path);
    g_list_free_full(repo_paths, free_repo_path);

out:
    g_free (r_path);
    if (vinfo)
        seaf_virtual_repo_info_free (vinfo);
    g_string_free (sql, TRUE);
    for (p1 = groups; p1 != NULL; p1 = p1->next)
        g_object_unref ((GObject *)p1->data);
    g_list_free (groups);

    return ret;
}

int
seaf_repo_manager_set_repo_status(SeafRepoManager *mgr,
                                  const char *repo_id, RepoStatus status)
{
    int ret = 0;

    if (seaf_db_statement_query (mgr->seaf->db,
                                 "UPDATE RepoInfo SET status=? "
                                 "WHERE repo_id=? OR repo_id IN "
                                 "(SELECT repo_id FROM VirtualRepo WHERE origin_repo=?)",
                                 3, "int", status,
                                 "string", repo_id, "string", repo_id) < 0)
        ret = -1;

    return ret;
}

int
seaf_repo_manager_get_repo_status(SeafRepoManager *mgr,
                                  const char *repo_id)
{
    char *sql = "SELECT status FROM RepoInfo WHERE repo_id=?";

    return seaf_db_statement_get_int (mgr->seaf->db, sql,
                                      1, "string", repo_id);
}
