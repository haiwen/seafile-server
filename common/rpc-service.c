/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include <glib/gstdio.h>
#include <ctype.h>

#include <sys/stat.h>
#include <dirent.h>
#include "utils.h"

#include "seafile-session.h"
#include "seaf-utils.h"
#include "fs-mgr.h"
#include "repo-mgr.h"
#include "seafile-error.h"
#include "seafile-rpc.h"
#include "mq-mgr.h"
#include "password-hash.h"

#ifdef SEAFILE_SERVER
#include "web-accesstoken-mgr.h"
#endif

#ifndef SEAFILE_SERVER
#include "seafile-config.h"
#endif

#define DEBUG_FLAG SEAFILE_DEBUG_OTHER
#include "log.h"

#ifndef SEAFILE_SERVER
#include "../daemon/vc-utils.h"

#endif  /* SEAFILE_SERVER */


/* -------- Utilities -------- */
static GObject*
convert_repo (SeafRepo *r)
{
    SeafileRepo *repo = NULL;

#ifndef SEAFILE_SERVER
    if (r->head == NULL)
        return NULL;

    if (r->worktree_invalid && !seafile_session_config_get_allow_invalid_worktree(seaf))
        return NULL;
#endif

    repo = seafile_repo_new ();
    if (!repo)
        return NULL;

    g_object_set (repo, "id", r->id, "name", r->name,
                  "desc", r->desc, "encrypted", r->encrypted,
                  "magic", r->magic, "enc_version", r->enc_version,
                  "pwd_hash", r->pwd_hash,
                  "pwd_hash_algo", r->pwd_hash_algo, "pwd_hash_params", r->pwd_hash_params,
                  "head_cmmt_id", r->head ? r->head->commit_id : NULL,
                  "root", r->root_id,
                  "version", r->version, "last_modify", r->last_modify,
                  "last_modifier", r->last_modifier,
                  NULL);
    g_object_set (repo,
                  "repo_id", r->id, "repo_name", r->name,
                  "repo_desc", r->desc, "last_modified", r->last_modify,
                  "status", r->status,
                  "repo_type", r->type,
                  NULL);

#ifdef SEAFILE_SERVER
    if (r->virtual_info) {
        g_object_set (repo,
                      "is_virtual", TRUE,
                      "origin_repo_id", r->virtual_info->origin_repo_id,
                      "origin_path", r->virtual_info->path,
                      NULL);
    }

    if (r->encrypted) {
        if (r->enc_version >= 2)
            g_object_set (repo, "random_key", r->random_key, NULL);
        if (r->enc_version >= 3)
            g_object_set (repo, "salt", r->salt, NULL);
    }

    g_object_set (repo, "store_id", r->store_id,
                  "repaired", r->repaired,
                  "size", r->size, "file_count", r->file_count, NULL);
    g_object_set (repo, "is_corrupted", r->is_corrupted, NULL);
#endif

#ifndef SEAFILE_SERVER
    g_object_set (repo, "worktree", r->worktree,
                  "relay-id", r->relay_id,
                  "worktree-invalid", r->worktree_invalid,
                  "last-sync-time", r->last_sync_time,
                  "auto-sync", r->auto_sync,
                  NULL);

#endif  /* SEAFILE_SERVER */

    return (GObject *)repo;
}

static void
free_repo_obj (gpointer repo)
{
    if (!repo)
        return;
    g_object_unref ((GObject *)repo);
}

static GList *
convert_repo_list (GList *inner_repos)
{
    GList *ret = NULL, *ptr;
    GObject *repo = NULL;

    for (ptr = inner_repos; ptr; ptr=ptr->next) {
        SeafRepo *r = ptr->data;
        repo = convert_repo (r);
        if (!repo) {
            g_list_free_full (ret, free_repo_obj);
            return NULL;
        }

        ret = g_list_prepend (ret, repo);
    }

    return g_list_reverse (ret);
}

/*
 * RPC functions available for both clients and server.
 */

GList *
seafile_branch_gets (const char *repo_id, GError **error)
{
    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    GList *blist = seaf_branch_manager_get_branch_list(seaf->branch_mgr,
                                                       repo_id);
    GList *ptr;
    GList *ret = NULL;

    for (ptr = blist; ptr; ptr=ptr->next) {
        SeafBranch *b = ptr->data;
        SeafileBranch *branch = seafile_branch_new ();
        g_object_set (branch, "repo_id", b->repo_id, "name", b->name,
                      "commit_id", b->commit_id, NULL);
        ret = g_list_prepend (ret, branch);
        seaf_branch_unref (b);
    }
    ret = g_list_reverse (ret);
    g_list_free (blist);
    return ret;
}

#ifdef SEAFILE_SERVER
GList*
seafile_get_trash_repo_list (int start, int limit, GError **error)
{
    return seaf_repo_manager_get_trash_repo_list (seaf->repo_mgr,
                                                  start, limit,
                                                  error);
}

GList *
seafile_get_trash_repos_by_owner (const char *owner, GError **error)
{
    if (!owner) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    return seaf_repo_manager_get_trash_repos_by_owner (seaf->repo_mgr,
                                                       owner,
                                                       error);
}

int
seafile_del_repo_from_trash (const char *repo_id, GError **error)
{
    int ret = 0;

    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }
    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    ret = seaf_repo_manager_del_repo_from_trash (seaf->repo_mgr, repo_id, error);

    return ret;
}

int
seafile_empty_repo_trash (GError **error)
{
    return seaf_repo_manager_empty_repo_trash (seaf->repo_mgr, error);
}

int
seafile_empty_repo_trash_by_owner (const char *owner, GError **error)
{
    if (!owner) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    return seaf_repo_manager_empty_repo_trash_by_owner (seaf->repo_mgr, owner, error);
}

int
seafile_restore_repo_from_trash (const char *repo_id, GError **error)
{
    int ret = 0;

    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }
    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    ret = seaf_repo_manager_restore_repo_from_trash (seaf->repo_mgr, repo_id, error);

    return ret;
}

int
seafile_publish_event(const char *channel, const char *content, GError **error)
{
    int ret = 0;

    if (!channel || !content) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");                                                          
        return -1;
    }

    ret = seaf_mq_manager_publish_event (seaf->mq_mgr, channel, content);

    return ret;
}

json_t *
seafile_pop_event(const char *channel, GError **error)
{
    if (!channel) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }
    return seaf_mq_manager_pop_event (seaf->mq_mgr, channel);
}
#endif

GList*
seafile_get_repo_list (int start, int limit, const char *order_by, int ret_virt_repo, GError **error)
{
    GList *repos = seaf_repo_manager_get_repo_list(seaf->repo_mgr, start, limit, order_by, ret_virt_repo);
    GList *ret = NULL;

    ret = convert_repo_list (repos);

#ifdef SEAFILE_SERVER
    GList *ptr;
    for (ptr = repos; ptr != NULL; ptr = ptr->next)
        seaf_repo_unref ((SeafRepo *)ptr->data);
#endif
    g_list_free (repos);

    return ret;
}

#ifdef SEAFILE_SERVER
gint64
seafile_count_repos (GError **error)
{
    return seaf_repo_manager_count_repos (seaf->repo_mgr, error);
}
#endif

GObject*
seafile_get_repo (const char *repo_id, GError **error)
{
    SeafRepo *r;

    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }
    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    r = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    /* Don't return repo that's not checked out. */
    if (r == NULL)
        return NULL;

    GObject *repo = convert_repo (r);

#ifdef SEAFILE_SERVER
    seaf_repo_unref (r);
#endif

    return repo;
}

SeafileCommit *
convert_to_seafile_commit (SeafCommit *c)
{
    SeafileCommit *commit = seafile_commit_new ();
    g_object_set (commit,
                  "id", c->commit_id,
                  "creator_name", c->creator_name,
                  "creator", c->creator_id,
                  "desc", c->desc,
                  "ctime", c->ctime,
                  "repo_id", c->repo_id,
                  "root_id", c->root_id,
                  "parent_id", c->parent_id,
                  "second_parent_id", c->second_parent_id,
                  "version", c->version,
                  "new_merge", c->new_merge,
                  "conflict", c->conflict,
                  "device_name", c->device_name,
                  "client_version", c->client_version,
                  NULL);
    return commit;
}

GObject*
seafile_get_commit (const char *repo_id, int version,
                    const gchar *id, GError **error)
{
    SeafileCommit *commit;
    SeafCommit *c;

    if (!repo_id || !is_uuid_valid(repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    if (!id || !is_object_id_valid(id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid commit id");
        return NULL;
    }

    c = seaf_commit_manager_get_commit (seaf->commit_mgr, repo_id, version, id);
    if (!c)
        return NULL;

    commit = convert_to_seafile_commit (c);
    seaf_commit_unref (c);
    return (GObject *)commit;
}

struct CollectParam {
    int offset;
    int limit;
    int count;
    GList *commits;
#ifdef SEAFILE_SERVER
    gint64 truncate_time;
    gboolean traversed_head;
#endif
};

static gboolean
get_commit (SeafCommit *c, void *data, gboolean *stop)
{
    struct CollectParam *cp = data;

#ifdef SEAFILE_SERVER
    if (cp->truncate_time == 0)
    {
        *stop = TRUE;
        /* Stop after traversing the head commit. */
    }
    /* We use <= here. This is for handling clean trash and history.
     * If the user cleans all history, truncate time will be equal to
     * the commit's ctime. In such case, we don't actually want to display
     * this commit.
     */
    else if (cp->truncate_time > 0 &&
             (gint64)(c->ctime) <= cp->truncate_time &&
             cp->traversed_head)
    {
        /* Still traverse the first commit older than truncate_time.
         * If a file in the child commit of this commit is deleted,
         * we need to access this commit in order to restore it
         * from trash.
         */
        *stop = TRUE;
    }

    /* Always traverse the head commit. */
    if (!cp->traversed_head)
        cp->traversed_head = TRUE;
#endif

    /* if offset = 1, limit = 1, we should stop when the count = 2 */
    if (cp->limit > 0 && cp->count >= cp->offset + cp->limit) {
        *stop = TRUE;
        return TRUE;  /* TRUE to indicate no error */
    }

    if (cp->count >= cp->offset) {
        SeafileCommit *commit = convert_to_seafile_commit (c);
        cp->commits = g_list_prepend (cp->commits, commit);
    }

    ++cp->count;
    return TRUE;                /* TRUE to indicate no error */
}


GList*
seafile_get_commit_list (const char *repo_id,
                         int offset,
                         int limit,
                         GError **error)
{
    SeafRepo *repo;
    GList *commits = NULL;
    gboolean ret;
    struct CollectParam cp;
    char *commit_id;

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    /* correct parameter */
    if (offset < 0)
        offset = 0;

    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_REPO, "No such repository");
        return NULL;
    }

    if (!repo->head) {
        SeafBranch *branch =
            seaf_branch_manager_get_branch (seaf->branch_mgr,
                                            repo->id, "master");
        if (branch != NULL) {
            commit_id = g_strdup (branch->commit_id);
            seaf_branch_unref (branch);
        } else {
            seaf_warning ("[repo-mgr] Failed to get repo %s branch master\n",
                       repo_id);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_REPO,
                         "No head and branch master");
#ifdef SEAFILE_SERVER
            seaf_repo_unref (repo);
#endif
            return NULL;
        }
    } else {
        commit_id = g_strdup (repo->head->commit_id);
    }

    /* Init CollectParam */
    memset (&cp, 0, sizeof(cp));
    cp.offset = offset;
    cp.limit = limit;

#ifdef SEAFILE_SERVER
    cp.truncate_time = seaf_repo_manager_get_repo_truncate_time (seaf->repo_mgr,
                                                                 repo_id);
#endif

    ret =
        seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                  repo->id, repo->version,
                                                  commit_id, get_commit, &cp, TRUE);
    g_free (commit_id);
#ifdef SEAFILE_SERVER
    seaf_repo_unref (repo);
#endif

    if (!ret) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_LIST_COMMITS, "Failed to list commits");
        return NULL;
    }

    commits = g_list_reverse (cp.commits);
    return commits;
}

#ifndef SEAFILE_SERVER
static
int do_unsync_repo(SeafRepo *repo)
{
    if (!seaf->started) {
        seaf_message ("System not started, skip removing repo.\n");
        return -1;
    }

    if (repo->auto_sync && (repo->sync_interval == 0))
        seaf_wt_monitor_unwatch_repo (seaf->wt_monitor, repo->id);

    seaf_sync_manager_cancel_sync_task (seaf->sync_mgr, repo->id);

    SyncInfo *info = seaf_sync_manager_get_sync_info (seaf->sync_mgr, repo->id);

    /* If we are syncing the repo,
     * we just mark the repo as deleted and let sync-mgr actually delete it.
     * Otherwise we are safe to delete the repo.
     */
    char *worktree = g_strdup (repo->worktree);
    if (info != NULL && info->in_sync) {
        seaf_repo_manager_mark_repo_deleted (seaf->repo_mgr, repo);
    } else {
        seaf_repo_manager_del_repo (seaf->repo_mgr, repo);
    }

    g_free (worktree);

    return 0;
}

static void
cancel_clone_tasks_by_account (const char *account_server, const char *account_email)
{
    GList *ptr, *tasks;
    CloneTask *task;

    tasks = seaf_clone_manager_get_tasks (seaf->clone_mgr);
    for (ptr = tasks; ptr != NULL; ptr = ptr->next) {
        task = ptr->data;

        if (g_strcmp0(account_server, task->peer_addr) == 0
            && g_strcmp0(account_email, task->email) == 0) {
            seaf_clone_manager_cancel_task (seaf->clone_mgr, task->repo_id);
        }
    }

    g_list_free (tasks);
}

int
seafile_unsync_repos_by_account (const char *server_addr, const char *email, GError **error)
{
    if (!server_addr || !email) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    GList *ptr, *repos = seaf_repo_manager_get_repo_list(seaf->repo_mgr, -1, -1, NULL, 0);
    if (!repos) {
        return 0;
    }

    for (ptr = repos; ptr; ptr = ptr->next) {
        SeafRepo *repo = (SeafRepo*)ptr->data;
        char *addr = NULL;
        seaf_repo_manager_get_repo_relay_info(seaf->repo_mgr,
                                              repo->id,
                                              &addr, /* addr */
                                              NULL); /* port */

        if (g_strcmp0(addr, server_addr) == 0 && g_strcmp0(repo->email, email) == 0) {
            if (do_unsync_repo(repo) < 0) {
                return -1;
            }
        }

        g_free (addr);
    }

    g_list_free (repos);

    cancel_clone_tasks_by_account (server_addr, email);

    return 0;
}

int
seafile_remove_repo_tokens_by_account (const char *server_addr, const char *email, GError **error)
{
    if (!server_addr || !email) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    GList *ptr, *repos = seaf_repo_manager_get_repo_list(seaf->repo_mgr, -1, -1, NULL, 0);
    if (!repos) {
        return 0;
    }

    for (ptr = repos; ptr; ptr = ptr->next) {
        SeafRepo *repo = (SeafRepo*)ptr->data;
        char *addr = NULL;
        seaf_repo_manager_get_repo_relay_info(seaf->repo_mgr,
                                              repo->id,
                                              &addr, /* addr */
                                              NULL); /* port */

        if (g_strcmp0(addr, server_addr) == 0 && g_strcmp0(repo->email, email) == 0) {
            if (seaf_repo_manager_remove_repo_token(seaf->repo_mgr, repo) < 0) {
                return -1;
            }
        }

        g_free (addr);
    }

    g_list_free (repos);

    cancel_clone_tasks_by_account (server_addr, email);

    return 0;
}

int
seafile_set_repo_token (const char *repo_id,
                        const char *token,
                        GError **error)
{
    int ret;

    if (repo_id == NULL || token == NULL) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments should not be empty");
        return -1;
    }

    SeafRepo *repo;
    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_REPO, "Can't find Repo %s", repo_id);
        return -1;
    }

    ret = seaf_repo_manager_set_repo_token (seaf->repo_mgr,
                                            repo, token);
    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL,
                     "Failed to set token for repo %s", repo_id);
        return -1;
    }

    return 0;
}

#endif

int
seafile_destroy_repo (const char *repo_id, GError **error)
{
    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }
    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

#ifndef SEAFILE_SERVER
    SeafRepo *repo;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "No such repository");
        return -1;
    }

    return do_unsync_repo(repo);
#else

    return seaf_repo_manager_del_repo (seaf->repo_mgr, repo_id, error);
#endif
}


GObject *
seafile_generate_magic_and_random_key(int enc_version,
                                      const char* repo_id,
                                      const char *passwd,
                                      GError **error)
{
    if (!repo_id || !passwd) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    gchar salt[65] = {0};
    gchar magic[65] = {0};
    gchar pwd_hash[65] = {0};
    gchar random_key[97] = {0};

    if (enc_version >= 3 && seafile_generate_repo_salt (salt) < 0) {
        return NULL;
    }

    seafile_generate_magic (enc_version, repo_id, passwd, salt, magic);
    if (seafile_generate_random_key (passwd, enc_version, salt, random_key) < 0) {
        return NULL;
    }

    SeafileEncryptionInfo *sinfo;
    sinfo = g_object_new (SEAFILE_TYPE_ENCRYPTION_INFO,
                          "repo_id", repo_id,
                          "passwd", passwd,
                          "enc_version", enc_version,
                          "magic", magic,
                          "random_key", random_key,
                          NULL);
    if (enc_version >= 3)
        g_object_set (sinfo, "salt", salt, NULL);

    return (GObject *)sinfo;

}

#include "diff-simple.h"

inline static const char*
get_diff_status_str(char status)
{
    if (status == DIFF_STATUS_ADDED)
        return "add";
    if (status == DIFF_STATUS_DELETED)
        return "del";
    if (status == DIFF_STATUS_MODIFIED)
        return "mod";
    if (status == DIFF_STATUS_RENAMED)
        return "mov";
    if (status == DIFF_STATUS_DIR_ADDED)
        return "newdir";
    if (status == DIFF_STATUS_DIR_DELETED)
        return "deldir";
    return NULL;
}

GList *
seafile_diff (const char *repo_id, const char *arg1, const char *arg2, int fold_dir_results, GError **error)
{
    SeafRepo *repo;
    char *err_msgs = NULL;
    GList *diff_entries, *p;
    GList *ret = NULL;

    if (!repo_id || !arg1 || !arg2) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    if ((arg1[0] != 0 && !is_object_id_valid (arg1)) || !is_object_id_valid(arg2)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid commit id");
        return NULL;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "No such repository");
        return NULL;
    }

    diff_entries = seaf_repo_diff (repo, arg1, arg2, fold_dir_results, &err_msgs);
    if (err_msgs) {
        g_set_error (error, SEAFILE_DOMAIN, -1, "%s", err_msgs);
        g_free (err_msgs);
#ifdef SEAFILE_SERVER
        seaf_repo_unref (repo);
#endif
        return NULL;
    }

#ifdef SEAFILE_SERVER
    seaf_repo_unref (repo);
#endif

    for (p = diff_entries; p != NULL; p = p->next) {
        DiffEntry *de = p->data;
        SeafileDiffEntry *entry = g_object_new (
            SEAFILE_TYPE_DIFF_ENTRY,
            "status", get_diff_status_str(de->status),
            "name", de->name,
            "new_name", de->new_name,
            NULL);
        ret = g_list_prepend (ret, entry);
    }

    for (p = diff_entries; p != NULL; p = p->next) {
        DiffEntry *de = p->data;
        diff_entry_free (de);
    }
    g_list_free (diff_entries);

    return g_list_reverse (ret);
}

/*
 * RPC functions only available for server.
 */

#ifdef SEAFILE_SERVER

GList *
seafile_list_dir_by_path(const char *repo_id,
                         const char *commit_id,
                         const char *path, GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *commit = NULL;
    SeafDir *dir;
    SeafDirent *dent;
    SeafileDirent *d;

    GList *ptr;
    GList *res = NULL;

    if (!repo_id || !commit_id || !path) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Args can't be NULL");
        return NULL;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid repo id");
        return NULL;
    }

    if (!is_object_id_valid (commit_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid commit id");
        return NULL;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad repo id");
        return NULL;
    }

    commit = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             repo_id, repo->version,
                                             commit_id);

    if (!commit) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_COMMIT, "No such commit");
        goto out;
    }

    char *rpath = format_dir_path (path);
    dir = seaf_fs_manager_get_seafdir_by_path (seaf->fs_mgr,
                                               repo->store_id,
                                               repo->version,
                                               commit->root_id,
                                               rpath, error);
    g_free (rpath);

    if (!dir) {
        seaf_warning ("Can't find seaf dir for %s in repo %s\n", path, repo->store_id);
        goto out;
    }

    for (ptr = dir->entries; ptr != NULL; ptr = ptr->next) {
        dent = ptr->data;

        if (!is_object_id_valid (dent->id))
            continue;

        d = g_object_new (SEAFILE_TYPE_DIRENT,
                          "obj_id", dent->id,
                          "obj_name", dent->name,
                          "mode", dent->mode,
                          "version", dent->version,
                          "mtime", dent->mtime,
                          "size", dent->size,
                          NULL);
        res = g_list_prepend (res, d);
    }

    seaf_dir_free (dir);
    res = g_list_reverse (res);

out:
    seaf_repo_unref (repo);
    seaf_commit_unref (commit);
    return res;
}

static void
filter_error (GError **error)
{
    if (*error && g_error_matches(*error,
                                  SEAFILE_DOMAIN,
                                  SEAF_ERR_PATH_NO_EXIST)) {
        g_clear_error (error);
    }
}

char *
seafile_get_dir_id_by_commit_and_path(const char *repo_id,
                                      const char *commit_id,
                                      const char *path,
                                      GError **error)
{
    SeafRepo *repo = NULL;
    char *res = NULL;
    SeafCommit *commit = NULL;
    SeafDir *dir;

    if (!repo_id || !commit_id || !path) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Args can't be NULL");
        return NULL;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid repo id");
        return NULL;
    }

    if (!is_object_id_valid (commit_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid commit id");
        return NULL;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad repo id");
        return NULL;
    }

    commit = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             repo_id, repo->version,
                                             commit_id);

    if (!commit) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_COMMIT, "No such commit");
        goto out;
    }

    char *rpath = format_dir_path (path);

    dir = seaf_fs_manager_get_seafdir_by_path (seaf->fs_mgr,
                                               repo->store_id,
                                               repo->version,
                                               commit->root_id,
                                               rpath, error);
    g_free (rpath);

    if (!dir) {
        seaf_warning ("Can't find seaf dir for %s in repo %s\n", path, repo->store_id);
        filter_error (error);
        goto out;
    }

    res = g_strdup (dir->dir_id);
    seaf_dir_free (dir);

 out:
    seaf_repo_unref (repo);
    seaf_commit_unref (commit);
    return res;
}

int
seafile_edit_repo (const char *repo_id,
                   const char *name,
                   const char *description,
                   const char *user,
                   GError **error)
{
    return seaf_repo_manager_edit_repo (repo_id, name, description, user, error);
}

int
seafile_change_repo_passwd (const char *repo_id,
                            const char *old_passwd,
                            const char *new_passwd,
                            const char *user,
                            GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *commit = NULL, *parent = NULL;
    int ret = 0;

    if (!user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "No user given");
        return -1;
    }

    if (!old_passwd || old_passwd[0] == 0 || !new_passwd || new_passwd[0] == 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Empty passwd");
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

    if (!repo->encrypted) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Repo not encrypted");
        return -1;
    }

    if (repo->enc_version < 2) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Unsupported enc version");
        return -1;
    }

    if (repo->pwd_hash_algo) {
        if (seafile_pwd_hash_verify_repo_passwd (repo->enc_version, repo_id, old_passwd, repo->salt,
                                                 repo->pwd_hash, repo->pwd_hash_algo, repo->pwd_hash_params) < 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Incorrect password");
            return -1;
        }
    } else {
        if (seafile_verify_repo_passwd (repo_id, old_passwd, repo->magic,
                                        repo->enc_version, repo->salt) < 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Incorrect password");
            return -1;
        }
    }

    parent = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             repo->id, repo->version,
                                             repo->head->commit_id);
    if (!parent) {
        seaf_warning ("Failed to get commit %s:%s.\n",
                      repo->id, repo->head->commit_id);
        ret = -1;
        goto out;
    }

    char new_magic[65], new_pwd_hash[65], new_random_key[97];

    if (repo->pwd_hash_algo) {
        seafile_generate_pwd_hash (repo->enc_version, repo_id, new_passwd, repo->salt,
                                   repo->pwd_hash_algo, repo->pwd_hash_params, new_pwd_hash);
    } else {
        seafile_generate_magic (repo->enc_version, repo_id, new_passwd, repo->salt,
                                new_magic);
    }
    if (seafile_update_random_key (old_passwd, repo->random_key,
                                   new_passwd, new_random_key,
                                   repo->enc_version, repo->salt) < 0) {
        ret = -1;
        goto out;
    }

    if (repo->pwd_hash_algo) {
        memcpy (repo->pwd_hash, new_pwd_hash, 64);
    } else {
        memcpy (repo->magic, new_magic, 64);
    }
    memcpy (repo->random_key, new_random_key, 96);

    commit = seaf_commit_new (NULL,
                              repo->id,
                              parent->root_id,
                              user,
                              EMPTY_SHA1,
                              "Changed library password",
                              0);
    commit->parent_id = g_strdup(parent->commit_id);
    seaf_repo_to_commit (repo, commit);

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

    if (seaf_passwd_manager_is_passwd_set (seaf->passwd_mgr, repo_id, user))
        seaf_passwd_manager_set_passwd (seaf->passwd_mgr, repo_id,
                                        user, new_passwd, error);

out:
    seaf_commit_unref (commit);
    seaf_commit_unref (parent);
    seaf_repo_unref (repo);

    return ret;
}

static void
set_pwd_hash_to_commit (SeafCommit *commit,
                        SeafRepo *repo,
                        const char *pwd_hash,
                        const char *pwd_hash_algo,
                        const char *pwd_hash_params)
{
    commit->repo_name = g_strdup (repo->name);
    commit->repo_desc = g_strdup (repo->desc);
    commit->encrypted = repo->encrypted;
    commit->repaired = repo->repaired;
    if (commit->encrypted) {
        commit->enc_version = repo->enc_version;
        if (commit->enc_version == 2) {
            commit->random_key = g_strdup (repo->random_key);
        } else if (commit->enc_version == 3) {
            commit->random_key = g_strdup (repo->random_key);
            commit->salt = g_strdup (repo->salt);
        } else if (commit->enc_version == 4) {
            commit->random_key = g_strdup (repo->random_key);
            commit->salt = g_strdup (repo->salt);
        }
        commit->pwd_hash = g_strdup (pwd_hash);
        commit->pwd_hash_algo = g_strdup (pwd_hash_algo);
        commit->pwd_hash_params = g_strdup (pwd_hash_params);
    }
    commit->no_local_history = repo->no_local_history;
    commit->version = repo->version;
}

int
seafile_upgrade_repo_pwd_hash_algorithm (const char *repo_id,
                                         const char *user,
                                         const char *passwd,
                                         const char *pwd_hash_algo,
                                         const char *pwd_hash_params,
                                         GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *commit = NULL, *parent = NULL;
    int ret = 0;

    if (!user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "No user given");
        return -1;
    }

    if (!passwd || passwd[0] == 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Empty passwd");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    if (!pwd_hash_algo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid pwd hash algorithm");
        return -1;
    }

    if (g_strcmp0 (pwd_hash_algo, PWD_HASH_PDKDF2) != 0 &&
        g_strcmp0 (pwd_hash_algo, PWD_HASH_ARGON2ID) != 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Unsupported pwd hash algorithm");
        return -1;
    }

    if (!pwd_hash_params) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid pwd hash params");
        return -1;
    }

retry:
    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "No such library");
        return -1;
    }

    if (g_strcmp0 (pwd_hash_algo, repo->pwd_hash_algo) == 0 &&
        g_strcmp0 (pwd_hash_params, repo->pwd_hash_params) == 0) {
        goto out;
    }

    if (!repo->encrypted) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Repo not encrypted");
        ret = -1;
        goto out;
    }

    if (repo->pwd_hash_algo) {
        if (seafile_pwd_hash_verify_repo_passwd (repo->enc_version, repo_id, passwd, repo->salt,
                                                 repo->pwd_hash, repo->pwd_hash_algo, repo->pwd_hash_params) < 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Incorrect password");
            ret = 1;
            goto out;
        }
    } else {
        if (seafile_verify_repo_passwd (repo_id, passwd, repo->magic,
                                        repo->enc_version, repo->salt) < 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Incorrect password");
            ret = -1;
            goto out;
        }
    }

    parent = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             repo->id, repo->version,
                                             repo->head->commit_id);
    if (!parent) {
        seaf_warning ("Failed to get commit %s:%s.\n",
                      repo->id, repo->head->commit_id);
        ret = -1;
        goto out;
    }

    char new_pwd_hash[65]= {0};

    seafile_generate_pwd_hash (repo->enc_version, repo_id, passwd, repo->salt,
                               pwd_hash_algo, pwd_hash_params, new_pwd_hash);

    // To prevent clients that have already synced this repo from overwriting the modified encryption algorithm,
    // delete all sync tokens.
    if (seaf_delete_repo_tokens (repo) < 0) {
        seaf_warning ("Failed to delete repo sync tokens, abort change pwd hash algorithm.\n");
        ret = -1;
        goto out;
    }

    memcpy (repo->pwd_hash, new_pwd_hash, 64);

    commit = seaf_commit_new (NULL,
                              repo->id,
                              parent->root_id,
                              user,
                              EMPTY_SHA1,
                              "Changed library password hash algorithm",
                              0);
    commit->parent_id = g_strdup(parent->commit_id);
    set_pwd_hash_to_commit (commit, repo, new_pwd_hash, pwd_hash_algo, pwd_hash_params);

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

    if (seaf_passwd_manager_is_passwd_set (seaf->passwd_mgr, repo_id, user))
        seaf_passwd_manager_set_passwd (seaf->passwd_mgr, repo_id,
                                        user, passwd, error);

out:
    seaf_commit_unref (commit);
    seaf_commit_unref (parent);
    seaf_repo_unref (repo);

    return ret;
}

int
seafile_is_repo_owner (const char *email,
                       const char *repo_id,
                       GError **error)
{
    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return 0;
    }

    char *owner = seaf_repo_manager_get_repo_owner (seaf->repo_mgr, repo_id);
    if (!owner) {
        /* seaf_warning ("Failed to get owner info for repo %s.\n", repo_id); */
        return 0;
    }

    if (strcmp(owner, email) != 0) {
        g_free (owner);
        return 0;
    }

    g_free (owner);
    return 1;
}

int
seafile_set_repo_owner(const char *repo_id, const char *email,
                       GError **error)
{
    if (!repo_id || !email) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }
    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    return seaf_repo_manager_set_repo_owner(seaf->repo_mgr, repo_id, email);
}

char *
seafile_get_repo_owner (const char *repo_id, GError **error)
{
    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }
    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    char *owner = seaf_repo_manager_get_repo_owner (seaf->repo_mgr, repo_id);
    /* if (!owner){ */
    /*     seaf_warning ("Failed to get repo owner for repo %s.\n", repo_id); */
    /* } */

    return owner;
}

GList *
seafile_get_orphan_repo_list(GError **error)
{
    GList *ret = NULL;
    GList *repos, *ptr;

    repos = seaf_repo_manager_get_orphan_repo_list(seaf->repo_mgr);
    ret = convert_repo_list (repos);

    for (ptr = repos; ptr; ptr = ptr->next) {
        seaf_repo_unref ((SeafRepo *)ptr->data);
    }
    g_list_free (repos);

    return ret;
}

GList *
seafile_list_owned_repos (const char *email, int ret_corrupted,
                          int start, int limit, GError **error)
{
    GList *ret = NULL;
    GList *repos, *ptr;

    repos = seaf_repo_manager_get_repos_by_owner (seaf->repo_mgr, email, ret_corrupted,
                                                  start, limit, NULL);
    ret = convert_repo_list (repos);

    /* for (ptr = ret; ptr; ptr = ptr->next) { */
    /*     g_object_get (ptr->data, "repo_id", &repo_id, NULL); */
    /*     is_shared = seaf_share_manager_is_repo_shared (seaf->share_mgr, repo_id); */
    /*     if (is_shared < 0) { */
    /*         g_free (repo_id); */
    /*         break; */
    /*     } else { */
    /*         g_object_set (ptr->data, "is_shared", is_shared, NULL); */
    /*         g_free (repo_id); */
    /*     } */
    /* } */

    /* while (ptr) { */
    /*     g_object_set (ptr->data, "is_shared", FALSE, NULL); */
    /*     ptr = ptr->prev; */
    /* } */

    for(ptr = repos; ptr; ptr = ptr->next) {
        seaf_repo_unref ((SeafRepo *)ptr->data);
    }
    g_list_free (repos);

    return ret;
}

GList *
seafile_search_repos_by_name (const char *name, GError **error)
{
    GList *ret = NULL;
    GList *repos, *ptr;

    repos = seaf_repo_manager_search_repos_by_name (seaf->repo_mgr, name);
    ret = convert_repo_list (repos);

    for (ptr = repos; ptr; ptr = ptr->next) {
        seaf_repo_unref ((SeafRepo *)ptr->data);
    }
    g_list_free (repos);

    return g_list_reverse(ret);
}

gint64
seafile_get_user_quota_usage (const char *email, GError **error)
{
    gint64 ret;

    if (!email) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad user id");
        return -1;
    }

    ret = seaf_quota_manager_get_user_usage (seaf->quota_mgr, email);
    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Internal server error");
        return -1;
    }

    return ret;
}

gint64
seafile_get_user_share_usage (const char *email, GError **error)
{
    gint64 ret;

    if (!email) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad user id");
        return -1;
    }

    ret = seaf_quota_manager_get_user_share_usage (seaf->quota_mgr, email);
    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Internal server error");
        return -1;
    }

    return ret;
}

gint64
seafile_server_repo_size(const char *repo_id, GError **error)
{
    gint64 ret;

    if (!repo_id || strlen(repo_id) != 36) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad repo id");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    ret = seaf_repo_manager_get_repo_size (seaf->repo_mgr, repo_id);
    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Internal server error");
        return -1;
    }

    return ret;
}

int
seafile_set_repo_history_limit (const char *repo_id,
                                int days,
                                GError **error)
{
    if (!repo_id || !is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    if (seaf_repo_manager_set_repo_history_limit (seaf->repo_mgr,
                                                  repo_id,
                                                  days) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "DB Error");
        return -1;
    }

    return 0;
}

int
seafile_get_repo_history_limit (const char *repo_id,
                                GError **error)
{
    if (!repo_id || !is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    return  seaf_repo_manager_get_repo_history_limit (seaf->repo_mgr, repo_id);
}

int
seafile_set_repo_valid_since (const char *repo_id,
                              gint64 timestamp,
                              GError **error)
{
    return seaf_repo_manager_set_repo_valid_since (seaf->repo_mgr,
                                                   repo_id,
                                                   timestamp);
}

int
seafile_repo_set_access_property (const char *repo_id, const char *ap, GError **error)
{
    int ret;

    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    if (strlen(repo_id) != 36) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Wrong repo id");
        return -1;
    }

    if (g_strcmp0(ap, "public") != 0 && g_strcmp0(ap, "own") != 0 && g_strcmp0(ap, "private") != 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Wrong access property");
        return -1;
    }

    ret = seaf_repo_manager_set_access_property (seaf->repo_mgr, repo_id, ap);
    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Internal server error");
        return -1;
    }

    return ret;
}

char *
seafile_repo_query_access_property (const char *repo_id, GError **error)
{
    char *ret;

    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    if (strlen(repo_id) != 36) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Wrong repo id");
        return NULL;
    }

    ret = seaf_repo_manager_query_access_property (seaf->repo_mgr, repo_id);

    return ret;
}

char *
seafile_web_get_access_token (const char *repo_id,
                              const char *obj_id,
                              const char *op,
                              const char *username,
                              int use_onetime,
                              GError **error)
{
    char *token;

    if (!repo_id || !obj_id || !op || !username) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Missing args");
        return NULL;
    }

    token = seaf_web_at_manager_get_access_token (seaf->web_at_mgr,
                                                  repo_id, obj_id, op,
                                                  username, use_onetime, error);
    return token;
}

GObject *
seafile_web_query_access_token (const char *token, GError **error)
{
    SeafileWebAccess *webaccess = NULL;

    if (!token) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Token should not be null");
        return NULL;
    }

    webaccess = seaf_web_at_manager_query_access_token (seaf->web_at_mgr,
                                                        token);
    if (webaccess)
        return (GObject *)webaccess;

    return NULL;
}

char *
seafile_query_zip_progress (const char *token, GError **error)
{
#ifdef HAVE_EVHTP
    return zip_download_mgr_query_zip_progress (seaf->zip_download_mgr,
                                                token, error);
#else
    return NULL;
#endif
}

int
seafile_cancel_zip_task (const char *token, GError **error)
{
#ifdef HAVE_EVHTP
    return zip_download_mgr_cancel_zip_task (seaf->zip_download_mgr,
                                             token);
#else
    return 0;
#endif
}

int
seafile_add_share (const char *repo_id, const char *from_email,
                   const char *to_email, const char *permission, GError **error)
{
    int ret;

    if (!repo_id || !from_email || !to_email || !permission) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Missing args");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid repo_id parameter");
        return -1;
    }

    if (g_strcmp0 (from_email, to_email) == 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Can not share repo to myself");
        return -1;
    }

    if (!is_permission_valid (permission)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid permission parameter");
        return -1;
    }

    ret = seaf_share_manager_add_share (seaf->share_mgr, repo_id, from_email,
                                        to_email, permission);

    return ret;
}

GList *
seafile_list_share_repos (const char *email, const char *type,
                          int start, int limit, GError **error)
{
    if (g_strcmp0 (type, "from_email") != 0 &&
        g_strcmp0 (type, "to_email") != 0 ) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Wrong type argument");
        return NULL;
    }

    return seaf_share_manager_list_share_repos (seaf->share_mgr,
                                                email, type,
                                                start, limit,
                                                NULL);
}

GList *
seafile_list_repo_shared_to (const char *from_user, const char *repo_id,
                             GError **error)
{

    if (!from_user || !repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Missing args");
        return NULL;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    return seaf_share_manager_list_repo_shared_to (seaf->share_mgr,
                                                   from_user, repo_id,
                                                   error);
}

char *
seafile_share_subdir_to_user (const char *repo_id,
                              const char *path,
                              const char *owner,
                              const char *share_user,
                              const char *permission,
                              const char *passwd,
                              GError **error)
{
    if (is_empty_string (repo_id) || !is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid repo_id parameter");
        return NULL;
    }

    if (is_empty_string (path) || strcmp (path, "/") == 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid path parameter");
        return NULL;
    }

    if (is_empty_string (owner)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid owner parameter");
        return NULL;
    }

    if (is_empty_string (share_user)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid share_user parameter");
        return NULL;
    }

    if (strcmp (owner, share_user) == 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Can't share subdir to myself");
        return NULL;
    }

    if (!is_permission_valid (permission)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid permission parameter");
        return NULL;
    }

    char *real_path;
    char *vrepo_name;
    char *vrepo_id;
    char *ret = NULL;

    real_path = format_dir_path (path);
    // Use subdir name as virtual repo name and description
    vrepo_name = g_path_get_basename (real_path);
    vrepo_id = seaf_repo_manager_create_virtual_repo (seaf->repo_mgr,
                                                      repo_id, real_path,
                                                      vrepo_name, vrepo_name,
                                                      owner, passwd, error);
    if (!vrepo_id)
        goto out;

    int result = seaf_share_manager_add_share (seaf->share_mgr, vrepo_id, owner,
                                        share_user, permission);
    if (result < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to share subdir to user");
        g_free (vrepo_id);
    }
    else 
        ret = vrepo_id;

out:
    g_free (vrepo_name);
    g_free (real_path);
    return ret;
}

int
seafile_unshare_subdir_for_user (const char *repo_id,
                                 const char *path,
                                 const char *owner,
                                 const char *share_user,
                                 GError **error)
{
    if (is_empty_string (repo_id) || !is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid repo_id parameter");
        return -1;
    }

    if (is_empty_string (path) || strcmp (path, "/") == 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid path parameter");
        return -1;
    }

    if (is_empty_string (owner)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid owner parameter");
        return -1;
    }

    if (is_empty_string (share_user) ||
        strcmp (owner, share_user) == 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid share_user parameter");
        return -1;
    }

    char *real_path;
    int ret = 0;

    real_path = format_dir_path (path);

    ret = seaf_share_manager_unshare_subdir (seaf->share_mgr,
                                             repo_id, real_path, owner, share_user);
    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to unshare subdir for user");
    }

    g_free (real_path);
    return ret;
}

int
seafile_update_share_subdir_perm_for_user (const char *repo_id,
                                           const char *path,
                                           const char *owner,
                                           const char *share_user,
                                           const char *permission,
                                           GError **error)
{
    if (is_empty_string (repo_id) || !is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid repo_id parameter");
        return -1;
    }

    if (is_empty_string (path) || strcmp (path, "/") == 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid path parameter");
        return -1;
    }

    if (is_empty_string (owner)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid owner parameter");
        return -1;
    }

    if (is_empty_string (share_user) ||
        strcmp (owner, share_user) == 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid share_user parameter");
        return -1;
    }

    if (!is_permission_valid (permission)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid permission parameter");
        return -1;
    }

    char *real_path;
    int ret = 0;

    real_path = format_dir_path (path);

    ret = seaf_share_manager_set_subdir_perm_by_path (seaf->share_mgr,
                                                      repo_id, owner, share_user,
                                                      permission, real_path);

    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to update share subdir permission for user");
    }

    g_free (real_path);
    return ret;
}

GList *
seafile_list_repo_shared_group (const char *from_user, const char *repo_id,
                                GError **error)
{

    if (!from_user || !repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Missing args");
        return NULL;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    return seaf_share_manager_list_repo_shared_group (seaf->share_mgr,
                                                      from_user, repo_id,
                                                      error);
}

int
seafile_remove_share (const char *repo_id, const char *from_email,
                      const char *to_email, GError **error)
{
    int ret;

    if (!repo_id || !from_email ||!to_email) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Missing args");
        return -1;
    }

    ret = seaf_share_manager_remove_share (seaf->share_mgr, repo_id, from_email,
                                           to_email);

    return ret;
}

/* Group repo RPC. */

int
seafile_group_share_repo (const char *repo_id, int group_id,
                          const char *user_name, const char *permission,
                          GError **error)
{
    SeafRepoManager *mgr = seaf->repo_mgr;
    int ret;

    if (group_id <= 0 || !user_name || !repo_id || !permission) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad input argument");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    if (!is_permission_valid (permission)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid permission parameter");
        return -1;
    }

    ret = seaf_repo_manager_add_group_repo (mgr, repo_id, group_id, user_name,
                                            permission, error);

    return ret;
}

int
seafile_group_unshare_repo (const char *repo_id, int group_id,
                            const char *user_name, GError **error)
{
    SeafRepoManager *mgr = seaf->repo_mgr;
    int ret;

    if (!user_name || !repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "User name and repo id can not be NULL");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    ret = seaf_repo_manager_del_group_repo (mgr, repo_id, group_id, error);

    return ret;

}

char *
seafile_share_subdir_to_group (const char *repo_id,
                               const char *path,
                               const char *owner,
                               int share_group,
                               const char *permission,
                               const char *passwd,
                               GError **error)
{
    if (is_empty_string (repo_id) || !is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid repo_id parameter");
        return NULL;
    }

    if (is_empty_string (path) || strcmp (path, "/") == 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid path parameter");
        return NULL;
    }

    if (is_empty_string (owner)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid owner parameter");
        return NULL;
    }

    if (share_group < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid share_group parameter");
        return NULL;
    }

    if (!is_permission_valid (permission)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid permission parameter");
        return NULL;
    }

    char *real_path;
    char *vrepo_name;
    char *vrepo_id;
    char* ret = NULL;

    real_path = format_dir_path (path);
    // Use subdir name as virtual repo name and description
    vrepo_name = g_path_get_basename (real_path);
    vrepo_id = seaf_repo_manager_create_virtual_repo (seaf->repo_mgr,
                                                      repo_id, real_path,
                                                      vrepo_name, vrepo_name,
                                                      owner, passwd, error);
    if (!vrepo_id)
        goto out;

    int result = seaf_repo_manager_add_group_repo (seaf->repo_mgr, vrepo_id, share_group,
                                            owner, permission, error);
    if (result < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to share subdir to group");
        g_free (vrepo_id);
    }
    else
        ret = vrepo_id;

out:
    g_free (vrepo_name);
    g_free (real_path);
    return ret;
}

int
seafile_unshare_subdir_for_group (const char *repo_id,
                                  const char *path,
                                  const char *owner,
                                  int share_group,
                                  GError **error)
{
    if (is_empty_string (repo_id) || !is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid repo_id parameter");
        return -1;
    }

    if (is_empty_string (path) || strcmp (path, "/") == 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid path parameter");
        return -1;
    }

    if (is_empty_string (owner)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid owner parameter");
        return -1;
    }

    if (share_group < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid share_group parameter");
        return -1;
    }

    char *real_path;
    int ret = 0;

    real_path = format_dir_path (path);

    ret = seaf_share_manager_unshare_group_subdir (seaf->share_mgr, repo_id,
                                                   real_path, owner, share_group);
    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to unshare subdir for group");
    }

    g_free (real_path);
    return ret;
}

int
seafile_update_share_subdir_perm_for_group (const char *repo_id,
                                            const char *path,
                                            const char *owner,
                                            int share_group,
                                            const char *permission,
                                            GError **error)
{
    if (is_empty_string (repo_id) || !is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid repo_id parameter");
        return -1;
    }

    if (is_empty_string (path) || strcmp (path, "/") == 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid path parameter");
        return -1;
    }

    if (is_empty_string (owner)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid owner parameter");
        return -1;
    }

    if (share_group < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid share_group parameter");
        return -1;
    }

    if (!is_permission_valid (permission)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid permission parameter");
        return -1;
    }

    char *real_path;
    int ret = 0;

    real_path = format_dir_path (path);
    ret = seaf_repo_manager_set_subdir_group_perm_by_path (seaf->repo_mgr,
                                                           repo_id, owner, share_group,
                                                           permission, real_path);
    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to update share subdir permission for group");
    }

    g_free (real_path);
    return ret;
}

char *
seafile_get_shared_groups_by_repo(const char *repo_id, GError **error)
{
    SeafRepoManager *mgr = seaf->repo_mgr;
    GList *group_ids = NULL, *ptr;
    GString *result;

    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return NULL;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    group_ids = seaf_repo_manager_get_groups_by_repo (mgr, repo_id, error);
    if (!group_ids) {
        return NULL;
    }

    result = g_string_new("");
    ptr = group_ids;
    while (ptr) {
        g_string_append_printf (result, "%d\n", (int)(long)ptr->data);
        ptr = ptr->next;
    }
    g_list_free (group_ids);

    return g_string_free (result, FALSE);
}

char *
seafile_get_group_repoids (int group_id, GError **error)
{
    SeafRepoManager *mgr = seaf->repo_mgr;
    GList *repo_ids = NULL, *ptr;
    GString *result;

    repo_ids = seaf_repo_manager_get_group_repoids (mgr, group_id, error);
    if (!repo_ids) {
        return NULL;
    }

    result = g_string_new("");
    ptr = repo_ids;
    while (ptr) {
        g_string_append_printf (result, "%s\n", (char *)ptr->data);
        g_free (ptr->data);
        ptr = ptr->next;
    }
    g_list_free (repo_ids);

    return g_string_free (result, FALSE);
}

GList *
seafile_get_repos_by_group (int group_id, GError **error)
{
    SeafRepoManager *mgr = seaf->repo_mgr;
    GList *ret = NULL;

    if (group_id < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid group id.");
        return NULL;
    }

    ret = seaf_repo_manager_get_repos_by_group (mgr, group_id, error);

    return ret;
}

GList *
seafile_get_group_repos_by_owner (char *user, GError **error)
{
    SeafRepoManager *mgr = seaf->repo_mgr;
    GList *ret = NULL;

    if (!user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "user name can not be NULL");
        return NULL;
    }

    ret = seaf_repo_manager_get_group_repos_by_owner (mgr, user, error);
    if (!ret) {
        return NULL;
    }

    return g_list_reverse (ret);
}

char *
seafile_get_group_repo_owner (const char *repo_id, GError **error)
{
    SeafRepoManager *mgr = seaf->repo_mgr;
    GString *result = g_string_new ("");

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    char *share_from = seaf_repo_manager_get_group_repo_owner (mgr, repo_id,
                                                               error);
    if (share_from) {
        g_string_append_printf (result, "%s", share_from);
        g_free (share_from);
    }

    return g_string_free (result, FALSE);
}

int
seafile_remove_repo_group(int group_id, const char *username, GError **error)
{
    if (group_id <= 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Wrong group id argument");
        return -1;
    }

    return seaf_repo_manager_remove_group_repos (seaf->repo_mgr,
                                                 group_id, username,
                                                 error);
}

/* Inner public repo RPC */

int
seafile_set_inner_pub_repo (const char *repo_id,
                            const char *permission,
                            GError **error)
{
    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad args");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    if (seaf_repo_manager_set_inner_pub_repo (seaf->repo_mgr,
                                              repo_id, permission) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Internal error");
        return -1;
    }

    return 0;
}

int
seafile_unset_inner_pub_repo (const char *repo_id, GError **error)
{
    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad args");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    if (seaf_repo_manager_unset_inner_pub_repo (seaf->repo_mgr, repo_id) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Internal error");
        return -1;
    }

    return 0;
}

GList *
seafile_list_inner_pub_repos (GError **error)
{
    return seaf_repo_manager_list_inner_pub_repos (seaf->repo_mgr, NULL);
}

gint64
seafile_count_inner_pub_repos (GError **error)
{
    return seaf_repo_manager_count_inner_pub_repos (seaf->repo_mgr);
}

GList *
seafile_list_inner_pub_repos_by_owner (const char *user, GError **error)
{
    if (!user) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Bad arguments");
        return NULL;
    }

    return seaf_repo_manager_list_inner_pub_repos_by_owner (seaf->repo_mgr, user);
}

int
seafile_is_inner_pub_repo (const char *repo_id, GError **error)
{
    if (!repo_id) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Bad arguments");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    return seaf_repo_manager_is_inner_pub_repo (seaf->repo_mgr, repo_id);
}

gint64
seafile_get_file_size (const char *store_id, int version,
                       const char *file_id, GError **error)
{
    gint64 file_size;

    if (!store_id || !is_uuid_valid(store_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid store id");
        return -1;
    }

    if (!file_id || !is_object_id_valid (file_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid file id");
        return -1;
    }

    file_size = seaf_fs_manager_get_file_size (seaf->fs_mgr, store_id, version, file_id);
    if (file_size < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL,
                     "failed to read file size");
        return -1;
    }

    return file_size;
}

gint64
seafile_get_dir_size (const char *store_id, int version,
                      const char *dir_id, GError **error)
{
    gint64 dir_size;

    if (!store_id || !is_uuid_valid (store_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid store id");
        return -1;
    }

    if (!dir_id || !is_object_id_valid (dir_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid dir id");
        return -1;
    }

    dir_size = seaf_fs_manager_get_fs_size (seaf->fs_mgr, store_id, version, dir_id);
    if (dir_size < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Failed to caculate dir size");
        return -1;
    }

    return dir_size;
}

int
seafile_check_passwd (const char *repo_id,
                      const char *magic,
                      GError **error)
{
    if (!repo_id || strlen(repo_id) != 36 || !magic) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return -1;
    }

    if (seaf_passwd_manager_check_passwd (seaf->passwd_mgr,
                                          repo_id, magic,
                                          error) < 0) {
        return -1;
    }

    return 0;
}

int
seafile_set_passwd (const char *repo_id,
                    const char *user,
                    const char *passwd,
                    GError **error)
{
    if (!repo_id || strlen(repo_id) != 36 || !user || !passwd) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return -1;
    }

    if (seaf_passwd_manager_set_passwd (seaf->passwd_mgr,
                                        repo_id, user, passwd,
                                        error) < 0) {
        return -1;
    }

    return 0;
}

int
seafile_unset_passwd (const char *repo_id,
                      const char *user,
                      GError **error)
{
    if (!repo_id || strlen(repo_id) != 36 || !user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return -1;
    }

    if (seaf_passwd_manager_unset_passwd (seaf->passwd_mgr,
                                          repo_id, user,
                                          error) < 0) {
        return -1;
    }

    return 0;
}

int
seafile_is_passwd_set (const char *repo_id, const char *user, GError **error)
{
    if (!repo_id || strlen(repo_id) != 36 || !user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return -1;
    }

    return seaf_passwd_manager_is_passwd_set (seaf->passwd_mgr,
                                              repo_id, user);
}

GObject *
seafile_get_decrypt_key (const char *repo_id, const char *user, GError **error)
{
    SeafileCryptKey *ret;

    if (!repo_id || strlen(repo_id) != 36 || !user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return NULL;
    }

    ret = seaf_passwd_manager_get_decrypt_key (seaf->passwd_mgr,
                                               repo_id, user);
    if (!ret) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Password was not set");
        return NULL;
    }

    return (GObject *)ret;
}

int
seafile_revert_on_server (const char *repo_id,
                          const char *commit_id,
                          const char *user_name,
                          GError **error)
{
    if (!repo_id || strlen(repo_id) != 36 ||
        !commit_id || strlen(commit_id) != 40 ||
        !user_name) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    if (!is_object_id_valid (commit_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid commit id");
        return -1;
    }

    return seaf_repo_manager_revert_on_server (seaf->repo_mgr,
                                               repo_id,
                                               commit_id,
                                               user_name,
                                               error);
}

int
seafile_post_file (const char *repo_id, const char *temp_file_path,
                   const char *parent_dir, const char *file_name,
                   const char *user,
                   GError **error)
{
    char *norm_parent_dir = NULL, *norm_file_name = NULL, *rpath = NULL;
    int ret = 0;

    if (!repo_id || !temp_file_path || !parent_dir || !file_name || !user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Argument should not be null");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    norm_parent_dir = normalize_utf8_path (parent_dir);
    if (!norm_parent_dir) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        ret = -1;
        goto out;
    }

    norm_file_name = normalize_utf8_path (file_name);
    if (!norm_file_name) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        ret = -1;
        goto out;
    }

    rpath = format_dir_path (norm_parent_dir);

    if (seaf_repo_manager_post_file (seaf->repo_mgr, repo_id,
                                     temp_file_path, rpath,
                                     norm_file_name, user,
                                     error) < 0) {
        ret = -1;
    }

out:
    g_free (norm_parent_dir);
    g_free (norm_file_name);
    g_free (rpath);

    return ret;
}

/* char * */
/* seafile_post_file_blocks (const char *repo_id, */
/*                           const char *parent_dir, */
/*                           const char *file_name, */
/*                           const char *blockids_json, */
/*                           const char *paths_json, */
/*                           const char *user, */
/*                           gint64 file_size, */
/*                           int replace_existed, */
/*                           GError **error) */
/* { */
/*     char *norm_parent_dir = NULL, *norm_file_name = NULL, *rpath = NULL; */
/*     char *new_id = NULL; */

/*     if (!repo_id || !parent_dir || !file_name */
/*         || !blockids_json || ! paths_json || !user || file_size < 0) { */
/*         g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, */
/*                      "Argument should not be null"); */
/*         return NULL; */
/*     } */

/*     if (!is_uuid_valid (repo_id)) { */
/*         g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id"); */
/*         return NULL; */
/*     } */

/*     norm_parent_dir = normalize_utf8_path (parent_dir); */
/*     if (!norm_parent_dir) { */
/*         g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, */
/*                      "Path is in valid UTF8 encoding"); */
/*         goto out; */
/*     } */

/*     norm_file_name = normalize_utf8_path (file_name); */
/*     if (!norm_file_name) { */
/*         g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, */
/*                      "Path is in valid UTF8 encoding"); */
/*         goto out; */
/*     } */

/*     rpath = format_dir_path (norm_parent_dir); */

/*     seaf_repo_manager_post_file_blocks (seaf->repo_mgr, */
/*                                         repo_id, */
/*                                         rpath, */
/*                                         norm_file_name, */
/*                                         blockids_json, */
/*                                         paths_json, */
/*                                         user, */
/*                                         file_size, */
/*                                         replace_existed, */
/*                                         &new_id, */
/*                                         error); */

/* out: */
/*     g_free (norm_parent_dir); */
/*     g_free (norm_file_name); */
/*     g_free (rpath); */

/*     return new_id; */
/* } */

char *
seafile_post_multi_files (const char *repo_id,
                          const char *parent_dir,
                          const char *filenames_json,
                          const char *paths_json,
                          const char *user,
                          int replace_existed,
                          GError **error)
{
    char *norm_parent_dir = NULL, *rpath = NULL;
    char *ret_json = NULL;

    if (!repo_id || !filenames_json || !parent_dir || !paths_json || !user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Argument should not be null");
        return NULL;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    norm_parent_dir = normalize_utf8_path (parent_dir);
    if (!norm_parent_dir) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        goto out;
    }

    rpath = format_dir_path (norm_parent_dir);

    seaf_repo_manager_post_multi_files (seaf->repo_mgr,
                                        repo_id,
                                        rpath,
                                        filenames_json,
                                        paths_json,
                                        user,
                                        replace_existed,
                                        0,
                                        &ret_json,
                                        NULL,
                                        error);

out:
    g_free (norm_parent_dir);
    g_free (rpath);

    return ret_json;
}

char *
seafile_put_file (const char *repo_id, const char *temp_file_path,
                  const char *parent_dir, const char *file_name,
                  const char *user, const char *head_id,
                  GError **error)
{
    char *norm_parent_dir = NULL, *norm_file_name = NULL, *rpath = NULL;
    char *new_file_id = NULL;

    if (!repo_id || !temp_file_path || !parent_dir || !file_name || !user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Argument should not be null");
        return NULL;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    norm_parent_dir = normalize_utf8_path (parent_dir);
    if (!norm_parent_dir) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        goto out;
    }

    norm_file_name = normalize_utf8_path (file_name);
    if (!norm_file_name) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        goto out;
    }

    rpath = format_dir_path (norm_parent_dir);

    seaf_repo_manager_put_file (seaf->repo_mgr, repo_id,
                                temp_file_path, rpath,
                                norm_file_name, user, head_id,
                                0,
                                &new_file_id, error);

out:
    g_free (norm_parent_dir);
    g_free (norm_file_name);
    g_free (rpath);

    return new_file_id;
}

/* char * */
/* seafile_put_file_blocks (const char *repo_id, const char *parent_dir, */
/*                          const char *file_name, const char *blockids_json, */
/*                          const char *paths_json, const char *user, */
/*                          const char *head_id, gint64 file_size, GError **error) */
/* { */
/*     char *norm_parent_dir = NULL, *norm_file_name = NULL, *rpath = NULL; */
/*     char *new_file_id = NULL; */

/*     if (!repo_id || !parent_dir || !file_name */
/*         || !blockids_json || ! paths_json || !user) { */
/*         g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, */
/*                      "Argument should not be null"); */
/*         return NULL; */
/*     } */

/*     if (!is_uuid_valid (repo_id)) { */
/*         g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id"); */
/*         return NULL; */
/*     } */

/*     norm_parent_dir = normalize_utf8_path (parent_dir); */
/*     if (!norm_parent_dir) { */
/*         g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, */
/*                      "Path is in valid UTF8 encoding"); */
/*         goto out; */
/*     } */

/*     norm_file_name = normalize_utf8_path (file_name); */
/*     if (!norm_file_name) { */
/*         g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, */
/*                      "Path is in valid UTF8 encoding"); */
/*         goto out; */
/*     } */

/*     rpath = format_dir_path (norm_parent_dir); */

/*     seaf_repo_manager_put_file_blocks (seaf->repo_mgr, repo_id, */
/*                                        rpath, norm_file_name, */
/*                                        blockids_json, paths_json, */
/*                                        user, head_id, file_size, */
/*                                        &new_file_id, error); */

/* out: */
/*     g_free (norm_parent_dir); */
/*     g_free (norm_file_name); */
/*     g_free (rpath); */

/*     return new_file_id; */
/* } */

int
seafile_post_dir (const char *repo_id, const char *parent_dir,
                  const char *new_dir_name, const char *user,
                  GError **error)
{
    char *norm_parent_dir = NULL, *norm_dir_name = NULL, *rpath = NULL;
    int ret = 0;

    if (!repo_id || !parent_dir || !new_dir_name || !user) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    norm_parent_dir = normalize_utf8_path (parent_dir);
    if (!norm_parent_dir) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        ret = -1;
        goto out;
    }

    norm_dir_name = normalize_utf8_path (new_dir_name);
    if (!norm_dir_name) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        ret = -1;
        goto out;
    }

    rpath = format_dir_path (norm_parent_dir);

    if (seaf_repo_manager_post_dir (seaf->repo_mgr, repo_id,
                                    rpath, norm_dir_name,
                                    user, error) < 0) {
        ret = -1;
    }

out:
    g_free (norm_parent_dir);
    g_free (norm_dir_name);
    g_free (rpath);

    return ret;
}

int
seafile_post_empty_file (const char *repo_id, const char *parent_dir,
                         const char *new_file_name, const char *user,
                         GError **error)
{
    char *norm_parent_dir = NULL, *norm_file_name = NULL, *rpath = NULL;
    int ret = 0;

    if (!repo_id || !parent_dir || !new_file_name || !user) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    norm_parent_dir = normalize_utf8_path (parent_dir);
    if (!norm_parent_dir) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        ret = -1;
        goto out;
    }

    norm_file_name = normalize_utf8_path (new_file_name);
    if (!norm_file_name) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        ret = -1;
        goto out;
    }

    rpath = format_dir_path (norm_parent_dir);

    if (seaf_repo_manager_post_empty_file (seaf->repo_mgr, repo_id,
                                           rpath, norm_file_name,
                                           user, error) < 0) {
        ret = -1;
    }

out:
    g_free (norm_parent_dir);
    g_free (norm_file_name);
    g_free (rpath);

    return ret;
}

int
seafile_del_file (const char *repo_id, const char *parent_dir,
                  const char *file_name, const char *user,
                  GError **error)
{
    char *norm_parent_dir = NULL, *norm_file_name = NULL, *rpath = NULL;
    int ret = 0;

    if (!repo_id || !parent_dir || !file_name || !user) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    norm_parent_dir = normalize_utf8_path (parent_dir);
    if (!norm_parent_dir) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        ret = -1;
        goto out;
    }

    norm_file_name = normalize_utf8_path (file_name);
    if (!norm_file_name) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        ret = -1;
        goto out;
    }

    rpath = format_dir_path (norm_parent_dir);

    if (seaf_repo_manager_del_file (seaf->repo_mgr, repo_id,
                                    rpath, norm_file_name,
                                    user, error) < 0) {
        ret = -1;
    }

out:
    g_free (norm_parent_dir);
    g_free (norm_file_name);
    g_free (rpath);

    return ret;
}

int
seafile_batch_del_files (const char *repo_id,
                         const char *filepaths,
                         const char *user,
                         GError **error)
{
    char *norm_file_list = NULL, *rpath = NULL;
    int ret = 0;

    if (!repo_id || !filepaths || !user) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }


    norm_file_list = normalize_utf8_path (filepaths);
    if (!norm_file_list) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        ret = -1;
        goto out;
    }

    if (seaf_repo_manager_batch_del_files (seaf->repo_mgr, repo_id,
                                           norm_file_list,
                                           user, error) < 0) {
        ret = -1;
    }

out:
    g_free (norm_file_list);

    return ret;
}

GObject *
seafile_copy_file (const char *src_repo_id,
                   const char *src_dir,
                   const char *src_filename,
                   const char *dst_repo_id,
                   const char *dst_dir,
                   const char *dst_filename,
                   const char *user,
                   int need_progress,
                   int synchronous,
                   GError **error)
{
    char *norm_src_dir = NULL, *norm_src_filename = NULL;
    char *norm_dst_dir = NULL, *norm_dst_filename = NULL;
    char *rsrc_dir = NULL, *rdst_dir = NULL;
    GObject *ret = NULL;

    if (!src_repo_id || !src_dir || !src_filename ||
        !dst_repo_id || !dst_dir || !dst_filename || !user) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    if (!is_uuid_valid (src_repo_id) || !is_uuid_valid(dst_repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    norm_src_dir = normalize_utf8_path (src_dir);
    if (!norm_src_dir) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        goto out;
    }

    norm_src_filename = normalize_utf8_path (src_filename);
    if (!norm_src_filename) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        goto out;
    }

    norm_dst_dir = normalize_utf8_path (dst_dir);
    if (!norm_dst_dir) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        goto out;
    }

    norm_dst_filename = normalize_utf8_path (dst_filename);
    if (!norm_dst_filename) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        goto out;
    }

    rsrc_dir = format_dir_path (norm_src_dir);
    rdst_dir = format_dir_path (norm_dst_dir);

    ret = (GObject *)seaf_repo_manager_copy_multiple_files (seaf->repo_mgr,
                                                            src_repo_id, rsrc_dir, norm_src_filename,
                                                            dst_repo_id, rdst_dir, norm_dst_filename,
                                                            user, need_progress, synchronous,
                                                            error);

out:
    g_free (norm_src_dir);
    g_free (norm_src_filename);
    g_free (norm_dst_dir);
    g_free (norm_dst_filename);
    g_free (rsrc_dir);
    g_free (rdst_dir);

    return ret;
}

GObject *
seafile_move_file (const char *src_repo_id,
                   const char *src_dir,
                   const char *src_filename,
                   const char *dst_repo_id,
                   const char *dst_dir,
                   const char *dst_filename,
                   int replace,
                   const char *user,
                   int need_progress,
                   int synchronous,
                   GError **error)
{
    char *norm_src_dir = NULL, *norm_src_filename = NULL;
    char *norm_dst_dir = NULL, *norm_dst_filename = NULL;
    char *rsrc_dir = NULL, *rdst_dir = NULL;
    GObject *ret = NULL;

    if (!src_repo_id || !src_dir || !src_filename ||
        !dst_repo_id || !dst_dir || !dst_filename || !user) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    if (!is_uuid_valid (src_repo_id) || !is_uuid_valid(dst_repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    norm_src_dir = normalize_utf8_path (src_dir);
    if (!norm_src_dir) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        goto out;
    }

    norm_src_filename = normalize_utf8_path (src_filename);
    if (!norm_src_filename) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        goto out;
    }

    norm_dst_dir = normalize_utf8_path (dst_dir);
    if (!norm_dst_dir) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        goto out;
    }

    norm_dst_filename = normalize_utf8_path (dst_filename);
    if (!norm_dst_filename) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        goto out;
    }

    rsrc_dir = format_dir_path (norm_src_dir);
    rdst_dir = format_dir_path (norm_dst_dir);

    ret = (GObject *)seaf_repo_manager_move_multiple_files (seaf->repo_mgr,
                                                            src_repo_id, rsrc_dir, norm_src_filename,
                                                            dst_repo_id, rdst_dir, norm_dst_filename,
                                                            replace, user, need_progress, synchronous,
                                                            error);

out:
    g_free (norm_src_dir);
    g_free (norm_src_filename);
    g_free (norm_dst_dir);
    g_free (norm_dst_filename);
    g_free (rsrc_dir);
    g_free (rdst_dir);

    return ret;
}

GObject *
seafile_get_copy_task (const char *task_id, GError **error)
{
    return (GObject *)seaf_copy_manager_get_task (seaf->copy_mgr, task_id);
}

int
seafile_cancel_copy_task (const char *task_id, GError **error)
{
    return seaf_copy_manager_cancel_task (seaf->copy_mgr, task_id);
}

int
seafile_rename_file (const char *repo_id,
                     const char *parent_dir,
                     const char *oldname,
                     const char *newname,
                     const char *user,
                     GError **error)
{
    char *norm_parent_dir = NULL, *norm_oldname = NULL, *norm_newname = NULL;
    char *rpath = NULL;
    int ret = 0;

    if (!repo_id || !parent_dir || !oldname || !newname || !user) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    norm_parent_dir = normalize_utf8_path (parent_dir);
    if (!norm_parent_dir) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        ret = -1;
        goto out;
    }

    norm_oldname = normalize_utf8_path (oldname);
    if (!norm_oldname) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        ret = -1;
        goto out;
    }

    norm_newname = normalize_utf8_path (newname);
    if (!norm_newname) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Path is in valid UTF8 encoding");
        ret = -1;
        goto out;
    }

    rpath = format_dir_path (norm_parent_dir);

    if (seaf_repo_manager_rename_file (seaf->repo_mgr, repo_id,
                                       rpath, norm_oldname, norm_newname,
                                       user, error) < 0) {
        ret = -1;
    }

out:
    g_free (norm_parent_dir);
    g_free (norm_oldname);
    g_free (norm_newname);
    g_free (rpath);
    return ret;
}

int
seafile_is_valid_filename (const char *repo_id,
                           const char *filename,
                           GError **error)
{
    if (!repo_id || !filename) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    int ret = seaf_repo_manager_is_valid_filename (seaf->repo_mgr,
                                                   repo_id,
                                                   filename,
                                                   error);
    return ret;
}

char *
seafile_create_repo (const char *repo_name,
                     const char *repo_desc,
                     const char *owner_email,
                     const char *passwd,
                     int enc_version,
                     const char *pwd_hash_algo,
                     const char *pwd_hash_params,
                     GError **error)
{
    if (!repo_name || !repo_desc || !owner_email) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    char *repo_id;

    repo_id = seaf_repo_manager_create_new_repo (seaf->repo_mgr,
                                                 repo_name, repo_desc,
                                                 owner_email,
                                                 passwd,
                                                 enc_version,
                                                 pwd_hash_algo,
                                                 pwd_hash_params,
                                                 error);
    return repo_id;
}

char *
seafile_create_enc_repo (const char *repo_id,
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
    if (!repo_id || !repo_name || !repo_desc || !owner_email) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    char *ret;

    ret = seaf_repo_manager_create_enc_repo (seaf->repo_mgr,
                                             repo_id, repo_name, repo_desc,
                                             owner_email,
                                             magic, random_key, salt,
                                             enc_version,
                                             pwd_hash, pwd_hash_algo, pwd_hash_params,
                                             error);
    return ret;
}

int
seafile_set_user_quota (const char *user, gint64 quota, GError **error)
{
    if (!user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return -1;
    }

    return seaf_quota_manager_set_user_quota (seaf->quota_mgr, user, quota);
}

gint64
seafile_get_user_quota (const char *user, GError **error)
{
    if (!user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return -1;
    }

    return seaf_quota_manager_get_user_quota (seaf->quota_mgr, user);
}

int
seafile_check_quota (const char *repo_id, gint64 delta, GError **error)
{
    int rc;

    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad arguments");
        return -1;
    }

    rc = seaf_quota_manager_check_quota_with_delta (seaf->quota_mgr, repo_id, delta);
    if (rc == 1)
        return -1;
    return rc;
}

GList *
seafile_list_user_quota_usage (GError **error)
{
    return seaf_repo_quota_manager_list_user_quota_usage (seaf->quota_mgr);
}

static char *
get_obj_id_by_path (const char *repo_id,
                    const char *path,
                    gboolean want_dir,
                    GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *commit = NULL;
    char *obj_id = NULL;

    if (!repo_id || !path) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return NULL;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL,
                     "Get repo error");
        goto out;
    }

    commit = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             repo->id, repo->version,
                                             repo->head->commit_id);
    if (!commit) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL,
                     "Get commit error");
        goto out;
    }

    guint32 mode = 0;
    obj_id = seaf_fs_manager_path_to_obj_id (seaf->fs_mgr,
                                             repo->store_id, repo->version,
                                             commit->root_id,
                                             path, &mode, error);

out:
    if (repo)
        seaf_repo_unref (repo);
    if (commit)
        seaf_commit_unref (commit);
    if (obj_id) {
        /* check if the mode matches */
        if ((want_dir && !S_ISDIR(mode)) || ((!want_dir) && S_ISDIR(mode))) {
            g_free (obj_id);
            return NULL;
        }
    }

    return obj_id;
}

char *seafile_get_file_id_by_path (const char *repo_id,
                                   const char *path,
                                   GError **error)
{
    if (!repo_id || !path) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return NULL;
    }

    char *rpath = format_dir_path (path);
    char *ret = get_obj_id_by_path (repo_id, rpath, FALSE, error);

    g_free (rpath);

    filter_error (error);

    return ret;
}

char *seafile_get_dir_id_by_path (const char *repo_id,
                                  const char *path,
                                  GError **error)
{
    if (!repo_id || !path) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return NULL;
    }

    char *rpath = format_dir_path (path);
    char *ret = get_obj_id_by_path (repo_id, rpath, TRUE, error);

    g_free (rpath);

    filter_error (error);

    return ret;
}

GObject *
seafile_get_dirent_by_path (const char *repo_id, const char *path,
                            GError **error)
{
    if (!repo_id || !path) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return NULL;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "invalid repo id");
        return NULL;
    }

    char *rpath = format_dir_path (path);
    if (strcmp (rpath, "/") == 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "invalid path");
        g_free (rpath);
        return NULL;
    }

    SeafRepo *repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL,
                     "Get repo error");
        return NULL;
    }

    SeafCommit *commit = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                         repo->id, repo->version,
                                                         repo->head->commit_id);
    if (!commit) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL,
                     "Get commit error");
        seaf_repo_unref (repo);
        return NULL;
    }

    SeafDirent *dirent = seaf_fs_manager_get_dirent_by_path (seaf->fs_mgr,
                                                             repo->store_id, repo->version,
                                                             commit->root_id, rpath,
                                                             error);
    g_free (rpath);

    if (!dirent) {
        filter_error (error);
        seaf_repo_unref (repo);
        seaf_commit_unref (commit);
        return NULL;
    }

    GObject *obj = g_object_new (SEAFILE_TYPE_DIRENT,
                                 "obj_id", dirent->id,
                                 "obj_name", dirent->name,
                                 "mode", dirent->mode,
                                 "version", dirent->version,
                                 "mtime", dirent->mtime,
                                 "size", dirent->size,
                                 "modifier", dirent->modifier,
                                 NULL);

    seaf_repo_unref (repo);
    seaf_commit_unref (commit);
    seaf_dirent_free (dirent);

    return obj;
}

char *
seafile_list_file_blocks (const char *repo_id,
                          const char *file_id,
                          int offset, int limit,
                          GError **error)
{
    SeafRepo *repo;
    Seafile *file;
    GString *buf = g_string_new ("");
    int index = 0;

    if (!repo_id || !is_uuid_valid(repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_DIR_ID, "Bad repo id");
        return NULL;
    }

    if (!file_id || !is_object_id_valid(file_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_DIR_ID, "Bad file id");
        return NULL;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad repo id");
        return NULL;
    }

    file = seaf_fs_manager_get_seafile (seaf->fs_mgr,
                                        repo->store_id,
                                        repo->version, file_id);
    if (!file) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_DIR_ID, "Bad file id");
        seaf_repo_unref (repo);
        return NULL;
    }

    if (offset < 0)
        offset = 0;

    for (index = 0; index < file->n_blocks; index++) {
        if (index < offset) {
            continue;
        }

        if (limit > 0) {
            if (index >= offset + limit)
                break;
        }
        g_string_append_printf (buf, "%s\n", file->blk_sha1s[index]);
    }

    seafile_unref (file);
    seaf_repo_unref (repo);
    return g_string_free (buf, FALSE);
}

/*
 * Directories are always before files. Otherwise compare the names.
 */
static gint
comp_dirent_func (gconstpointer a, gconstpointer b)
{
    const SeafDirent *dent_a = a, *dent_b = b;

    if (S_ISDIR(dent_a->mode) && S_ISREG(dent_b->mode))
        return -1;

    if (S_ISREG(dent_a->mode) && S_ISDIR(dent_b->mode))
        return 1;

    return strcasecmp (dent_a->name, dent_b->name);
}

GList *
seafile_list_dir (const char *repo_id,
                  const char *dir_id, int offset, int limit, GError **error)
{
    SeafRepo *repo;
    SeafDir *dir;
    SeafDirent *dent;
    SeafileDirent *d;
    GList *res = NULL;
    GList *p;

    if (!repo_id || !is_uuid_valid(repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_DIR_ID, "Bad repo id");
        return NULL;
    }

    if (!dir_id || !is_object_id_valid (dir_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_DIR_ID, "Bad dir id");
        return NULL;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad repo id");
        return NULL;
    }

    dir = seaf_fs_manager_get_seafdir (seaf->fs_mgr,
                                       repo->store_id, repo->version, dir_id);
    if (!dir) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_DIR_ID, "Bad dir id");
        seaf_repo_unref (repo);
        return NULL;
    }

    dir->entries = g_list_sort (dir->entries, comp_dirent_func);

    if (offset < 0) {
        offset = 0;
    }

    int index = 0;
    for (p = dir->entries; p != NULL; p = p->next, index++) {
        if (index < offset) {
            continue;
        }

        if (limit > 0) {
            if (index >= offset + limit)
                break;
        }

        dent = p->data;

        if (!is_object_id_valid (dent->id))
            continue;

        d = g_object_new (SEAFILE_TYPE_DIRENT,
                          "obj_id", dent->id,
                          "obj_name", dent->name,
                          "mode", dent->mode,
                          "version", dent->version,
                          "mtime", dent->mtime,
                          "size", dent->size,
                          "permission", "",
                          NULL);
        res = g_list_prepend (res, d);
    }

    seaf_dir_free (dir);
    seaf_repo_unref (repo);
    res = g_list_reverse (res);
    return res;
}

GList *
seafile_list_file_revisions (const char *repo_id,
                             const char *commit_id,
                             const char *path,
                             int limit,
                             GError **error)
{
    if (!repo_id || !path) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return NULL;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    char *rpath = format_dir_path (path);

    GList *commit_list;
    commit_list = seaf_repo_manager_list_file_revisions (seaf->repo_mgr,
                                                         repo_id, commit_id, rpath,
                                                         limit, FALSE, FALSE, error);
    g_free (rpath);

    return commit_list;
}

GList *
seafile_calc_files_last_modified (const char *repo_id,
                                  const char *parent_dir,
                                  int limit,
                                  GError **error)
{
    if (!repo_id || !parent_dir) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return NULL;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    char *rpath = format_dir_path (parent_dir);

    GList *ret = seaf_repo_manager_calc_files_last_modified (seaf->repo_mgr,
                                                             repo_id, rpath,
                                                             limit, error);
    g_free (rpath);

    return ret;
}

int
seafile_revert_file (const char *repo_id,
                     const char *commit_id,
                     const char *path,
                     const char *user,
                     GError **error)
{
    if (!repo_id || !commit_id || !path || !user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    if (!is_object_id_valid (commit_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid commit id");
        return -1;
    }

    char *rpath = format_dir_path (path);

    int ret = seaf_repo_manager_revert_file (seaf->repo_mgr,
                                             repo_id, commit_id,
                                             rpath, user, error);
    g_free (rpath);

    return ret;
}

int
seafile_revert_dir (const char *repo_id,
                    const char *commit_id,
                    const char *path,
                    const char *user,
                    GError **error)
{
    if (!repo_id || !commit_id || !path || !user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    if (!is_object_id_valid (commit_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid commit id");
        return -1;
    }

    char *rpath = format_dir_path (path);

    int ret = seaf_repo_manager_revert_dir (seaf->repo_mgr,
                                            repo_id, commit_id,
                                            rpath, user, error);
    g_free (rpath);

    return ret;
}


char *
seafile_check_repo_blocks_missing (const char *repo_id,
                                   const char *blockids_json,
                                   GError **error)
{
    json_t *array, *value, *ret_json;
    json_error_t err;
    size_t index;
    char *json_data, *ret;
    SeafRepo *repo = NULL;

    array = json_loadb (blockids_json, strlen(blockids_json), 0, &err);
    if (!array) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return NULL;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Failed to get repo %.8s.\n", repo_id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Repo not found");
        json_decref (array);
        return NULL;
    }

    ret_json = json_array();
    size_t n = json_array_size (array);
    for (index = 0; index < n; index++) {
        value = json_array_get (array, index);
        const char *blockid = json_string_value (value);
        if (!blockid)
            continue;
        if (!seaf_block_manager_block_exists(seaf->block_mgr, repo_id,
                                             repo->version, blockid)) {
            json_array_append_new (ret_json, json_string(blockid));
        }
    }

    json_data = json_dumps (ret_json, 0);
    ret = g_strdup (json_data);

    free (json_data);
    json_decref (ret_json);
    json_decref (array);
    seaf_repo_unref (repo);
    return ret;
}


GList *
seafile_get_deleted (const char *repo_id, int show_days,
                     const char *path, const char *scan_stat,
                     int limit, GError **error)
{
    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return NULL;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    char *rpath = NULL;
    if (path)
        rpath = format_dir_path (path);

    GList *ret = seaf_repo_manager_get_deleted_entries (seaf->repo_mgr,
                                                        repo_id, show_days,
                                                        rpath, scan_stat,
                                                        limit, error);
    g_free (rpath);

    return ret;
}

char *
seafile_generate_repo_token (const char *repo_id,
                             const char *email,
                             GError **error)
{
    char *token;

    if (!repo_id || !email) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments should not be empty");
        return NULL;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    token = seaf_repo_manager_generate_repo_token (seaf->repo_mgr, repo_id, email, error);

    return token;
}

int
seafile_delete_repo_token (const char *repo_id,
                           const char *token,
                           const char *user,
                           GError **error)
{
    if (!repo_id || !token || !user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments should not be empty");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    return seaf_repo_manager_delete_token (seaf->repo_mgr,
                                           repo_id, token, user, error);
}

GList *
seafile_list_repo_tokens (const char *repo_id,
                          GError **error)
{
    GList *ret_list;

    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments should not be empty");
        return NULL;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    ret_list = seaf_repo_manager_list_repo_tokens (seaf->repo_mgr, repo_id, error);

    return ret_list;
}

GList *
seafile_list_repo_tokens_by_email (const char *email,
                                   GError **error)
{
    GList *ret_list;

    if (!email) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments should not be empty");
        return NULL;
    }

    ret_list = seaf_repo_manager_list_repo_tokens_by_email (seaf->repo_mgr, email, error);

    return ret_list;
}

int
seafile_delete_repo_tokens_by_peer_id(const char *email,
                                      const char *peer_id,
                                      GError **error)
{
    if (!email || !peer_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments should not be empty");
        return -1;
    }

    /* check the peer id */
    if (strlen(peer_id) != 40) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "invalid peer id");
        return -1;
    }
    const char *c = peer_id;
    while (*c) {
        char v = *c;
        if ((v >= '0' && v <= '9') || (v >= 'a' && v <= 'z')) {
            c++;
            continue;
        } else {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "invalid peer id");
            return -1;
        }
    }

    GList *tokens = NULL;
    if (seaf_repo_manager_delete_repo_tokens_by_peer_id (seaf->repo_mgr, email, peer_id, &tokens, error) < 0) {
        g_list_free_full (tokens, (GDestroyNotify)g_free);
        return -1;
    }

#ifdef HAVE_EVHTP
    seaf_http_server_invalidate_tokens(seaf->http_server, tokens);
#endif
    g_list_free_full (tokens, (GDestroyNotify)g_free);
    return 0;
}

int
seafile_delete_repo_tokens_by_email (const char *email,
                                     GError **error)
{
    if (!email) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments should not be empty");
        return -1;
    }

    return seaf_repo_manager_delete_repo_tokens_by_email (seaf->repo_mgr, email, error);
}

char *
seafile_check_permission (const char *repo_id, const char *user, GError **error)
{
    if (!repo_id || !user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments should not be empty");
        return NULL;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    if (strlen(user) == 0)
        return NULL;

    return seaf_repo_manager_check_permission (seaf->repo_mgr,
                                               repo_id, user, error);
}

char *
seafile_check_permission_by_path (const char *repo_id, const char *path,
                                  const char *user, GError **error)
{
    return seafile_check_permission (repo_id, user, error);
}

GList *
seafile_list_dir_with_perm (const char *repo_id,
                            const char *path,
                            const char *dir_id,
                            const char *user,
                            int offset,
                            int limit,
                            GError **error)
{
    if (!repo_id || !is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    if (!path) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid path");
        return NULL;
    }

    if (!dir_id || !is_object_id_valid (dir_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid dir id");
        return NULL;
    }

    if (!user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid user");
        return NULL;
    }

    char *rpath = format_dir_path (path);

    GList *ret = seaf_repo_manager_list_dir_with_perm (seaf->repo_mgr,
                                                       repo_id,
                                                       rpath,
                                                       dir_id,
                                                       user,
                                                       offset,
                                                       limit,
                                                       error);
    g_free (rpath);

    return ret;
}

int
seafile_set_share_permission (const char *repo_id,
                              const char *from_email,
                              const char *to_email,
                              const char *permission,
                              GError **error)
{
    if (!repo_id || !from_email || !to_email || !permission) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments should not be empty");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid repo_id parameter");
        return -1;
    }

    if (!is_permission_valid (permission)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid permission parameter");
        return -1;
    }

    return seaf_share_manager_set_permission (seaf->share_mgr,
                                              repo_id,
                                              from_email,
                                              to_email,
                                              permission);
}

int
seafile_set_group_repo_permission (int group_id,
                                   const char *repo_id,
                                   const char *permission,
                                   GError **error)
{
    if (!repo_id || !permission) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments should not be empty");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    if (!is_permission_valid (permission)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid permission parameter");
        return -1;

    }

    return seaf_repo_manager_set_group_repo_perm (seaf->repo_mgr,
                                                  repo_id,
                                                  group_id,
                                                  permission,
                                                  error);
}

char *
seafile_get_file_id_by_commit_and_path(const char *repo_id,
                                       const char *commit_id,
                                       const char *path,
                                       GError **error)
{
    SeafRepo *repo;
    SeafCommit *commit;
    char *file_id;
    guint32 mode;

    if (!repo_id || !is_uuid_valid(repo_id) || !commit_id || !path) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Arguments should not be empty");
        return NULL;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad repo id");
        return NULL;
    }

    commit = seaf_commit_manager_get_commit(seaf->commit_mgr,
                                            repo_id,
                                            repo->version,
                                            commit_id);
    if (!commit) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "bad commit id");
        seaf_repo_unref (repo);
        return NULL;
    }

    char *rpath = format_dir_path (path);

    file_id = seaf_fs_manager_path_to_obj_id (seaf->fs_mgr,
                                              repo->store_id, repo->version,
                                              commit->root_id, rpath, &mode, error);
    if (file_id && S_ISDIR(mode)) {
        g_free (file_id);
        file_id = NULL;
    }
    g_free (rpath);

    filter_error (error);

    seaf_commit_unref(commit);
    seaf_repo_unref (repo);

    return file_id;
}

/* Virtual repo related */

char *
seafile_create_virtual_repo (const char *origin_repo_id,
                             const char *path,
                             const char *repo_name,
                             const char *repo_desc,
                             const char *owner,
                             const char *passwd,
                             GError **error)
{
    if (!origin_repo_id || !path ||!repo_name || !repo_desc || !owner) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    if (!is_uuid_valid (origin_repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    char *repo_id;
    char *rpath = format_dir_path (path);

    repo_id = seaf_repo_manager_create_virtual_repo (seaf->repo_mgr,
                                                     origin_repo_id, rpath,
                                                     repo_name, repo_desc,
                                                     owner, passwd, error);
    g_free (rpath);

    return repo_id;
}

GList *
seafile_get_virtual_repos_by_owner (const char *owner, GError **error)
{
    GList *repos, *ret = NULL, *ptr;
    SeafRepo *r, *o;
    SeafileRepo *repo;
    char *orig_repo_id;
    gboolean is_original_owner;

    if (!owner) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    repos = seaf_repo_manager_get_virtual_repos_by_owner (seaf->repo_mgr,
                                                          owner,
                                                          error);
    for (ptr = repos; ptr != NULL; ptr = ptr->next) {
        r = ptr->data;

        orig_repo_id = r->virtual_info->origin_repo_id;
        o = seaf_repo_manager_get_repo (seaf->repo_mgr, orig_repo_id);
        if (!o) {
            seaf_warning ("Failed to get origin repo %.10s.\n", orig_repo_id);
            seaf_repo_unref (r);
            continue;
        }

        char *orig_owner = seaf_repo_manager_get_repo_owner (seaf->repo_mgr,
                                                             orig_repo_id);
        if (g_strcmp0 (orig_owner, owner) == 0)
            is_original_owner = TRUE;
        else
            is_original_owner = FALSE;
        g_free (orig_owner);

        char *perm = seaf_repo_manager_check_permission (seaf->repo_mgr,
                                                         r->id, owner, NULL);

        repo = (SeafileRepo *)convert_repo (r);
        if (repo) {
            g_object_set (repo, "is_original_owner", is_original_owner,
                          "origin_repo_name", o->name,
                          "virtual_perm", perm, NULL);
            ret = g_list_prepend (ret, repo);
        }

        seaf_repo_unref (r);
        seaf_repo_unref (o);
        g_free (perm);
    }
    g_list_free (repos);

    return g_list_reverse (ret);
}

GObject *
seafile_get_virtual_repo (const char *origin_repo,
                          const char *path,
                          const char *owner,
                          GError **error)
{
    char *repo_id;
    GObject *repo_obj;

    char *rpath = format_dir_path (path);

    repo_id = seaf_repo_manager_get_virtual_repo_id (seaf->repo_mgr,
                                                     origin_repo,
                                                     rpath,
                                                     owner);
    g_free (rpath);

    if (!repo_id)
        return NULL;

    repo_obj = seafile_get_repo (repo_id, error);

    g_free (repo_id);
    return repo_obj;
}

/* System default library */

char *
seafile_get_system_default_repo_id (GError **error)
{
    return get_system_default_repo_id(seaf);
}

static int
update_valid_since_time (SeafRepo *repo, gint64 new_time)
{
    int ret = 0;
    gint64 old_time = seaf_repo_manager_get_repo_valid_since (repo->manager,
                                                              repo->id);

    if (new_time > 0) {
        if (new_time > old_time)
            ret = seaf_repo_manager_set_repo_valid_since (repo->manager,
                                                          repo->id,
                                                          new_time);
    } else if (new_time == 0) {
        /* Only the head commit is valid after GC if no history is kept. */
        SeafCommit *head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                           repo->id, repo->version,
                                                           repo->head->commit_id);
        if (head && (old_time < 0 || head->ctime > (guint64)old_time))
            ret = seaf_repo_manager_set_repo_valid_since (repo->manager,
                                                          repo->id,
                                                          head->ctime);
        seaf_commit_unref (head);
    }

    return ret;
}

/* Clean up a repo's history.
 * It just set valid-since time but not actually delete the data.
 */
int
seafile_clean_up_repo_history (const char *repo_id, int keep_days, GError **error)
{
    SeafRepo *repo;
    int ret;

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid arguments");
        return -1;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Cannot find repo %s.\n", repo_id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid arguments");
        return -1;
    }

    gint64 truncate_time, now;
    if (keep_days > 0) {
        now = (gint64)time(NULL);
        truncate_time = now - keep_days * 24 * 3600;
    } else
        truncate_time = 0;

    ret = update_valid_since_time (repo, truncate_time);
    if (ret < 0) {
        seaf_warning ("Failed to update valid since time for repo %.8s.\n", repo->id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Database error");
    }

    seaf_repo_unref (repo);
    return ret;
}

GList *
seafile_get_shared_users_for_subdir (const char *repo_id,
                                     const char *path,
                                     const char *from_user,
                                     GError **error)
{
    if (!repo_id || !path || !from_user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo_id");
        return NULL;
    }

    char *rpath = format_dir_path (path);

    GList *ret = seaf_repo_manager_get_shared_users_for_subdir (seaf->repo_mgr,
                                                                repo_id, rpath,
                                                                from_user, error);
    g_free (rpath);

    return ret;
}

GList *
seafile_get_shared_groups_for_subdir (const char *repo_id,
                                      const char *path,
                                      const char *from_user,
                                      GError **error)
{
    if (!repo_id || !path || !from_user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo_id");
        return NULL;
    }

    char *rpath = format_dir_path (path);

    GList *ret = seaf_repo_manager_get_shared_groups_for_subdir (seaf->repo_mgr,
                                                                 repo_id, rpath,
                                                                 from_user, error);
    g_free (rpath);

    return ret;
}

gint64
seafile_get_total_file_number (GError **error)
{
    return seaf_get_total_file_number (error);
}

gint64
seafile_get_total_storage (GError **error)
{
    return seaf_get_total_storage (error);
}

GObject *
seafile_get_file_count_info_by_path (const char *repo_id,
                                     const char *path,
                                     GError **error)
{
    if (!repo_id || !path) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    GObject *ret = NULL;
    SeafRepo *repo = NULL;
    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Failed to get repo %.10s\n", repo_id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Library not exists");
        return NULL;
    }

    ret = seaf_fs_manager_get_file_count_info_by_path (seaf->fs_mgr,
                                                       repo->store_id,
                                                       repo->version,
                                                       repo->root_id,
                                                       path, error);
    seaf_repo_unref (repo);

    return ret;
}

char *
seafile_get_trash_repo_owner (const char *repo_id, GError **error)
{
    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    return seaf_get_trash_repo_owner (repo_id);
}

int
seafile_mkdir_with_parents (const char *repo_id, const char *parent_dir,
                            const char *new_dir_path, const char *user,
                            GError **error)
{
    if (!repo_id || !parent_dir || !new_dir_path || !user) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    if (seaf_repo_manager_mkdir_with_parents (seaf->repo_mgr, repo_id,
                                              parent_dir, new_dir_path,
                                              user, error) < 0) {
        return -1;
    }

    return 0;
}

int
seafile_set_server_config_int (const char *group, const char *key, int value,
                               GError **error)
{
    if (!group || !key) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    return seaf_cfg_manager_set_config_int (seaf->cfg_mgr, group, key, value);
}

int
seafile_get_server_config_int (const char *group, const char *key, GError **error)
{
    if (!group || !key ) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    return seaf_cfg_manager_get_config_int (seaf->cfg_mgr, group, key);
}

int
seafile_set_server_config_int64 (const char *group, const char *key, gint64 value,
                                 GError **error)
{
    if (!group || !key) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    return seaf_cfg_manager_set_config_int64 (seaf->cfg_mgr, group, key, value);
}

gint64
seafile_get_server_config_int64 (const char *group, const char *key, GError **error)
{
    if (!group || !key ) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    return seaf_cfg_manager_get_config_int64 (seaf->cfg_mgr, group, key);
}

int
seafile_set_server_config_string (const char *group, const char *key, const char *value,
                                  GError **error)
{
    if (!group || !key || !value) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    return seaf_cfg_manager_set_config_string (seaf->cfg_mgr, group, key, value);
}

char *
seafile_get_server_config_string (const char *group, const char *key, GError **error)
{
    if (!group || !key ) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    return seaf_cfg_manager_get_config_string (seaf->cfg_mgr, group, key);
}

int
seafile_set_server_config_boolean (const char *group, const char *key, int value,
                                   GError **error)
{
    if (!group || !key) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    return seaf_cfg_manager_set_config_boolean (seaf->cfg_mgr, group, key, value);
}

int
seafile_get_server_config_boolean (const char *group, const char *key, GError **error)
{
    if (!group || !key ) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    return seaf_cfg_manager_get_config_boolean (seaf->cfg_mgr, group, key);
}

GObject *
seafile_get_group_shared_repo_by_path (const char *repo_id,
                                       const char *path,
                                       int group_id,
                                       int is_org,
                                       GError **error)
{
    if (!repo_id || group_id < 0) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Arguments error");
        return NULL;
    }
    SeafRepoManager *mgr = seaf->repo_mgr;

    return seaf_get_group_shared_repo_by_path (mgr, repo_id, path, group_id, is_org ? TRUE:FALSE, error);
}

GObject *
seafile_get_shared_repo_by_path (const char *repo_id,
                                 const char *path,
                                 const char *shared_to,
                                 int is_org,
                                 GError **error)
{
    if (!repo_id || !shared_to) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Arguments error");
        return NULL;
    }
    SeafRepoManager *mgr = seaf->repo_mgr;

    return seaf_get_shared_repo_by_path (mgr, repo_id, path, shared_to, is_org ? TRUE:FALSE, error);
}

GList *
seafile_get_group_repos_by_user (const char *user, GError **error)
{
    if (!user) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Arguments error");
        return NULL;
    }
    SeafRepoManager *mgr = seaf->repo_mgr;

    return seaf_get_group_repos_by_user (mgr, user, -1, error);
}

GList *
seafile_get_org_group_repos_by_user (const char *user, int org_id, GError **error)
{
    if (!user) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Arguments error");
        return NULL;
    }
    SeafRepoManager *mgr = seaf->repo_mgr;

    return seaf_get_group_repos_by_user (mgr, user, org_id, error);
}

int
seafile_repo_has_been_shared (const char *repo_id, int including_groups, GError **error)
{
    if (!repo_id) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Arguments error");
        return FALSE;
    }

    gboolean exists = seaf_share_manager_repo_has_been_shared (seaf->share_mgr, repo_id,
                                                               including_groups ? TRUE : FALSE);
    return exists ? 1 : 0;
}

GList *
seafile_get_shared_users_by_repo (const char *repo_id, GError **error)
{
    if (!repo_id) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Arguments error");
        return NULL;
    }

    return seaf_share_manager_get_shared_users_by_repo (seaf->share_mgr,
                                                        repo_id);
}

GList *
seafile_org_get_shared_users_by_repo (int org_id,
                                      const char *repo_id,
                                      GError **error)
{
    if (!repo_id || org_id < 0) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Arguments error");
        return NULL;
    }

    return seaf_share_manager_org_get_shared_users_by_repo (seaf->share_mgr,
                                                            org_id, repo_id);
}

/* Resumable file upload. */

gint64
seafile_get_upload_tmp_file_offset (const char *repo_id, const char *file_path,
                                    GError **error)
{
    if (!repo_id || !is_uuid_valid(repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid repo id");
        return -1;
    }

    int path_len;
    if (!file_path || (path_len = strlen(file_path)) == 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid file path");
        return -1;
    }

    char *rfile_path = format_dir_path (file_path);
    gint64 ret = seaf_repo_manager_get_upload_tmp_file_offset (seaf->repo_mgr, repo_id,
                                                               rfile_path, error);
    g_free (rfile_path);

    return ret;
}

char *
seafile_convert_repo_path (const char *repo_id,
                           const char *path,
                           const char *user,
                           int is_org,
                           GError **error)
{
    if (!is_uuid_valid(repo_id) || !path || !user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments error");
        return NULL;
    }

    char *rpath = format_dir_path (path);
    char *ret = seaf_repo_manager_convert_repo_path(seaf->repo_mgr, repo_id, rpath, user, is_org ? TRUE : FALSE, error);
    g_free(rpath);

    return ret;
}

int
seafile_set_repo_status(const char *repo_id, int status, GError **error)
{
    if (!is_uuid_valid(repo_id) ||
        status < 0 || status >= N_REPO_STATUS) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments error");
        return -1;
    }

    return seaf_repo_manager_set_repo_status(seaf->repo_mgr, repo_id, status);
}

int
seafile_get_repo_status(const char *repo_id, GError **error)
{
    int status;

    if (!is_uuid_valid(repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments error");
        return -1;
    }

    status = seaf_repo_manager_get_repo_status(seaf->repo_mgr, repo_id);

    return (status == -1) ? 0 : status;
}

GList *
seafile_search_files (const char *repo_id, const char *str, GError **error)
{
    return seafile_search_files_by_path (repo_id, NULL, str, error);
}

GList *
seafile_search_files_by_path (const char *repo_id, const char *path, const char *str, GError **error)
{
    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    GList *file_list = seaf_fs_manager_search_files_by_path (seaf->fs_mgr, repo_id, path, str);
    GList *ret = NULL, *ptr;

    for (ptr = file_list; ptr; ptr=ptr->next) {
        SearchResult *sr = ptr->data;
        SeafileSearchResult *search_result = seafile_search_result_new ();
        g_object_set (search_result, "path", sr->path, "size", sr->size,
                      "mtime", sr->mtime, "is_dir", sr->is_dir, NULL);

        ret = g_list_prepend (ret, search_result);
        g_free (sr->path);
        g_free (sr);
    }

    return g_list_reverse (ret);
}

/*RPC functions merged from ccnet-server*/
int
ccnet_rpc_add_emailuser (const char *email, const char *passwd,
                         int is_staff, int is_active, GError **error)
{
    CcnetUserManager *user_mgr = seaf->user_mgr; 
    int ret;
    
    if (!email || !passwd) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Email and passwd can not be NULL");
        return -1;
    }

    ret = ccnet_user_manager_add_emailuser (user_mgr, email, passwd,
                                            is_staff, is_active);
    
    return ret;
}

int
ccnet_rpc_remove_emailuser (const char *source, const char *email, GError **error)
{
    CcnetUserManager *user_mgr = seaf->user_mgr; 
    int ret;

    if (!email) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Email can not be NULL");
        return -1;
    }

    ret = ccnet_user_manager_remove_emailuser (user_mgr, source, email);

    return ret;
}

int
ccnet_rpc_validate_emailuser (const char *email, const char *passwd, GError **error)
{
   CcnetUserManager *user_mgr = seaf->user_mgr; 
    int ret;
    
    if (!email || !passwd) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Email and passwd can not be NULL");
        return -1;
    }

    if (passwd[0] == 0)
        return -1;

    ret = ccnet_user_manager_validate_emailuser (user_mgr, email, passwd);

    return ret;
}

GObject*
ccnet_rpc_get_emailuser (const char *email, GError **error)
{
    if (!email) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Email can not be NULL");
        return NULL;
    }

    CcnetUserManager *user_mgr = seaf->user_mgr;
    CcnetEmailUser *emailuser = NULL;
    
    emailuser = ccnet_user_manager_get_emailuser (user_mgr, email, error);
    
    return (GObject *)emailuser;
}

GObject*
ccnet_rpc_get_emailuser_with_import (const char *email, GError **error)
{
    if (!email) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Email can not be NULL");
        return NULL;
    }

    CcnetUserManager *user_mgr = seaf->user_mgr;
    CcnetEmailUser *emailuser = NULL;

    emailuser = ccnet_user_manager_get_emailuser_with_import (user_mgr, email, error);

    return (GObject *)emailuser;
}

GObject*
ccnet_rpc_get_emailuser_by_id (int id, GError **error)
{
   CcnetUserManager *user_mgr = seaf->user_mgr; 
    CcnetEmailUser *emailuser = NULL;
    
    emailuser = ccnet_user_manager_get_emailuser_by_id (user_mgr, id);
    
    return (GObject *)emailuser;
}

GList*
ccnet_rpc_get_emailusers (const char *source,
                          int start, int limit,
                          const char *status,
                          GError **error)
{
   CcnetUserManager *user_mgr = seaf->user_mgr; 
    GList *emailusers = NULL;

    emailusers = ccnet_user_manager_get_emailusers (user_mgr, source, start, limit, status);
    
    return emailusers;
}

GList*
ccnet_rpc_search_emailusers (const char *source,
                             const char *email_patt,
                             int start, int limit,
                             GError **error)
{
    CcnetUserManager *user_mgr = seaf->user_mgr; 
    GList *emailusers = NULL;

    emailusers = ccnet_user_manager_search_emailusers (user_mgr,
                                                       source,
                                                       email_patt,
                                                       start, limit);
    
    return emailusers;
}

GList*
ccnet_rpc_search_groups (const char *group_patt,
                         int start, int limit,
                         GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    GList *groups = NULL;

    groups = ccnet_group_manager_search_groups (group_mgr,
                                                group_patt,
                                                start, limit);
    return groups;
}

GList *
ccnet_rpc_search_group_members (int group_id, const char *pattern, GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    GList *ret = NULL;

    ret = ccnet_group_manager_search_group_members (group_mgr, group_id, pattern);

    return ret;
}

GList*
ccnet_rpc_get_top_groups (int including_org, GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    GList *groups = NULL;

    groups = ccnet_group_manager_get_top_groups (group_mgr, including_org ? TRUE : FALSE, error);

    return groups;
}

GList*
ccnet_rpc_get_child_groups (int group_id, GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    GList *groups = NULL;

    groups = ccnet_group_manager_get_child_groups (group_mgr, group_id, error);

    return groups;
}

GList*
ccnet_rpc_get_descendants_groups(int group_id, GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    GList *groups = NULL;

    groups = ccnet_group_manager_get_descendants_groups (group_mgr, group_id, error);

    return groups;
}

GList*
ccnet_rpc_search_ldapusers (const char *keyword,
                            int start, int limit,
                            GError **error)
{
    GList *ldapusers = NULL;
    CcnetUserManager *user_mgr = seaf->user_mgr;

    ldapusers = ccnet_user_manager_search_ldapusers (user_mgr, keyword,
                                                     start, limit);
    return ldapusers;
}

gint64
ccnet_rpc_count_emailusers (const char *source, GError **error)
{
   CcnetUserManager *user_mgr = seaf->user_mgr; 

   return ccnet_user_manager_count_emailusers (user_mgr, source);
}

gint64
ccnet_rpc_count_inactive_emailusers (const char *source, GError **error)
{
   CcnetUserManager *user_mgr = seaf->user_mgr;

   return ccnet_user_manager_count_inactive_emailusers (user_mgr, source);
}

int
ccnet_rpc_update_emailuser (const char *source, int id, const char* passwd,
                            int is_staff, int is_active,
                            GError **error)
{
    CcnetUserManager *user_mgr = seaf->user_mgr;

    return ccnet_user_manager_update_emailuser(user_mgr, source, id, passwd,
                                               is_staff, is_active);
}

int
ccnet_rpc_update_role_emailuser (const char* email, const char* role,
                            GError **error)
{
    CcnetUserManager *user_mgr = seaf->user_mgr;

    return ccnet_user_manager_update_role_emailuser(user_mgr, email, role);
}

GList*
ccnet_rpc_get_superusers (GError **error)
{
    CcnetUserManager *user_mgr = seaf->user_mgr; 

    return ccnet_user_manager_get_superusers(user_mgr);
}

GList *
ccnet_rpc_get_emailusers_in_list(const char *source, const char *user_list, GError **error)
{
    if (!user_list || !source) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return NULL;
    }
    CcnetUserManager *user_mgr = seaf->user_mgr;

    return ccnet_user_manager_get_emailusers_in_list (user_mgr, source, user_list, error);
}

int
ccnet_rpc_update_emailuser_id (const char *old_email, const char *new_email, GError **error)
{
    if (!old_email || !new_email) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return -1;
    }
    CcnetUserManager *user_mgr = seaf->user_mgr;

    return ccnet_user_manager_update_emailuser_id (user_mgr, old_email, new_email, error);
}

int
ccnet_rpc_create_group (const char *group_name, const char *user_name,
                        const char *type, int parent_group_id, GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    int ret;

    if (!group_name || !user_name) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL,
                     "Group name and user name can not be NULL");
        return -1;
    }

    ret = ccnet_group_manager_create_group (group_mgr, group_name, user_name, parent_group_id, error);

    return ret;
}

int
ccnet_rpc_create_org_group (int org_id, const char *group_name,
                            const char *user_name, int parent_group_id, GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    int ret;

    if (org_id < 0 || !group_name || !user_name) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad args");
        return -1;
    }

    ret = ccnet_group_manager_create_org_group (group_mgr, org_id,
                                                group_name, user_name, parent_group_id, error);

    return ret;
}

int
ccnet_rpc_remove_group (int group_id, GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    int ret;

    if (group_id <= 0) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL,
                     "Invalid group_id parameter");
        return -1;
    }

    ret = ccnet_group_manager_remove_group (group_mgr, group_id, FALSE, error);

    return ret;

}

int
ccnet_rpc_group_add_member (int group_id, const char *user_name,
                            const char *member_name, GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    int ret;

    if (group_id <= 0 || !user_name || !member_name) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL,
                     "Group id and user name and member name can not be NULL");
        return -1;
    }

    ret = ccnet_group_manager_add_member (group_mgr, group_id, user_name, member_name,
                                          error);

    return ret;
}

int
ccnet_rpc_group_remove_member (int group_id, const char *user_name,
                               const char *member_name, GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    int ret;

    if (!user_name || !member_name) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL,
                     "User name and member name can not be NULL");
        return -1;
    }

    ret = ccnet_group_manager_remove_member (group_mgr, group_id, user_name,
                                             member_name, error);

    return ret;
}

int
ccnet_rpc_group_set_admin (int group_id, const char *member_name,
                           GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    int ret;

    if (group_id <= 0 || !member_name) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL,
                     "Bad arguments");
        return -1;
    }

    ret = ccnet_group_manager_set_admin (group_mgr, group_id, member_name,
                                         error);
    return ret;
}

int
ccnet_rpc_group_unset_admin (int group_id, const char *member_name,
                           GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    int ret;

    if (group_id <= 0 || !member_name) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL,
                     "Bad arguments");
        return -1;
    }

    ret = ccnet_group_manager_unset_admin (group_mgr, group_id, member_name,
                                           error);
    return ret;
}

int
ccnet_rpc_set_group_name (int group_id, const char *group_name,
                          GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    int ret;

    if (group_id <= 0 || !group_name) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL,
                     "Bad arguments");
        return -1;
    }

    ret = ccnet_group_manager_set_group_name (group_mgr, group_id, group_name,
                                              error);
    return ret;
}

int
ccnet_rpc_quit_group (int group_id, const char *user_name, GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    int ret;

    if (group_id <= 0 || !user_name) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL,
                     "Group id and user name can not be NULL");
        return -1;
    }

    ret = ccnet_group_manager_quit_group (group_mgr, group_id, user_name, error);

    return ret;
}

GList *
ccnet_rpc_get_groups (const char *username, int return_ancestors, GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    GList *ret = NULL;

    if (!username) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL,
                     "User name can not be NULL");
        return NULL;
    }

    ret = ccnet_group_manager_get_groups_by_user (group_mgr, username,
                                                  return_ancestors ? TRUE : FALSE, error);
    return ret;
}

GList *
ccnet_rpc_list_all_departments (GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    GList *ret = NULL;

    ret = ccnet_group_manager_list_all_departments (group_mgr, error);

    return ret;
}

GList*
seafile_get_repos_by_id_prefix  (const char *id_prefix, int start,
                                 int limit, GError **error)
{
    GList *ret = NULL;
    GList *repos, *ptr;

    if (!id_prefix) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    repos = seaf_repo_manager_get_repos_by_id_prefix (seaf->repo_mgr, id_prefix,
                                                      start, limit);

    ret = convert_repo_list (repos);

    for(ptr = repos; ptr; ptr = ptr->next) {
        seaf_repo_unref ((SeafRepo *)ptr->data);
    }
    g_list_free (repos);

    return ret;
}

GList *
ccnet_rpc_get_all_groups (int start, int limit,
                          const char *source, GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    GList *ret = NULL;

    ret = ccnet_group_manager_get_all_groups (group_mgr, start, limit, error);

    return ret;
}

GList *
ccnet_rpc_get_ancestor_groups (int group_id, GError ** error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    GList *ret = NULL;

    ret = ccnet_group_manager_get_ancestor_groups (group_mgr, group_id);

    return ret;
}

GObject *
ccnet_rpc_get_group (int group_id, GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    CcnetGroup *group = NULL;

    group = ccnet_group_manager_get_group (group_mgr, group_id, error);
    if (!group) {
        return NULL;
    }

    /* g_object_ref (group); */
    return (GObject *)group;
}


GList *
ccnet_rpc_get_group_members (int group_id, int start, int limit, GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    GList *ret = NULL;

    if (start < 0 ) {
        start = 0;
    }

    ret = ccnet_group_manager_get_group_members (group_mgr, group_id, start, limit, error);
    if (ret == NULL)
        return NULL;

    return g_list_reverse (ret);
}

GList *
ccnet_rpc_get_members_with_prefix(int group_id, const char *prefix, GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    GList *ret = NULL;

    ret = ccnet_group_manager_get_members_with_prefix (group_mgr, group_id, prefix, error);

    return ret;
}

int
ccnet_rpc_check_group_staff (int group_id, const char *user_name, int in_structure,
                             GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;

    if (group_id <= 0 || !user_name) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL,
                     "Bad arguments");
        return -1;
    }

    return ccnet_group_manager_check_group_staff (group_mgr,
                                                  group_id, user_name,
                                                  in_structure ? TRUE : FALSE);
}

int
ccnet_rpc_remove_group_user (const char *user, GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    if (!user) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return -1;
    }

    return ccnet_group_manager_remove_group_user (group_mgr, user);
}

int
ccnet_rpc_is_group_user (int group_id, const char *user, int in_structure, GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    if (!user || group_id < 0) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return 0;
    }

    return ccnet_group_manager_is_group_user (group_mgr, group_id, user, in_structure ? TRUE : FALSE);
}

int
ccnet_rpc_set_group_creator (int group_id, const char *user_name,
                             GError **error)
{
    CcnetGroupManager *group_mgr = seaf->group_mgr;
    if (!user_name || group_id < 0) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return -1;
    }

    return ccnet_group_manager_set_group_creator (group_mgr, group_id,
                                                  user_name);
}

GList *
ccnet_rpc_get_groups_members (const char *group_ids, GError **error)
{
    if (!group_ids || g_strcmp0(group_ids, "") == 0) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return NULL;
    }
    CcnetGroupManager *group_mgr = seaf->group_mgr;

    return ccnet_group_manager_get_groups_members (group_mgr, group_ids, error);
}

int
ccnet_rpc_create_org (const char *org_name, const char *url_prefix,
                      const char *creator, GError **error)
{
    CcnetOrgManager *org_mgr = seaf->org_mgr;

    if (!org_name || !url_prefix || !creator) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return -1;
    }

    return ccnet_org_manager_create_org (org_mgr, org_name, url_prefix, creator,
                                         error);
}

int
ccnet_rpc_remove_org (int org_id, GError **error)
{
    GList *group_ids = NULL, *email_list=NULL, *ptr;
    const char *url_prefix = NULL;
    CcnetOrgManager *org_mgr = seaf->org_mgr;
    CcnetUserManager *user_mgr = seaf->user_mgr;
    CcnetGroupManager *group_mgr = seaf->group_mgr;

    if (org_id < 0) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return -1;
    }

    url_prefix = ccnet_org_manager_get_url_prefix_by_org_id (org_mgr, org_id,
                                                             error);
    email_list = ccnet_org_manager_get_org_emailusers (org_mgr, url_prefix,
                                                       0, INT_MAX);
    ptr = email_list;
    while (ptr) {
        ccnet_user_manager_remove_emailuser (user_mgr, "DB", (gchar *)ptr->data);
        ptr = ptr->next;
    }
    string_list_free (email_list);

    group_ids = ccnet_org_manager_get_org_group_ids (org_mgr, org_id, 0, INT_MAX);
    ptr = group_ids;
    while (ptr) {
        ccnet_group_manager_remove_group (group_mgr, (int)(long)ptr->data, TRUE, error);
        ptr = ptr->next;
    }
    g_list_free (group_ids);

    return ccnet_org_manager_remove_org (org_mgr, org_id, error);
}

GList *
ccnet_rpc_get_all_orgs (int start, int limit, GError **error)
{
    CcnetOrgManager *org_mgr = seaf->org_mgr;
    GList *ret = NULL;

    ret = ccnet_org_manager_get_all_orgs (org_mgr, start, limit);

    return ret;
}

gint64
ccnet_rpc_count_orgs (GError **error)
{
    CcnetOrgManager *org_mgr = seaf->org_mgr;

    return ccnet_org_manager_count_orgs(org_mgr);
}


GObject *
ccnet_rpc_get_org_by_url_prefix (const char *url_prefix, GError **error)
{
    CcnetOrganization *org = NULL;
    CcnetOrgManager *org_mgr = seaf->org_mgr;

    if (!url_prefix) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return NULL;
    }

    org = ccnet_org_manager_get_org_by_url_prefix (org_mgr, url_prefix, error);
    if (!org)
        return NULL;

    return (GObject *)org;
}

GObject *
ccnet_rpc_get_org_by_id (int org_id, GError **error)
{
    CcnetOrganization *org = NULL;
    CcnetOrgManager *org_mgr = seaf->org_mgr;

    if (org_id <= 0) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return NULL;
    }

    org = ccnet_org_manager_get_org_by_id (org_mgr, org_id, error);
    if (!org)
        return NULL;

    return (GObject *)org;
}

int
ccnet_rpc_add_org_user (int org_id, const char *email, int is_staff,
                        GError **error)
{
    CcnetOrgManager *org_mgr = seaf->org_mgr;

    if (org_id < 0 || !email) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return -1;
    }

    return ccnet_org_manager_add_org_user (org_mgr, org_id, email, is_staff,
                                           error);
}

int
ccnet_rpc_remove_org_user (int org_id, const char *email, GError **error)
{
    CcnetOrgManager *org_mgr = seaf->org_mgr;

    if (org_id < 0 || !email) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return -1;
    }

    return ccnet_org_manager_remove_org_user (org_mgr, org_id, email, error);
}

GList *
ccnet_rpc_get_orgs_by_user (const char *email, GError **error)
{
    CcnetOrgManager *org_mgr = seaf->org_mgr;
    GList *org_list = NULL;

    org_list = ccnet_org_manager_get_orgs_by_user (org_mgr, email, error);

    return org_list;
}

GList *
ccnet_rpc_get_org_emailusers (const char *url_prefix, int start , int limit,
                              GError **error)
{
    CcnetUserManager *user_mgr = seaf->user_mgr;
    CcnetOrgManager *org_mgr = seaf->org_mgr;
    GList *email_list = NULL, *ptr;
    GList *ret = NULL;

    if (!url_prefix) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return NULL;
    }

    email_list = ccnet_org_manager_get_org_emailusers (org_mgr, url_prefix,
                                                       start, limit);
    if (email_list == NULL) {
        return NULL;
    }

    ptr = email_list;
    while (ptr) {
        char *email = ptr->data;
        CcnetEmailUser *emailuser = ccnet_user_manager_get_emailuser (user_mgr,
                                                                      email, NULL);
        if (emailuser != NULL) {
            ret = g_list_prepend (ret, emailuser);
        }

        ptr = ptr->next;
    }

    string_list_free (email_list);

    return g_list_reverse (ret);
}

int
ccnet_rpc_add_org_group (int org_id, int group_id, GError **error)
{
    CcnetOrgManager *org_mgr = seaf->org_mgr;

    if (org_id < 0 || group_id < 0) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return -1;
    }

    return ccnet_org_manager_add_org_group (org_mgr, org_id, group_id, error);
}

int
ccnet_rpc_remove_org_group (int org_id, int group_id, GError **error)
{
    CcnetOrgManager *org_mgr = seaf->org_mgr;

    if (org_id < 0 || group_id < 0) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return -1;
    }

    return ccnet_org_manager_remove_org_group (org_mgr, org_id, group_id,
                                               error);
}

int
ccnet_rpc_is_org_group (int group_id, GError **error)
{
    CcnetOrgManager *org_mgr = seaf->org_mgr;

    if (group_id <= 0) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return -1;
    }

    return ccnet_org_manager_is_org_group (org_mgr, group_id, error);
}

int
ccnet_rpc_get_org_id_by_group (int group_id, GError **error)
{
    CcnetOrgManager *org_mgr = seaf->org_mgr;

    if (group_id <= 0) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return -1;
    }

    return ccnet_org_manager_get_org_id_by_group (org_mgr, group_id, error);
}

GList *
ccnet_rpc_get_org_groups (int org_id, int start, int limit, GError **error)
{
    CcnetOrgManager *org_mgr = seaf->org_mgr;
    GList *ret = NULL;

    if (org_id < 0) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return NULL;
    }

    /* correct parameter */
    if (start < 0 ) {
        start = 0;
    }

    ret = ccnet_org_manager_get_org_groups (org_mgr, org_id, start, limit);

    return ret;
}

GList *
ccnet_rpc_get_org_groups_by_user (const char *user, int org_id, GError **error)
{
    CcnetOrgManager *org_mgr = seaf->org_mgr;
    GList *ret = NULL;

    if (org_id < 0 || !user) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return NULL;
    }
    ret = ccnet_org_manager_get_org_groups_by_user (org_mgr, user, org_id);

    return ret;
}

GList *
ccnet_rpc_get_org_top_groups (int org_id, GError **error)
{
    CcnetOrgManager *org_mgr = seaf->org_mgr;
    GList *ret = NULL;

    if (org_id < 0) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return NULL;
    }
    ret = ccnet_org_manager_get_org_top_groups (org_mgr, org_id, error);

    return ret;
}

int
ccnet_rpc_org_user_exists (int org_id, const char *email, GError **error)
{
    CcnetOrgManager *org_mgr = seaf->org_mgr;

    if (org_id < 0 || !email) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return -1;
    }

    return ccnet_org_manager_org_user_exists (org_mgr, org_id, email, error);
}

int
ccnet_rpc_is_org_staff (int org_id, const char *email, GError **error)
{
    CcnetOrgManager *org_mgr = seaf->org_mgr;

    if (org_id < 0 || !email) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return -1;
    }

    return ccnet_org_manager_is_org_staff (org_mgr, org_id, email, error);
}

int
ccnet_rpc_set_org_staff (int org_id, const char *email, GError **error)
{
    CcnetOrgManager *org_mgr = seaf->org_mgr;

    if (org_id < 0 || !email) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return -1;
    }

    return ccnet_org_manager_set_org_staff (org_mgr, org_id, email, error);
}

int
ccnet_rpc_unset_org_staff (int org_id, const char *email, GError **error)
{
    CcnetOrgManager *org_mgr = seaf->org_mgr;

    if (org_id < 0 || !email) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return -1;
    }

    return ccnet_org_manager_unset_org_staff (org_mgr, org_id, email, error);
}

int
ccnet_rpc_set_org_name (int org_id, const char *org_name, GError **error)
{
    CcnetOrgManager *org_mgr = seaf->org_mgr;

    if (org_id < 0 || !org_name) {
        g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Bad arguments");
        return -1;
    }

    return ccnet_org_manager_set_org_name (org_mgr, org_id, org_name, error);
}

int
ccnet_rpc_set_reference_id (const char *primary_id, const char *reference_id, GError **error)
{
    CcnetUserManager *user_mgr = seaf->user_mgr;

    return ccnet_user_manager_set_reference_id (user_mgr, primary_id, reference_id, error);
}

char *
ccnet_rpc_get_primary_id (const char *email, GError **error)
{
    CcnetUserManager *user_mgr = seaf->user_mgr;

    return ccnet_user_manager_get_primary_id (user_mgr, email);
}

#endif  /* SEAFILE_SERVER */
