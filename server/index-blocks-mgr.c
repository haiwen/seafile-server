/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <glib/gstdio.h>

#include <jansson.h>
#include <openssl/sha.h>

#include <timer.h>

#include "utils.h"
#include "log.h"

#include "seafile-session.h"
#include "repo-mgr.h"
#include "fs-mgr.h"
#include "seafile-error.h"
#include "seafile-crypt.h"
#include "index-blocks-mgr.h"

#define TOKEN_LEN 36
#define PROGRESS_TTL 5 * 3600 // 5 hours
#define SCAN_PROGRESS_INTERVAL 24 * 3600 // 1 day

static void
start_index_task (gpointer data, gpointer user_data);

static char *
gen_new_token (GHashTable *token_hash);

static int
scan_progress (void *data);

struct SeafileCrypt;

typedef struct IndexBlksMgrPriv {
    pthread_mutex_t progress_lock;
    GHashTable *progress_store;
    GThreadPool *idx_tpool;
    // This timer is used to scan progress and remove invalid progress.
    CcnetTimer *scan_progress_timer;
} IndexBlksMgrPriv;

typedef struct IndexPara {
    GList *filenames;
    GList *paths;
    SeafRepo *repo;
    char *user;
    char *canon_path;
    int replace_existed;
    SeafileCrypt *crypt;
    gboolean ret_json;
    IdxProgress *progress;
} IndexPara;

static void
free_progress (IdxProgress *progress)
{
    if (!progress)
        return;

    g_free (progress->ret_json);
    g_free (progress);
}


IndexBlksMgr *
index_blocks_mgr_new (SeafileSession *session)
{
    GError *error = NULL;
    IndexBlksMgr *mgr = g_new0 (IndexBlksMgr, 1);
    IndexBlksMgrPriv *priv = g_new0 (IndexBlksMgrPriv, 1);

    priv->idx_tpool = g_thread_pool_new (start_index_task,
                                         priv,
                                         session->max_index_processing_threads,
                                         FALSE, &error);
    if (!priv->idx_tpool) {
        if (error) {
            seaf_warning ("Failed to create index task thread pool: %s.\n", error->message);
            g_clear_error (&error);
        } else {
            seaf_warning ("Failed to create index task thread pool.\n");
        }
        g_free (priv);
        g_free (mgr);
        return NULL;
    }

    pthread_mutex_init (&priv->progress_lock, NULL);
    priv->progress_store = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
                                                  (GDestroyNotify)free_progress);
    priv->scan_progress_timer = ccnet_timer_new (scan_progress, priv,
                                                 SCAN_PROGRESS_INTERVAL * 1000);
    mgr->priv = priv;

    return mgr;
}

static int
scan_progress (void *data)
{
    time_t now = time(NULL);
    IndexBlksMgrPriv *priv = data;
    GHashTableIter iter;
    gpointer key, value;
    IdxProgress *progress;

    pthread_mutex_lock (&priv->progress_lock);

    g_hash_table_iter_init (&iter, priv->progress_store);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        progress = value;
        if (now >= progress->expire_ts && progress->status != 1) {
            g_hash_table_iter_remove (&iter);
        }
    }

    pthread_mutex_unlock (&priv->progress_lock);

    return TRUE;
}

static void
free_index_para (IndexPara *idx_para)
{
    if (!idx_para)
        return;

    string_list_free (idx_para->filenames);
    string_list_free (idx_para->paths);
    seaf_repo_unref (idx_para->repo);
    g_free (idx_para->user);
    g_free (idx_para->canon_path);
    g_free (idx_para->crypt);
    g_free (idx_para);
}

static void
start_index_task (gpointer data, gpointer user_data)
{
    IndexPara *idx_para = data;
    SeafRepo *repo = idx_para->repo;
    GList *ptr = NULL, *id_list = NULL, *size_list = NULL;
    char *path = NULL;
    char *ret_json = NULL;
    char *gc_id = NULL;
    char hex[41];
    unsigned char sha1[20];
    int ret = 0;
    IdxProgress *progress = idx_para->progress;
    SeafileCrypt *crypt = idx_para->crypt;

    gc_id = seaf_repo_get_current_gc_id(repo);
    gint64 *size;
    for (ptr = idx_para->paths; ptr; ptr = ptr->next) {
        path = ptr->data;

        size = g_new (gint64, 1);
        if (seaf_fs_manager_index_blocks (seaf->fs_mgr,
                    repo->store_id, repo->version,
                    path, sha1, size, crypt, TRUE, FALSE, &(progress->indexed)) < 0) {
            seaf_warning ("failed to index blocks");
            progress->status = -1;
            goto out;
        }

        rawdata_to_hex(sha1, hex, 20);
        id_list = g_list_prepend (id_list, g_strdup(hex));
        size_list = g_list_prepend (size_list, size);
    }
    id_list = g_list_reverse (id_list);
    size_list = g_list_reverse (size_list);
    ret = post_files_and_gen_commit (idx_para->filenames,
                                     idx_para->repo->id,
                                     idx_para->user,
                                     idx_para->ret_json ? &ret_json : NULL,
                                     idx_para->replace_existed,
                                     idx_para->canon_path,
                                     id_list,
                                     size_list,
                                     0,
                                     gc_id,
                                     NULL);
    progress->status = ret;
    if (idx_para->ret_json) {
        progress->ret_json = g_strdup(ret_json);
        g_free (ret_json);
    }

out:
    /* remove temp files */
    for (ptr = idx_para->paths; ptr; ptr = ptr->next)
        g_unlink (ptr->data);

    g_list_free_full (id_list, g_free);
    g_list_free_full (size_list, g_free);
    free_index_para (idx_para);
    g_free (gc_id);
    return;
}

char *
index_blocks_mgr_query_progress (IndexBlksMgr *mgr,
                                 const char *token,
                                 GError **error)
{
    char *ret_info;
    json_t *obj;
    IdxProgress *progress;
    IndexBlksMgrPriv *priv = mgr->priv;

    pthread_mutex_lock (&priv->progress_lock);
    progress = g_hash_table_lookup (priv->progress_store, token);
    pthread_mutex_unlock (&priv->progress_lock);

    if (!progress) {
        seaf_warning ("Index progress not found for token %s\n", token);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Index progress not found");
        return NULL;
    }

    obj = json_object ();
    json_object_set_int_member (obj, "indexed", progress->indexed);
    json_object_set_int_member (obj, "total", progress->total);
    json_object_set_int_member (obj, "status", progress->status);
    json_object_set_string_member (obj, "ret_json", progress->ret_json);
    ret_info = json_dumps (obj, JSON_COMPACT);
    json_decref (obj);

    /* index finished */
    if (progress->status != 1) {
        pthread_mutex_lock (&priv->progress_lock);
        g_hash_table_remove (priv->progress_store, token);
        pthread_mutex_unlock (&priv->progress_lock);
    }

    return ret_info;
}

int
index_blocks_mgr_start_index (IndexBlksMgr *mgr,
                              GList *filenames,
                              GList *paths,
                              const char *repo_id,
                              const char *user,
                              int replace_existed,
                              gboolean ret_json,
                              const char *canon_path,
                              SeafileCrypt *crypt,
                              char **task_id)
{
    GList *ptr = NULL;
    char *path = NULL, *token = NULL;
    SeafileCrypt *_crypt = NULL;

    SeafRepo *repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Failed to get repo %.8s.\n", repo_id);
        return -1;
    }
    IndexBlksMgrPriv *priv = mgr->priv;

    token = gen_new_token(priv->progress_store);
    if (!token) {
        seaf_warning ("Failed to genarate index token for repo %.8s.\n", repo_id);
        seaf_repo_unref (repo);
        return -1;
    }
    if (crypt) {
        _crypt = g_new0(SeafileCrypt, 1);
        memcpy (_crypt, crypt, sizeof (SeafileCrypt));
    }

    *task_id = g_strdup (token);
    IdxProgress *progress = g_new0(IdxProgress, 1);
    progress->status = 1;

    IndexPara *idx_para = g_new0 (IndexPara, 1);
    idx_para->filenames = g_list_copy_deep (filenames, (GCopyFunc)g_strdup, NULL);
    idx_para->paths = g_list_copy_deep (paths, (GCopyFunc)g_strdup, NULL);
    idx_para->repo = repo;
    idx_para->user = g_strdup (user);
    idx_para->canon_path = g_strdup(canon_path);
    idx_para->replace_existed = replace_existed;
    idx_para->ret_json = ret_json;
    idx_para->crypt = _crypt;
    idx_para->progress = progress;

    progress->status = 1;
    progress->expire_ts = time(NULL) + PROGRESS_TTL;

    /* Get total size of all files for progress. */
    for (ptr = paths; ptr; ptr = ptr->next) {
        SeafStat sb;
        path = ptr->data;
        if (seaf_stat (path, &sb) < 0) {
            seaf_warning ("Bad file %s: %s.\n", path, strerror(errno));
            goto error;
        }

        if (!S_ISREG(sb.st_mode))
            goto error;

        progress->total += (gint64)sb.st_size;
    }

    pthread_mutex_lock (&priv->progress_lock);
    g_hash_table_replace (priv->progress_store, g_strdup (token), progress);
    pthread_mutex_unlock (&priv->progress_lock);

    g_thread_pool_push (priv->idx_tpool, idx_para, NULL);

    g_free (token);
    return 0;

error:
    g_free (token);
    /* remove temp files */
    for (ptr = idx_para->paths; ptr; ptr = ptr->next)
        g_unlink (ptr->data);

    free_index_para (idx_para);
    g_free (progress);

    return -1;
}

static char *
gen_new_token (GHashTable *token_hash)
{
    char uuid[37];
    char *token;

    while (1) {
        gen_uuid_inplace (uuid);
        token = g_strndup(uuid, TOKEN_LEN);

        /* Make sure the new token doesn't conflict with an existing one. */
        if (g_hash_table_lookup (token_hash, token) != NULL)
            g_free (token);
        else
            return token;
    }
}
