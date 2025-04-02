#include "common.h"

#include <pthread.h>

#include "seafile-session.h"
#include "size-sched.h"
#include "diff-simple.h"
#define DEBUG_FLAG SEAFILE_DEBUG_OTHER
#include "log.h"
#include "obj-cache.h"

#define REPO_SIZE_LIST "repo_size_task"

typedef struct SizeSchedulerPriv {
    pthread_t thread_id;
    GThreadPool *compute_repo_size_thread_pool;
    struct ObjCache *cache;
} SizeSchedulerPriv;

typedef struct RepoSizeJob {
    SizeScheduler *sched;
    char repo_id[37];
} RepoSizeJob;

typedef struct RepoInfo {
    gchar *head_id;
    gint64 size;
    gint64 file_count;
} RepoInfo;

static void*
compute_repo_size (void *vjob);
static void
compute_task (void *data, void *user_data);
static void*
log_unprocessed_task_thread (void *arg);

#define DEFAULT_SCHEDULE_THREAD_NUMBER 1;

SizeScheduler *
size_scheduler_new (SeafileSession *session)
{
    GError *error = NULL;
    SizeScheduler *sched = g_new0 (SizeScheduler, 1);
    int sched_thread_num;

    if (!sched)
        return NULL;

    sched->priv = g_new0 (SizeSchedulerPriv, 1);
    if (!sched->priv) {
        g_free (sched);
        return NULL;
    }

    sched->priv->cache = session->obj_cache;

    sched->seaf = session;

    sched_thread_num = g_key_file_get_integer (session->config, "scheduler", "size_sched_thread_num", NULL);

    if (sched_thread_num == 0)
        sched_thread_num = DEFAULT_SCHEDULE_THREAD_NUMBER;

    sched->priv->compute_repo_size_thread_pool = g_thread_pool_new (compute_task, NULL,
                                                                    sched_thread_num, FALSE, &error);
    if (!sched->priv->compute_repo_size_thread_pool) {
        if (error) {
            seaf_warning ("Failed to create compute repo size thread pool: %s.\n", error->message);
        } else {
            seaf_warning ("Failed to create repo size thread pool.\n");
        }

        g_clear_error (&error);
        g_free (sched->priv);
        g_free (sched);
        return NULL;
    }

    return sched;
}

int
size_scheduler_start (SizeScheduler *scheduler)
{
    int ret = pthread_create (&scheduler->priv->thread_id, NULL, log_unprocessed_task_thread, scheduler);
    if (ret < 0) {
        seaf_warning ("Failed to create log unprocessed task thread.\n");
        return -1;
    }
    pthread_detach (scheduler->priv->thread_id);

    return 0;
}

void
schedule_repo_size_computation (SizeScheduler *scheduler, const char *repo_id)
{
    RepoSizeJob *job = g_new0(RepoSizeJob, 1);

    job->sched = scheduler;
    memcpy (job->repo_id, repo_id, 37);

    g_thread_pool_push (scheduler->priv->compute_repo_size_thread_pool, job, NULL);
}

#define PRINT_UNPROCESSED_TASKS_INTERVAL 30

void *log_unprocessed_task_thread (void *arg)
{
    SizeScheduler *sched = arg;
    guint unprocessed_num;

    while (1) {
        unprocessed_num = g_thread_pool_unprocessed (sched->priv->compute_repo_size_thread_pool);

        if (unprocessed_num > 10)
            seaf_message ("The number of repo size update tasks in queue is %u\n",
                          unprocessed_num);

        sleep (PRINT_UNPROCESSED_TASKS_INTERVAL);
    }

    return NULL;
}

static void
compute_task (void *data, void *user_data)
{
    RepoSizeJob *job = data;

    compute_repo_size (job);

    g_free (job);
}

static gboolean get_head_id (SeafDBRow *row, void *data)
{
    char *head_id_out = data;
    const char *head_id;

    head_id = seaf_db_row_get_column_text (row, 0);
    memcpy (head_id_out, head_id, 40);

    return FALSE;
}

static int
set_repo_size_and_file_count (SeafDB *db,
                              const char *repo_id,
                              const char *new_head_id,
                              gint64 size,
                              gint64 file_count)
{
    SeafDBTrans *trans;
    char *sql;
    char cached_head_id[41] = {0};
    int ret = 0;

    trans = seaf_db_begin_transaction (db);
    if (!trans)
        return -1;

    sql = "SELECT head_id FROM RepoSize WHERE repo_id=?";

    int n = seaf_db_trans_foreach_selected_row (trans, sql,
                                                get_head_id,
                                                cached_head_id,
                                                1, "string", repo_id);
    if (n < 0) {
        ret = -1;
        goto rollback;
    }

    if (n == 0) {
        /* Size not set before. */
        sql = "INSERT INTO RepoSize (repo_id, size, head_id) VALUES (?, ?, ?)";
        if (seaf_db_trans_query (trans, sql, 3, "string", repo_id, "int64", size,
                                 "string", new_head_id) < 0) {
            ret = -1;
            goto rollback;
        }
    } else {
        sql = "UPDATE RepoSize SET size = ?, head_id = ? WHERE repo_id = ?";
        if (seaf_db_trans_query (trans, sql, 3, "int64", size, "string", new_head_id,
                                 "string", repo_id) < 0) {
            ret = -1;
            goto rollback;
        }
    }

    gboolean exist;
    gboolean db_err;

    exist = seaf_db_trans_check_for_existence (trans,
                                               "SELECT 1 FROM RepoFileCount WHERE repo_id=?",
                                               &db_err, 1, "string", repo_id);
    if (db_err) {
        ret = -1;
        goto rollback;
    }

    if (exist) {
        if (seaf_db_trans_query (trans,
                                 "UPDATE RepoFileCount SET file_count=? WHERE repo_id=?",
                                 2, "int64", file_count, "string", repo_id) < 0) {
            ret = -1;
            goto rollback;
        }
    } else {
        if (seaf_db_trans_query (trans,
                                 "INSERT INTO RepoFileCount (repo_id,file_count) VALUES (?,?)",
                                 2, "string", repo_id, "int64", file_count) < 0) {
            ret = -1;
            goto rollback;
        }
    }

    if (seaf_db_commit (trans) < 0) {
        ret = -1;
        goto rollback;
    }

    seaf_db_trans_close (trans);

    return ret;

rollback:
    seaf_db_rollback (trans);
    seaf_db_trans_close (trans);
    return ret;
}

static gboolean
create_old_repo_info (SeafDBRow *row, void *data)
{
    RepoInfo **info = data;

    const char *head_id = seaf_db_row_get_column_text (row, 0);
    gint64 size = seaf_db_row_get_column_int64 (row, 1);
    gint64 file_count = seaf_db_row_get_column_int64 (row, 2);

    if (!head_id)
        return FALSE;
    
    *info = g_new0(RepoInfo, 1);
    if (!*info)
        return FALSE;
    (*info)->head_id = g_strdup(head_id);
    (*info)->size = size;
    (*info)->file_count = file_count;

    return TRUE;
}

static RepoInfo*
get_old_repo_info_from_db (SeafDB *db, const char *repo_id, gboolean *is_db_err)
{
    RepoInfo *info = NULL;
    char *sql;

    switch (seaf_db_type (db)) {
    case SEAF_DB_TYPE_MYSQL:
    case SEAF_DB_TYPE_PGSQL:
        sql = "select s.head_id,s.size,f.file_count FROM "
            "RepoSize s LEFT JOIN RepoFileCount f ON "
            "s.repo_id=f.repo_id WHERE "
            "s.repo_id=? FOR UPDATE";
        break;
    case SEAF_DB_TYPE_SQLITE:
        sql = "select s.head_id,s.size,f.file_count FROM "
            "RepoSize s LEFT JOIN RepoFileCount f ON "
            "s.repo_id=f.repo_id WHERE "
            "s.repo_id=?";
        break;
    default:
        seaf_warning("Unexpected database type.\n");
        *is_db_err = TRUE;
        return NULL;
    }
    int ret = seaf_db_statement_foreach_row (db, sql,
                                             create_old_repo_info, &info,
                                             1, "string", repo_id);
    if (ret < 0)
        *is_db_err = TRUE;

    return info;

}

static void
notify_repo_size_change (SizeScheduler *sched, const char *repo_id)
{
    ObjCache *cache =  sched->priv->cache;
    if (!cache) {
        return;
    }

    json_t *obj = NULL;
    char *msg = NULL;

    obj = json_object ();

    json_object_set_new (obj, "repo_id", json_string(repo_id));

    msg = json_dumps (obj, JSON_COMPACT);

    objcache_push (cache, REPO_SIZE_LIST, msg);

out:
    g_free (msg);
    json_decref (obj);
}

static void*
compute_repo_size (void *vjob)
{
    RepoSizeJob *job = vjob;
    SizeScheduler *sched = job->sched;
    SeafRepo *repo = NULL;
    SeafCommit *head = NULL;
    SeafCommit *old_head = NULL;
    GObject *file_count_info = NULL;
    gint64 size = 0;
    gint64 file_count = 0;
    int ret;
    RepoInfo *info = NULL;
    GError *error = NULL;
    gboolean is_db_err = FALSE;

    repo = seaf_repo_manager_get_repo (sched->seaf->repo_mgr, job->repo_id);
    if (!repo) {
        seaf_warning ("[scheduler] failed to get repo %s.\n", job->repo_id);
        return vjob;
    }

    info = get_old_repo_info_from_db(sched->seaf->db, job->repo_id, &is_db_err);
    if (is_db_err)
        goto out;
    if (info && g_strcmp0 (info->head_id, repo->head->commit_id) == 0)
        goto out;

    head = seaf_commit_manager_get_commit (sched->seaf->commit_mgr,
                                           repo->id, repo->version,
                                           repo->head->commit_id);
    if (!head) {
        seaf_warning ("[scheduler] failed to get head commit %s.\n",
                   repo->head->commit_id);
        goto out;
    }

    if (info)
        old_head = seaf_commit_manager_get_commit (sched->seaf->commit_mgr,
                                                   repo->id, repo->version,
                                                   info->head_id);

    if (info && (info->file_count != 0) && old_head){
        gint64 change_size = 0;
        gint64 change_file_count = 0;
        GList *diff_entries = NULL;
        
        ret = diff_commits (old_head, head, &diff_entries, FALSE);
        if (ret < 0) {
            seaf_warning("[scheduler] failed to do diff.\n");
            goto out;
        }
        GList *des = NULL;
        for (des = diff_entries; des ; des = des->next){
            DiffEntry *diff_entry = des->data;
            if (diff_entry->status == DIFF_STATUS_DELETED){            
                change_size -= diff_entry->size;
                --change_file_count;
            }
            else if (diff_entry->status == DIFF_STATUS_ADDED){
                change_size += diff_entry->size;
                ++change_file_count;
            }
            else if (diff_entry->status == DIFF_STATUS_MODIFIED)
                change_size = change_size + diff_entry->size - diff_entry->origin_size;
        }
        size = info->size + change_size;
        file_count = info->file_count + change_file_count;

        g_list_free_full (diff_entries, (GDestroyNotify)diff_entry_free);
    } else {
        file_count_info = seaf_fs_manager_get_file_count_info_by_path (seaf->fs_mgr,
                                                                       repo->store_id,
                                                                       repo->version,
                                                                       repo->root_id,
                                                                       "/", &error);
        if (!file_count_info) {
            seaf_warning ("[scheduler] failed to get file count info.\n");
            g_clear_error (&error);
            goto out;
        }
        g_object_get (file_count_info, "file_count", &file_count, "size", &size, NULL);
        g_object_unref (file_count_info);
    }

    ret = set_repo_size_and_file_count (sched->seaf->db,
                                        job->repo_id,
                                        repo->head->commit_id,
                                        size,
                                        file_count);
    
    if (ret < 0) {
        seaf_warning ("[scheduler] failed to store repo size and file count %s.\n", job->repo_id);
        goto out;
    }

    notify_repo_size_change (sched, repo->store_id);

out:
    seaf_repo_unref (repo);
    seaf_commit_unref (head);
    seaf_commit_unref (old_head);
    if (info)
        g_free (info->head_id);
    g_free (info);

    return vjob;
}

