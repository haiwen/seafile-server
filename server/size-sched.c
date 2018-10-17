#include "common.h"

#include <ccnet/timer.h>
#include <pthread.h>

#include "seafile-session.h"
#include "size-sched.h"

#define DEBUG_FLAG SEAFILE_DEBUG_OTHER
#include "log.h"

typedef struct SizeSchedulerPriv {
    pthread_t thread_id;
    GThreadPool *compute_repo_size_thread_pool;
} SizeSchedulerPriv;

typedef struct RepoSizeJob {
    SizeScheduler *sched;
    char repo_id[37];
} RepoSizeJob;

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

static char *
get_cached_head_id (SeafDB *db, const char *repo_id)
{
    char *sql;

    sql = "SELECT head_id FROM RepoSize WHERE repo_id=?";
    return seaf_db_statement_get_string (db, sql, 1, "string", repo_id);
}


static void*
compute_repo_size (void *vjob)
{
    RepoSizeJob *job = vjob;
    SizeScheduler *sched = job->sched;
    SeafRepo *repo = NULL;
    SeafCommit *head = NULL;
    char *cached_head_id = NULL;
    GObject *file_count_info = NULL;
    gint64 size = 0;
    gint64 file_count = 0;
    GError **error = NULL;
    int ret;

    repo = seaf_repo_manager_get_repo (sched->seaf->repo_mgr, job->repo_id);
    if (!repo) {
        seaf_warning ("[scheduler] failed to get repo %s.\n", job->repo_id);
        return vjob;
    }

    cached_head_id = get_cached_head_id (sched->seaf->db, job->repo_id);
    if (g_strcmp0 (cached_head_id, repo->head->commit_id) == 0)
        goto out;

    head = seaf_commit_manager_get_commit (sched->seaf->commit_mgr,
                                           repo->id, repo->version,
                                           repo->head->commit_id);
    if (!head) {
        seaf_warning ("[scheduler] failed to get head commit %s.\n",
                   repo->head->commit_id);
        goto out;
    }

    file_count_info = seaf_fs_manager_get_file_count_info_by_path (seaf->fs_mgr,
                                                                   repo->store_id,
                                                                   repo->version,
                                                                   repo->root_id,
                                                                   "/", error);

    if (!file_count_info) {
        seaf_warning ("[scheduler] failed to get file count info.\n");
        g_clear_error (error);
        goto out;
    }

    g_object_get (file_count_info, "file_count", &file_count, "size", &size, NULL);

    ret = set_repo_size_and_file_count (sched->seaf->db,
                                        job->repo_id,
                                        repo->head->commit_id,
                                        size,
                                        file_count);

    g_object_unref (file_count_info);

    if (ret < 0) {
        seaf_warning ("[scheduler] failed to store repo size and file count %s.\n", job->repo_id);
        goto out;
    }

out:
    seaf_repo_unref (repo);
    seaf_commit_unref (head);
    g_free (cached_head_id);

    return vjob;
}

