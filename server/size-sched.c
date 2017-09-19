#include "common.h"

#include <ccnet/timer.h>
#include <pthread.h>

#include "seafile-session.h"
#include "size-sched.h"

#define DEBUG_FLAG SEAFILE_DEBUG_OTHER
#include "log.h"

typedef struct SizeSchedulerPriv {
    pthread_mutex_t q_lock;
    GQueue *repo_size_job_queue;
    int n_running_repo_size_jobs;
    gint64 last_print_queue_size_time;

    CcnetTimer *sched_timer;
} SizeSchedulerPriv;

typedef struct RepoSizeJob {
    SizeScheduler *sched;
    char repo_id[37];
} RepoSizeJob;

#define SCHEDULER_INTV 1000    /* 1s */
#define CONCURRENT_JOBS 1

static int
schedule_pulse (void *vscheduler);
static void*
compute_repo_size (void *vjob);
static void
compute_repo_size_done (void *vjob);

SizeScheduler *
size_scheduler_new (SeafileSession *session)
{
    SizeScheduler *sched = g_new0 (SizeScheduler, 1);

    if (!sched)
        return NULL;

    sched->priv = g_new0 (SizeSchedulerPriv, 1);
    if (!sched->priv) {
        g_free (sched);
        return NULL;
    }

    sched->seaf = session;

    pthread_mutex_init (&sched->priv->q_lock, NULL);

    sched->priv->repo_size_job_queue = g_queue_new ();

    return sched;
}

int
size_scheduler_start (SizeScheduler *scheduler)
{
    scheduler->priv->sched_timer = ccnet_timer_new (schedule_pulse,
                                              scheduler,
                                              SCHEDULER_INTV);

    return 0;
}

void
schedule_repo_size_computation (SizeScheduler *scheduler, const char *repo_id)
{
    RepoSizeJob *job = g_new0(RepoSizeJob, 1);

    job->sched = scheduler;
    memcpy (job->repo_id, repo_id, 37);

    pthread_mutex_lock (&scheduler->priv->q_lock);
    g_queue_push_tail (scheduler->priv->repo_size_job_queue, job);
    pthread_mutex_unlock (&scheduler->priv->q_lock);
}

#define PRINT_QUEUE_SIZE_INTERVAL 300

static int
schedule_pulse (void *vscheduler)
{
    SizeScheduler *sched = vscheduler;
    RepoSizeJob *job;

    while (sched->priv->n_running_repo_size_jobs < CONCURRENT_JOBS) {
        gint64 now = (gint64)time(NULL);
        pthread_mutex_lock (&sched->priv->q_lock);
        job = (RepoSizeJob *)g_queue_pop_head (sched->priv->repo_size_job_queue);
        if (now - sched->priv->last_print_queue_size_time >= PRINT_QUEUE_SIZE_INTERVAL) {
            seaf_message ("Repo size compute queue size is %u\n",
                          sched->priv->repo_size_job_queue->length);
            sched->priv->last_print_queue_size_time = now;
        }
        pthread_mutex_unlock (&sched->priv->q_lock);

        if (!job)
            break;

        int ret = ccnet_job_manager_schedule_job (sched->seaf->job_mgr,
                                                  compute_repo_size,
                                                  compute_repo_size_done,
                                                  job);
        if (ret < 0) {
            seaf_warning ("[scheduler] failed to start compute job.\n");
            g_free (job);
            break;
        }
        ++(sched->priv->n_running_repo_size_jobs);
    }

    return 1;
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
        sql = "INSERT INTO RepoSize VALUES (?, ?, ?)";
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
    gint64 size = 0;
    gint64 file_count = 0;

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

    size = seaf_fs_manager_get_fs_size (sched->seaf->fs_mgr,
                                        repo->store_id, repo->version,
                                        head->root_id);
    if (size < 0) {
        seaf_warning ("[scheduler] Failed to compute size of repo %.8s.\n",
                   repo->id);
        goto out;
    }

    file_count = seaf_fs_manager_count_fs_files (sched->seaf->fs_mgr,
                                                 repo->store_id, repo->version,
                                                 head->root_id);
    if (file_count < 0) {
        seaf_warning ("[scheduler] Failed to compute file count for repo %s.\n",
                      repo->id);
        goto out;
    }

    int ret = set_repo_size_and_file_count (sched->seaf->db,
                                            job->repo_id,
                                            repo->head->commit_id,
                                            size,
                                            file_count);
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

static void
compute_repo_size_done (void *vjob)
{
    RepoSizeJob *job = vjob;
    --(job->sched->priv->n_running_repo_size_jobs);
    g_free (job);
}
