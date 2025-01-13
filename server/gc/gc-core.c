/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "seafile-session.h"
#include "bloom-filter.h"
#include "gc-core.h"
#include "utils.h"

#define DEBUG_FLAG SEAFILE_DEBUG_OTHER
#include "log.h"

#include <time.h>
#define MAX_BF_SIZE (((size_t)1) << 29)   /* 64 MB */

#define KEEP_ALIVE_PER_OBJS 100
#define KEEP_ALIVE_PER_SECOND 1

/*
 * The number of bits in the bloom filter is 4 times the number of all blocks.
 * Let m be the bits in the bf, n be the number of blocks to be added to the bf
 * (the number of live blocks), and k = 3 (closed to optimal for m/n = 4),
 * the probability of false-positive is
 *
 *     p = (1 - e^(-kn/m))^k = 0.15
 *
 * Because m = 4 * total_blocks >= 4 * (live blocks) = 4n, we should have p <= 0.15.
 * Put it another way, we'll clean up at least 85% dead blocks in each gc operation.
 * See http://en.wikipedia.org/wiki/Bloom_filter.
 *
 * Supose we have 8TB space, and the avg block size is 1MB, we'll have 8M blocks, then
 * the size of bf is (8M * 4)/8 = 4MB.
 *
 * If total_blocks is a small number (e.g. < 100), we should try to clean all dead blocks.
 * So we set the minimal size of the bf to 1KB.
 */

/*
 * Online GC algorithm
 *
 * There is a table `GCID` in the seafile database. Every time GC is run for a repo,
 * a new GC ID (UUID) will be generated and inserted into this table.
 * 
 * Other threads that want to update the branch head of a repo must do so as follows:
 * 1. Read the GC ID from the table before wrting blocks;
 * 2. begin a transaction;
 * 3. Read the GC ID again with `SELECT ... FOR UPDATE`;
 * 4. Compare the new GC ID with the previous one. If they are the same, proceed to
 *    update the branch head; otherwise, a GC operation has been run between
 *    steps 1 and 3, the branch update operation must be failed.
 * 5. Commit or rollback the transaction.
 *
 * For syncing clients, the algorithm is a bit more complicated.
 * Because writing blocks and updating the branch head is not executed in the same
 * context (or more precisely, not in the same thread), the GC ID read in step 1
 * has to be stored into a database table `LastGCID (client_token, gc_id)`.
 * After step 4, no matter the branch update succeeds or not, the entry in `LastGCID`
 * table has to be deleted.
 */

static Bloom *
alloc_gc_index (const char *repo_id, guint64 total_blocks)
{
    size_t size;

    size = (size_t) MAX(total_blocks << 2, 1 << 13);
    size = MIN (size, MAX_BF_SIZE);

    seaf_message ("GC index size is %u Byte for repo %.8s.\n",
                  (int)size >> 3, repo_id);

    return bloom_create (size, 3, 0);
}

typedef struct {
    SeafRepo *repo;
    Bloom *blocks_index;
    Bloom *fs_index;
    GHashTable *visited;
    GHashTable *visited_commits;

    /* > 0: keep a period of history;
     * == 0: only keep data in head commit;
     * < 0: keep all history data.
     */
    gint64 truncate_time;
    gboolean traversed_head;

    int traversed_commits;
    gint64 traversed_blocks;

    int verbose;
    gint64 traversed_fs_objs;

    SeafDBTrans *trans;
    gint64 keep_alive_last_time;
    gint64 keep_alive_obj_counter;

    gboolean traverse_base_commit;
} GCData;

static int
add_blocks_to_index (SeafFSManager *mgr, GCData *data, const char *file_id)
{
    SeafRepo *repo = data->repo;
    Bloom *blocks_index = data->blocks_index;
    Seafile *seafile;
    int i;

    seafile = seaf_fs_manager_get_seafile (mgr, repo->store_id, repo->version, file_id);
    if (!seafile) {
        seaf_warning ("Failed to find file %s:%s.\n", repo->store_id, file_id);
        return -1;
    }

    for (i = 0; i < seafile->n_blocks; ++i) {
        bloom_add (blocks_index, seafile->blk_sha1s[i]);
        ++data->traversed_blocks;
    }

    seafile_unref (seafile);

    return 0;
}

static void
add_fs_to_index(GCData *data, const char *file_id)
{
    Bloom *fs_index = data->fs_index;
    if (fs_index) {
        bloom_add (fs_index, file_id);
    }
    ++(data->traversed_fs_objs);
}

static gboolean
fs_callback (SeafFSManager *mgr,
             const char *store_id,
             int version,
             const char *obj_id,
             int type,
             void *user_data,
             gboolean *stop)
{
    GCData *data = user_data;

    if (data->visited != NULL) {
        if (g_hash_table_lookup (data->visited, obj_id) != NULL) {
            *stop = TRUE;
            return TRUE;
        }

        char *key = g_strdup(obj_id);
        g_hash_table_replace (data->visited, key, key);
    }

    if (data->trans) {
        ++(data->keep_alive_obj_counter);

        if (data->keep_alive_obj_counter >= KEEP_ALIVE_PER_OBJS &&
            ((gint64)time(NULL) - data->keep_alive_last_time) >= KEEP_ALIVE_PER_SECOND)
        {
            data->keep_alive_last_time = (gint64)time(NULL);
            data->keep_alive_obj_counter = 0;
            seaf_db_trans_query(data->trans, "SELECT 1;", 0);
        }
    }

    add_fs_to_index(data, obj_id);

    // If traversing the base_commit, only the fs objects need to be retained, while the block does not.
    // This is because only the fs objects are needed when merging virtual repo.
    if (data->traverse_base_commit) {
        return TRUE;
    }

    if (type == SEAF_METADATA_TYPE_FILE &&
        add_blocks_to_index (mgr, data, obj_id) < 0)
        return FALSE;

    return TRUE;
}

static gboolean
traverse_commit (SeafCommit *commit, void *vdata, gboolean *stop)
{
    GCData *data = vdata;
    int ret;

    if (g_hash_table_lookup (data->visited_commits, commit->commit_id)) {
        // Has traversed on prev head commit, stop traverse from this branch
        *stop = TRUE;
        return TRUE;
    }

    if (data->truncate_time == 0)
    {
        *stop = TRUE;
        /* Stop after traversing the head commit. */
    }
    else if (data->truncate_time > 0 &&
             (gint64)(commit->ctime) < data->truncate_time &&
             data->traversed_head)
    {
        /* Still traverse the first commit older than truncate_time.
         * If a file in the child commit of this commit is deleted,
         * we need to access this commit in order to restore it
         * from trash.
         */
        *stop = TRUE;
    }

    if (!data->traversed_head)
        data->traversed_head = TRUE;

    if (data->verbose)
        seaf_message ("Traversing commit %.8s for repo %.8s.\n",
                      commit->commit_id, data->repo->id);

    ++data->traversed_commits;

    data->traversed_fs_objs = 0;

    ret = seaf_fs_manager_traverse_tree (seaf->fs_mgr,
                                         data->repo->store_id, data->repo->version,
                                         commit->root_id,
                                         fs_callback,
                                         data, FALSE);
    if (ret < 0)
        return FALSE;

    int dummy;
    g_hash_table_replace (data->visited_commits,
                          g_strdup (commit->commit_id), &dummy);

    if (data->verbose)
        seaf_message ("Traversed %"G_GINT64_FORMAT" fs objects for repo %.8s.\n",
                      data->traversed_fs_objs, data->repo->id);

    return TRUE;
}

static int
update_gc_id (SeafRepo *repo, SeafDBTrans *trans)
{
    char *sql;
    char *gc_id;
    gboolean id_exists, db_err = FALSE;
    int ret;

    sql = "SELECT 1 FROM GCID WHERE repo_id = ?";
    id_exists = seaf_db_trans_check_for_existence (trans, sql, &db_err,
                                                   1, "string", repo->id);

    gc_id = gen_uuid ();
    if (id_exists) {
        sql = "UPDATE GCID SET gc_id = ? WHERE repo_id = ?";
        ret = seaf_db_trans_query (trans, sql, 2,
                                   "string", gc_id, "string", repo->id);
    } else {
        sql = "INSERT INTO GCID (repo_id, gc_id) VALUES (?, ?)";
        ret = seaf_db_trans_query (trans, sql, 2,
                                   "string", repo->id, "string", gc_id);
    }
    g_free (gc_id);

    return ret;
}

static void
update_valid_since_time (SeafRepo *repo, gint64 new_time)
{
    gint64 old_time = seaf_repo_manager_get_repo_valid_since (repo->manager,
                                                              repo->id);

    if (new_time > 0) {
        if (new_time > old_time)
            seaf_repo_manager_set_repo_valid_since (repo->manager,
                                                    repo->id,
                                                    new_time);
    } else if (new_time == 0) {
        /* Only the head commit is valid after GC if no history is kept. */
        SeafCommit *head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                           repo->id, repo->version,
                                                           repo->head->commit_id);
        if (head && (old_time < 0 || head->ctime > (guint64)old_time))
            seaf_repo_manager_set_repo_valid_since (repo->manager,
                                                    repo->id,
                                                    head->ctime);
        seaf_commit_unref (head);
    }
}

static GCData *
gc_data_new (SeafRepo *repo, Bloom *blocks_index, Bloom *fs_index, int verbose)
{
    GCData *data;
    data = g_new0(GCData, 1);
    seaf_repo_ref(repo);
    data->repo = repo;
    data->blocks_index = blocks_index;
    data->fs_index = fs_index;
    data->visited = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
    data->visited_commits = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                   g_free, NULL);
    data->verbose = verbose;

    gint64 truncate_time;
    truncate_time = seaf_repo_manager_get_repo_truncate_time (repo->manager,
                                                              repo->id);
    update_valid_since_time (repo, truncate_time);
    data->truncate_time = truncate_time;

    data->keep_alive_last_time = (gint64)time(NULL);
    data->keep_alive_obj_counter = 0;

    return data;
}

static void
gc_data_free (GCData *data)
{
    if (!data)
        return;

    seaf_repo_unref(data->repo);
    g_hash_table_destroy (data->visited);
    g_hash_table_destroy (data->visited_commits);
    g_free (data);

    return;
}

static gint64
populate_gc_index_for_repo_for_new_commits (GCData *data, SeafDBTrans *trans)
{
    SeafBranch *new_branch = NULL;
    gint64 n_blocks_last = 0;
    int n_commits_last = 0;
    gboolean res;
    gint64 ret = 0;
    SeafRepo *repo = data->repo;

    if (!repo->is_virtual) {
        if (trans != NULL && update_gc_id (repo, trans) < 0) {
            seaf_warning ("Failed to update GCID for repo %s.\n", repo->id);
            ret = -1;
            goto out;
        }
    }

    n_blocks_last = data->traversed_blocks;
    n_commits_last = data->traversed_commits;
    data->traversed_blocks = 0;
    data->traversed_commits = 0;
    data->trans = trans;

    new_branch = seaf_branch_manager_get_branch (seaf->branch_mgr, repo->id, "master");
    if (!new_branch) {
        seaf_warning ("Failed to get master branch of repo %.8s.\n", repo->id);
        ret = -1;
        goto out;
    }

    if (g_strcmp0 (repo->head->commit_id, new_branch->commit_id) != 0) {
        res = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                        repo->id, repo->version,
                                                        new_branch->commit_id,
                                                        traverse_commit,
                                                        data,
                                                        FALSE);
        if (!res) {
            ret = -1;
            seaf_warning ("Failed to populate index for repo %.8s.\n", repo->id);
            goto out;
        }
    }

    seaf_message ("Traversed %d commits, %"G_GINT64_FORMAT" blocks for repo %.8s.\n",
                  data->traversed_commits + n_commits_last,
                  data->traversed_blocks + n_blocks_last,
                  repo->id);

    ret = data->traversed_blocks;

out:
    seaf_branch_unref (new_branch);

    return ret;

}

static gint64
populate_gc_index_for_repo (GCData *data, SeafDBTrans *trans)
{
    gboolean res;
    gint64 ret = 0;
    SeafRepo *repo = data->repo;

    data->trans = trans;

    if (!repo->is_virtual)
        seaf_message ("Populating index for repo %.8s.\n", repo->id);
    else
        seaf_message ("Populating index for sub-repo %.8s.\n", repo->id);

    res = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                    repo->id, repo->version,
                                                    repo->head->commit_id,
                                                    traverse_commit,
                                                    data,
                                                    FALSE);
    if (!res) {
        ret = -1;
        seaf_warning ("Failed to populate index for repo %.8s.\n", repo->id);
        return -1;
    }

    // Traverse the base commit of the virtual repo. Otherwise, if the virtual repo has not been updated for a long time,
    // the fs object corresponding to the base commit will be removed by mistake.
    if (!repo->is_virtual) {
        GList *vrepo_ids = NULL, *ptr;
        char *repo_id = NULL;
        SeafVirtRepo *vinfo = NULL;
        vrepo_ids = seaf_repo_manager_get_virtual_repo_ids_by_origin (seaf->repo_mgr,
                                                                      repo->id);
        for (ptr = vrepo_ids; ptr; ptr = ptr->next) {
            repo_id = ptr->data;
            vinfo = seaf_repo_manager_get_virtual_repo_info (seaf->repo_mgr, repo_id);
            if (!vinfo) {
                continue;
            }
            data->traverse_base_commit = TRUE;
            res = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                            repo->store_id, repo->version,
                                                            vinfo->base_commit,
                                                            traverse_commit,
                                                            data,
                                                            FALSE);
            data->traverse_base_commit = FALSE;
            seaf_virtual_repo_info_free (vinfo);
            if (!res) {
                seaf_warning ("Failed to traverse base commit %s for virtual repo %s.\n", vinfo->base_commit, repo_id);
                string_list_free (vrepo_ids);
                return -1;
            }
        }
        string_list_free (vrepo_ids);
    }

    ret = data->traversed_blocks;

    return ret;
}

#define MAX_THREADS 10

typedef struct CheckBlockParam {
    char *store_id;
    int repo_version;
    Bloom *index;
    int dry_run;
    GAsyncQueue *async_queue;
    pthread_mutex_t counter_lock;
    gint64 removed_blocks;
} CheckBlockParam;

typedef struct CheckFSParam {
    char *store_id;
    int repo_version;
    Bloom *index;
    int dry_run;
    GAsyncQueue *async_queue;
    pthread_mutex_t counter_lock;
    gint64 removed_fs;
} CheckFSParam;

static void
check_block_liveness (gpointer data, gpointer user_data)
{
    char *block_id = data;
    CheckBlockParam *param = user_data;

    if (!bloom_test (param->index, block_id)) {
        pthread_mutex_lock (&param->counter_lock);
        param->removed_blocks ++;
        pthread_mutex_unlock (&param->counter_lock);
        if (!param->dry_run)
            seaf_block_manager_remove_block (seaf->block_mgr,
                                             param->store_id, param->repo_version,
                                             block_id);
    }

    g_async_queue_push (param->async_queue, block_id);
}

static gint64
check_existing_blocks (char *store_id, int repo_version, GHashTable *exist_blocks,
                       Bloom *blocks_index, int dry_run)
{
    char *block_id;
    GThreadPool *tpool = NULL;
    GAsyncQueue *async_queue = NULL;
    CheckBlockParam *param = NULL;
    GHashTableIter iter;
    gpointer key, value;
    gint64 ret = 0;

    async_queue = g_async_queue_new ();
    param = g_new0 (CheckBlockParam, 1);
    param->store_id = store_id;
    param->repo_version = repo_version;
    param->index = blocks_index;
    param->dry_run = dry_run;
    param->async_queue = async_queue;
    pthread_mutex_init (&param->counter_lock, NULL);

    tpool = g_thread_pool_new (check_block_liveness, param, MAX_THREADS, FALSE, NULL);
    if (!tpool) {
        seaf_warning ("Failed to create thread pool for repo %s, stop gc.\n",
                      store_id);
        ret = -1;
        goto out;
    }

    g_hash_table_iter_init (&iter, exist_blocks);

    while (g_hash_table_iter_next (&iter, &key, &value)) {
        g_thread_pool_push (tpool, (char *)key, NULL);
    }

    while ((block_id = g_async_queue_pop (async_queue))) {
        g_hash_table_remove (exist_blocks, block_id);
        if (g_hash_table_size (exist_blocks) == 0) {
            break;
        }
    }

    ret = param->removed_blocks;

out:
    g_thread_pool_free (tpool, TRUE, TRUE);
    g_async_queue_unref (async_queue);
    g_free (param);

    return ret;
}

static gboolean
collect_exist_blocks (const char *store_id, int version,
                      const char *block_id, void *vdata)
{
    GHashTable *exist_blocks = vdata;
    int dummy;

    g_hash_table_replace (exist_blocks, g_strdup (block_id), &dummy);

    return TRUE;
}

static void
check_fs_liveness (gpointer data, gpointer user_data)
{
    char *fs_id = data;
    CheckFSParam *param = user_data;

    if (!bloom_test (param->index, fs_id)) {
        pthread_mutex_lock (&param->counter_lock);
        param->removed_fs ++;
        pthread_mutex_unlock (&param->counter_lock);
        if (!param->dry_run)
            seaf_fs_manager_delete_object(seaf->fs_mgr,
                                          param->store_id, param->repo_version,
                                          fs_id);
    }

    g_async_queue_push (param->async_queue, fs_id);
}

static gint64
check_existing_fs (char *store_id, int repo_version, GHashTable *exist_fs,
                   Bloom *fs_index, int dry_run)
{
    char *fs_id;
    GThreadPool *tpool = NULL;
    GAsyncQueue *async_queue = NULL;
    CheckFSParam *param = NULL;
    GHashTableIter iter;
    gpointer key, value;
    gint64 ret = 0;

    async_queue = g_async_queue_new ();
    param = g_new0 (CheckFSParam, 1);
    param->store_id = store_id;
    param->repo_version = repo_version;
    param->index = fs_index;
    param->dry_run = dry_run;
    param->async_queue = async_queue;
    pthread_mutex_init (&param->counter_lock, NULL);

    tpool = g_thread_pool_new (check_fs_liveness, param, MAX_THREADS, FALSE, NULL);
    if (!tpool) {
        seaf_warning ("Failed to create thread pool for repo %s, stop gc.\n",
                      store_id);
        ret = -1;
        goto out;
    }

    g_hash_table_iter_init (&iter, exist_fs);

    while (g_hash_table_iter_next (&iter, &key, &value)) {
        g_thread_pool_push (tpool, (char *)key, NULL);
    }

    while ((fs_id = g_async_queue_pop (async_queue))) {
        g_hash_table_remove (exist_fs, fs_id);
        if (g_hash_table_size (exist_fs) == 0) {
            break;
        }
    }

    ret = param->removed_fs;

out:
    g_thread_pool_free (tpool, TRUE, TRUE);
    g_async_queue_unref (async_queue);
    g_free (param);

    return ret;
}

static gboolean
collect_exist_fs (const char *store_id, int version,
                   const char *fs_id, void *vdata)
{
    GHashTable *exist_fs = vdata;
    int dummy;

    g_hash_table_replace (exist_fs, g_strdup (fs_id), &dummy);

    return TRUE;
}

static gint64
populate_gc_index_for_virtual_repos_for_new_commits (GList *virtual_repos,
                                                     SeafDBTrans *trans)
{
    GList *ptr;
    SeafRepo *vrepo;
    gint64 scan_ret = 0;
    gint64 ret = 0;
    GCData *data = NULL;

    for (ptr = virtual_repos; ptr; ptr = ptr->next) {
        data = ptr->data;
        if (!data)
            continue;

        vrepo = data->repo;
        if (!vrepo) {
            continue;
        }

        scan_ret = populate_gc_index_for_repo_for_new_commits (data, trans);
        if (scan_ret < 0) {
            ret = -1;
            goto out;
        }
        ret += scan_ret;
    }

out:
    return ret;
}

static gint64
populate_gc_index_for_virtual_repos (SeafRepo *repo,
                                     GList **virtual_repos,
                                     Bloom *blocks_index,
                                     Bloom *fs_index,
                                     SeafDBTrans *trans,
                                     int verbose)
{
    GList *vrepo_ids = NULL, *ptr;
    char *repo_id;
    SeafRepo *vrepo;
    gint64 scan_ret = 0;
    gint64 ret = 0;
    GCData *data;

    vrepo_ids = seaf_repo_manager_get_virtual_repo_ids_by_origin (seaf->repo_mgr,
                                                                  repo->id);
    for (ptr = vrepo_ids; ptr; ptr = ptr->next) {
        repo_id = ptr->data;
        vrepo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
        if (!vrepo) {
            seaf_warning ("Failed to get repo %s.\n", repo_id);
            ret = -1;
            goto out;
        }

        data = gc_data_new (vrepo, blocks_index, fs_index, verbose);
        *virtual_repos = g_list_prepend (*virtual_repos, data);

        scan_ret = populate_gc_index_for_repo (data, trans);
        seaf_repo_unref(vrepo);
        if (scan_ret < 0) {
            ret = -1;
            goto out;
        }
        ret += scan_ret;
    }

out:
    string_list_free (vrepo_ids);
    return ret;
}

/*
 * @keep_days: explicitly sepecify how many days of history to keep after GC.
 *             This has higher priority than the history limit set in database.
 * @online: is running online GC. Online GC is not supported for SQLite DB.
 */
gint64
gc_v1_repo (SeafRepo *repo, int dry_run, int online, int verbose, int rm_fs)
{
    Bloom *blocks_index = NULL;
    Bloom *fs_index = NULL;
    GHashTable *exist_blocks = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
    GHashTable *exist_fs = NULL;
    GList *virtual_repos = NULL;
    guint64 total_blocks = 0;
    guint64 total_fs = 0;
    guint64 reachable_blocks = 0;
    gint64 removed_fs = 0;
    gint64 ret;
    GCData *data;
    SeafDBTrans *trans = NULL;

    ret = seaf_block_manager_foreach_block (seaf->block_mgr,
                                            repo->store_id, repo->version,
                                            collect_exist_blocks,
                                            exist_blocks);
    if (ret < 0) {
        seaf_warning ("Failed to collect existing blocks for repo %.8s, stop GC.\n\n",
                      repo->id);
        g_hash_table_destroy (exist_blocks);
        return ret;
    }

    total_blocks = g_hash_table_size (exist_blocks);
    if (total_blocks == 0) {
        seaf_message ("No blocks for repo %.8s, skip GC.\n\n", repo->id);
        g_hash_table_destroy (exist_blocks);
        return 0;
    }

     if (rm_fs) {
        exist_fs = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
        ret = seaf_obj_store_foreach_obj (seaf->fs_mgr->obj_store,
                                          repo->store_id, repo->version,
                                          collect_exist_fs,
                                          exist_fs);
        if (ret < 0) {
            seaf_warning ("Failed to collect existing fs for repo %.8s, stop GC.\n\n",
                        repo->id);
            goto out;
        }

        total_fs = g_hash_table_size (exist_fs);
    }

    if (rm_fs)
        seaf_message ("GC started for repo %.8s. Total block number is %"G_GUINT64_FORMAT", total fs number is %"G_GUINT64_FORMAT".\n",
                      repo->id, total_blocks, total_fs);
    else
        seaf_message ("GC started for repo %.8s. Total block number is %"G_GUINT64_FORMAT".\n",
                      repo->id, total_blocks);

    /*
     * Store the index of live blocks in bloom filter to save memory.
     * Since bloom filters only have false-positive, we
     * may skip some garbage blocks, but we won't delete
     * blocks that are still alive.
     */
    blocks_index = alloc_gc_index (repo->id, total_blocks);
    if (!blocks_index) {
        seaf_warning ("GC: Failed to allocate blocks index for repo %.8s, stop gc.\n",
                      repo->id);
        ret = -1;
        goto out;
    }

    if (rm_fs && total_fs > 0) {
        fs_index = alloc_gc_index (repo->id, total_fs);
        if (!fs_index) {
            seaf_warning ("GC: Failed to allocate fs index for repo %.8s, stop gc.\n",
                        repo->id);
            ret = -1;
            goto out;
        }
    }

    data = gc_data_new (repo, blocks_index, fs_index, verbose);
    ret = populate_gc_index_for_repo (data, trans);
    if (ret < 0) {
        goto out;
    }

    reachable_blocks += ret;

    /* Since virtual repos share fs and block store with the origin repo,
     * it's necessary to do GC for them together.
     */
    ret = populate_gc_index_for_virtual_repos (repo, &virtual_repos,
                                               blocks_index, fs_index, trans, verbose);
    if (ret < 0) {
        goto out;
    }

    reachable_blocks += ret;

    if (online) {
        trans = seaf_db_begin_transaction (seaf->db);
        if (!trans)
            goto out;
    }

    ret = populate_gc_index_for_repo_for_new_commits (data, trans);
    if (ret < 0) {
        if (online) {
            seaf_db_rollback (trans);
            seaf_db_trans_close (trans);
        }
        goto out;
    }

    reachable_blocks += ret;


    ret = populate_gc_index_for_virtual_repos_for_new_commits (virtual_repos, trans);

    if (ret < 0) {
        if (online) {
            seaf_db_rollback (trans);
            seaf_db_trans_close (trans);
        }
        goto out;
    }

    reachable_blocks += ret;

    if (!dry_run)
        seaf_message ("Scanning and deleting unused blocks for repo %.8s.\n",
                      repo->id);
    else
        seaf_message ("Scanning unused blocks for repo %.8s.\n", repo->id);

    ret = check_existing_blocks (repo->store_id, repo->version, exist_blocks,
                                 blocks_index, dry_run);
    if (ret < 0) {
        if (online) {
            seaf_db_rollback (trans);
            seaf_db_trans_close (trans);
        }
        goto out;
    }

    if (rm_fs && total_fs > 0) {
        removed_fs = check_existing_fs(repo->store_id, repo->version, exist_fs,
                                       fs_index, dry_run);
        if (removed_fs < 0) {
            if (online) {
                seaf_db_rollback (trans);
                seaf_db_trans_close (trans);
            }
            goto out;
        }
    }

    if (!dry_run) {
        if (rm_fs)
            seaf_message ("GC finished for repo %.8s. %"G_GUINT64_FORMAT" blocks total, "
                          "about %"G_GUINT64_FORMAT" reachable blocks, "
                          "%"G_GUINT64_FORMAT" blocks are removed. "
                          "%"G_GUINT64_FORMAT" fs are removed.\n",
                          repo->id, total_blocks, reachable_blocks, ret, removed_fs);
        else
            seaf_message ("GC finished for repo %.8s. %"G_GUINT64_FORMAT" blocks total, "
                          "about %"G_GUINT64_FORMAT" reachable blocks, "
                          "%"G_GUINT64_FORMAT" blocks are removed.\n",
                          repo->id, total_blocks, reachable_blocks, ret);
    } else {
        if (rm_fs)
            seaf_message ("GC finished for repo %.8s. %"G_GUINT64_FORMAT" blocks total, "
                          "about %"G_GUINT64_FORMAT" reachable blocks, "
                          "%"G_GUINT64_FORMAT" blocks can be removed. "
                          "%"G_GUINT64_FORMAT" fs can be removed.\n",
                          repo->id, total_blocks, reachable_blocks, ret, removed_fs);
        else
            seaf_message ("GC finished for repo %.8s. %"G_GUINT64_FORMAT" blocks total, "
                          "about %"G_GUINT64_FORMAT" reachable blocks, "
                          "%"G_GUINT64_FORMAT" blocks can be removed.\n",
                          repo->id, total_blocks, reachable_blocks, ret);
    }

    if (online) {
        if (seaf_db_commit (trans) < 0) {
            seaf_db_rollback (trans);
        }
        seaf_db_trans_close (trans);
    }

out:
    printf ("\n");

    if (blocks_index)
        bloom_destroy (blocks_index);
    if (fs_index)
        bloom_destroy(fs_index);
    g_hash_table_destroy (exist_blocks);
    if (exist_fs)
        g_hash_table_destroy (exist_fs);
    gc_data_free (data);
    g_list_free_full(virtual_repos, (GDestroyNotify)gc_data_free);
    return ret;
}

typedef enum RemoveType {
    COMMIT,
    FS,
    BLOCK
} RemoveType;

typedef struct RemoveTask {
    const char *repo_id;
    RemoveType remove_type;
    gboolean success;
} RemoveTask;

static void
remove_store (gpointer data, gpointer user_data)
{
    RemoveTask *task = data;
    GAsyncQueue *async_queue = user_data;
    int ret = 0;

    switch (task->remove_type) {
        case COMMIT:
            seaf_message ("Deleting commits for repo %s.\n", task->repo_id);
            ret = seaf_commit_manager_remove_store (seaf->commit_mgr, task->repo_id);
            if (ret == 0) {
                task->success = TRUE;
            }
            break;
        case FS:
            seaf_message ("Deleting fs objects for repo %s.\n", task->repo_id);
            ret = seaf_fs_manager_remove_store (seaf->fs_mgr, task->repo_id);
            if (ret == 0) {
                task->success = TRUE;
            }
            break;
        case BLOCK:
            seaf_message ("Deleting blocks for repo %s.\n", task->repo_id);
            ret = seaf_block_manager_remove_store (seaf->block_mgr, task->repo_id);
            if (ret == 0) {
                task->success = TRUE;
            }
            break;
        default:
            break;
    }

    g_async_queue_push (async_queue, task);
}

void
delete_garbaged_repos (int dry_run, int thread_num)
{
    GList *del_repos = NULL;
    GList *ptr;
    GAsyncQueue *async_queue = NULL;
    int tnum;
    GThreadPool *tpool = NULL;
    RemoveTask *task = NULL;
    int n_tasks = 0;
    char *repo_id;
    char *dup_id;
    GHashTableIter iter;
    gpointer key, value;
    GHashTable *deleted;

    deleted = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

    seaf_message ("=== Repos deleted by users ===\n");
    del_repos = seaf_repo_manager_list_garbage_repos (seaf->repo_mgr);

    if (!dry_run && del_repos) {
        async_queue = g_async_queue_new ();
        if (!async_queue) {
            seaf_warning ("Failed to create async queue.\n");
            goto out;
        }

        tnum = thread_num <= 0 ? MAX_THREADS : thread_num;
        tpool = g_thread_pool_new (remove_store, async_queue, tnum, FALSE, NULL);
        if (!tpool) {
            seaf_warning ("Failed to create thread pool.\n");
            goto out;
        }
    }

    for (ptr = del_repos; ptr; ptr = ptr->next) {
        repo_id = ptr->data;
        if (!is_uuid_valid(repo_id)) {
            continue;
        }

        /* Confirm repo doesn't exist before removing blocks. */
        if (!seaf_repo_manager_repo_exists (seaf->repo_mgr, repo_id)) {
            if (!dry_run) {
                seaf_message ("Start to GC deleted repo %s.\n", repo_id);
                // Remove commit
                task = g_new0 (RemoveTask, 1);
                task->repo_id = repo_id;
                task->remove_type = COMMIT;
                g_thread_pool_push (tpool, task, NULL);

                // Remove fs
                task = g_new0 (RemoveTask, 1);
                task->repo_id = repo_id;
                task->remove_type = FS;
                g_thread_pool_push (tpool, task, NULL);

                // Remove block
                task = g_new0 (RemoveTask, 1);
                task->repo_id = repo_id;
                task->remove_type = BLOCK;
                g_thread_pool_push (tpool, task, NULL);

                n_tasks += 3;

                dup_id = g_strdup (repo_id);
                g_hash_table_insert (deleted, dup_id, dup_id);
            } else {
                seaf_message ("Repo %s can be GC'ed.\n", repo_id);
            }
        }
    }

    while (n_tasks > 0 && (task = g_async_queue_pop (async_queue))) {
        n_tasks--;
        if (!task->success) {
            if (g_hash_table_lookup (deleted, task->repo_id)) {
                g_hash_table_remove(deleted, task->repo_id);
            }
        }
        g_free (task);
    }

    if (!dry_run) {
        g_hash_table_iter_init (&iter, deleted);
        while (g_hash_table_iter_next (&iter, &key, &value)) {
            seaf_repo_manager_remove_garbage_repo (seaf->repo_mgr, (char *)key);
        }
    }

out:
    g_hash_table_destroy (deleted);
    if (tpool)
        g_thread_pool_free (tpool, TRUE, TRUE);
    if (async_queue)
        g_async_queue_unref (async_queue);
    string_list_free (del_repos);
}

typedef struct GCRepoParam {
    int dry_run;
    int verbose;
    int rm_fs;
    gboolean online;
    GAsyncQueue *async_queue;
} GCRepoParam;

typedef struct GCRepo {
    SeafRepo *repo;
    gint64 gc_ret;
} GCRepo;

static void
free_gc_repo (GCRepo *gc_repo)
{
    if (!gc_repo)
        return;

    seaf_repo_unref (gc_repo->repo);
    g_free (gc_repo);
}

static void
gc_repo_cb (gpointer data, gpointer user_data)
{
    GCRepo *gc_repo = data;
    GCRepoParam *param = user_data;
    SeafRepo *repo = gc_repo->repo;

    seaf_message ("GC version %d repo %s(%s)\n",
                  repo->version, repo->name, repo->id);

    gc_repo->gc_ret = gc_v1_repo (repo, param->dry_run,
                                  param->online, param->verbose, param->rm_fs);

    g_async_queue_push (param->async_queue, gc_repo);
}

int
gc_core_run (GList *repo_id_list, const char *id_prefix,
             int dry_run, int verbose, int thread_num, int rm_fs)
{
    GList *ptr;
    SeafRepo *repo;
    GList *corrupt_repos = NULL;
    GList *del_block_repos = NULL;
    gboolean del_garbage = FALSE;
    GAsyncQueue *async_queue = NULL;
    GCRepoParam *param = NULL;
    int tnum;
    GThreadPool *tpool = NULL;
    int gc_repo_num = 0;
    GCRepo *gc_repo = NULL;
    char *repo_id;
    gboolean online;

    if (seaf_db_type (seaf->db) == SEAF_DB_TYPE_SQLITE) {
        online = FALSE;
        seaf_message ("Database is SQLite, use offline GC.\n");
    } else {
        online = TRUE;
        seaf_message ("Database is MySQL/Postgre/Oracle, use online GC.\n");
    }

    async_queue = g_async_queue_new ();
    if (!async_queue) {
        seaf_warning ("Failed to create async queue, stop gc.\n");
        return -1;
    }

    param = g_new0 (GCRepoParam, 1);
    param->dry_run = dry_run;
    param->verbose = verbose;
    param->rm_fs = rm_fs;
    param->online = online;
    param->async_queue = async_queue;

    tnum = thread_num <= 0 ? MAX_THREADS : thread_num;
    tpool = g_thread_pool_new (gc_repo_cb, param, tnum, FALSE, NULL);
    if (!tpool) {
        seaf_warning ("Failed to create thread pool, stop gc.\n");
        g_async_queue_unref (async_queue);
        g_free (param);
        return -1;
    }

    seaf_message ("Using up to %d threads to run GC.\n", tnum);

    if (id_prefix) {
        if (repo_id_list)
            g_list_free (repo_id_list);
        repo_id_list = seaf_repo_manager_get_repo_id_list_by_prefix (seaf->repo_mgr, id_prefix);
        del_garbage = TRUE;
    } else if (repo_id_list == NULL) {
        repo_id_list = seaf_repo_manager_get_repo_id_list (seaf->repo_mgr);
        del_garbage = TRUE;
    }

    for (ptr = repo_id_list; ptr; ptr = ptr->next) {
        repo = seaf_repo_manager_get_repo_ex (seaf->repo_mgr, (const gchar *)ptr->data);

        g_free (ptr->data);

        if (!repo)
            continue;

        if (repo->is_corrupted) {
            corrupt_repos = g_list_prepend (corrupt_repos, g_strdup(repo->id));
            seaf_message ("Repo %s is damaged, skip GC.\n\n", repo->id);
            seaf_repo_unref (repo);
            continue;
        }

        if (!repo->is_virtual) {
            gc_repo = g_new0 (GCRepo, 1);
            gc_repo->repo = repo;
            g_thread_pool_push (tpool, gc_repo, NULL);
            gc_repo_num++;
        } else {
            seaf_repo_unref (repo);
        }
    }
    g_list_free (repo_id_list);

    while (gc_repo_num > 0 && (gc_repo = g_async_queue_pop (async_queue))) {
        if (gc_repo->gc_ret < 0) {
            corrupt_repos = g_list_prepend (corrupt_repos, g_strdup(gc_repo->repo->id));
        } else if (dry_run && gc_repo->gc_ret) {
            del_block_repos = g_list_prepend (del_block_repos, g_strdup(gc_repo->repo->id));
        }
        free_gc_repo (gc_repo);
        gc_repo_num--;
    }

    if (del_garbage) {
        delete_garbaged_repos (dry_run, tnum);
    }

    seaf_message ("=== GC is finished ===\n");

    if (corrupt_repos) {
        seaf_message ("The following repos are damaged. "
                      "You can run seaf-fsck to fix them.\n");
        for (ptr = corrupt_repos; ptr; ptr = ptr->next) {
            repo_id = ptr->data;
            seaf_message ("%s\n", repo_id);
            g_free (repo_id);
        }
        g_list_free (corrupt_repos);
    }

    if (del_block_repos) {
        printf("\n");
        seaf_message ("The following repos have blocks to be removed:\n");
        for (ptr = del_block_repos; ptr; ptr = ptr->next) {
            repo_id = ptr->data;
            seaf_message ("%s\n", repo_id);
            g_free (repo_id);
        }
        g_list_free (del_block_repos);
    }

    g_thread_pool_free (tpool, TRUE, TRUE);
    g_async_queue_unref (async_queue);
    g_free (param);

    return 0;
}
