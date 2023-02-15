/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "seafile-session.h"
#include "bloom-filter.h"
#include "gc-core.h"
#include "utils.h"

#define DEBUG_FLAG SEAFILE_DEBUG_OTHER
#include "log.h"

#define MAX_BF_SIZE (((size_t)1) << 29)   /* 64 MB */

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
static Bloom *
alloc_gc_index (guint64 total_objs)
{
    size_t size;

    size = (size_t) MAX(total_objs << 2, 1 << 13);
    size = MIN (size, MAX_BF_SIZE);

    seaf_message ("GC index size is %u Byte.\n", (int)size >> 3);

    return bloom_create (size, 3, 0);
}

typedef struct {
    SeafRepo *repo;
    Bloom *blocks_index;
    Bloom *fs_index;
    GHashTable *visited;

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

    add_fs_to_index(data, obj_id);

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
        seaf_message ("Traversing commit %.8s.\n", commit->commit_id);

    ++data->traversed_commits;

    data->traversed_fs_objs = 0;

    ret = seaf_fs_manager_traverse_tree (seaf->fs_mgr,
                                         data->repo->store_id, data->repo->version,
                                         commit->root_id,
                                         fs_callback,
                                         data, FALSE);
    if (ret < 0)
        return FALSE;

    if (data->verbose)
        seaf_message ("Traversed %"G_GINT64_FORMAT" fs objects.\n",
                      data->traversed_fs_objs);

    return TRUE;
}

static gint64
populate_gc_index_for_repo (SeafRepo *repo, Bloom *blocks_index, Bloom *fs_index, int verbose)
{
    GList *branches, *ptr;
    SeafBranch *branch;
    GCData *data;
    int ret = 0;

    if (!repo->is_virtual)
        seaf_message ("Populating index for repo %.8s.\n", repo->id);
    else
        seaf_message ("Populating index for sub-repo %.8s.\n", repo->id);

    branches = seaf_branch_manager_get_branch_list (seaf->branch_mgr, repo->id);
    if (branches == NULL) {
        seaf_warning ("[GC] Failed to get branch list of repo %s.\n", repo->id);
        return -1;
    }

    data = g_new0(GCData, 1);
    data->repo = repo;
    data->blocks_index = blocks_index;
    data->fs_index = fs_index;
    data->visited = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
    data->verbose = verbose;

    gint64 truncate_time = seaf_repo_manager_get_repo_truncate_time (repo->manager,
                                                                     repo->id);
    if (truncate_time > 0) {
        seaf_repo_manager_set_repo_valid_since (repo->manager,
                                                repo->id,
                                                truncate_time);
    } else if (truncate_time == 0) {
        /* Only the head commit is valid after GC if no history is kept. */
        SeafCommit *head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                           repo->id, repo->version,
                                                           repo->head->commit_id);
        if (head)
            seaf_repo_manager_set_repo_valid_since (repo->manager,
                                                    repo->id,
                                                    head->ctime);
        seaf_commit_unref (head);
    }

    data->truncate_time = truncate_time;

    for (ptr = branches; ptr != NULL; ptr = ptr->next) {
        branch = ptr->data;
        gboolean res = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                                 repo->id,
                                                                 repo->version,
                                                                 branch->commit_id,
                                                                 traverse_commit,
                                                                 data,
                                                                 FALSE);
        seaf_branch_unref (branch);
        if (!res) {
            ret = -1;
            break;
        }
    }

    // Traverse the base commit of the virtual repo. Otherwise, if the virtual repo has not been updated for a long time,
    // the fs object corresponding to the base commit will be removed by mistake.
    if (repo->is_virtual) {
        SeafVirtRepo *vinfo = NULL;
        vinfo = seaf_repo_manager_get_virtual_repo_info (seaf->repo_mgr, repo->id);
        if (!vinfo) {
            seaf_warning ("Failed to get virtual repo info %.8s.\n", repo->id);
            ret = -1;
        }
        gboolean res = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                                 repo->store_id, repo->version,
                                                                 vinfo->base_commit,
                                                                 traverse_commit,
                                                                 data,
                                                                 FALSE);
        seaf_virtual_repo_info_free (vinfo);
        if (!res) {
            seaf_warning ("Failed to populate index for virtual repo %.8s.\n", repo->id);
            ret = -1;
        }
    }

    seaf_message ("Traversed %d commits, %"G_GINT64_FORMAT" blocks.\n",
                  data->traversed_commits, data->traversed_blocks);
    ret = data->traversed_blocks;

    g_list_free (branches);
    g_hash_table_destroy (data->visited);
    g_free (data);

    return ret;
}

typedef struct {
    Bloom *index;
    int dry_run;
    guint64 removed_blocks;
} CheckBlocksData;

static gboolean
check_block_liveness (const char *store_id, int version,
                      const char *block_id, void *vdata)
{
    CheckBlocksData *data = vdata;
    Bloom *index = data->index;

    if (!bloom_test (index, block_id)) {
        data->removed_blocks++;
        if (!data->dry_run)
            seaf_block_manager_remove_block (seaf->block_mgr,
                                             store_id, version,
                                             block_id);
    }

    return TRUE;
}

#define MAX_THREADS 10

static gint64
check_existing_fs (char *store_id, int repo_version, GHashTable *exist_fs,
                   Bloom *fs_index, int dry_run)
{
    GHashTableIter iter;
    gpointer key, value;
    gint64 ret = 0;

    g_hash_table_iter_init (&iter, exist_fs);

    while (g_hash_table_iter_next (&iter, &key, &value)) {
        if (!bloom_test (fs_index, (char *)key)) {
            ret++;
            if (dry_run)
                continue;
            seaf_fs_manager_delete_object(seaf->fs_mgr,
                                          store_id, repo_version,
                                          (char *)key);
        }
    }

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
populate_gc_index_for_virtual_repos (SeafRepo *repo, Bloom *blocks_index, Bloom *fs_index, int verbose)
{
    GList *vrepo_ids = NULL, *ptr;
    char *repo_id;
    SeafRepo *vrepo;
    gint64 ret = 0;
    gint64 scan_ret = 0;

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

        scan_ret = populate_gc_index_for_repo (vrepo, blocks_index, fs_index, verbose);
        seaf_repo_unref (vrepo);
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

gint64
gc_v1_repo (SeafRepo *repo, int dry_run, int verbose, int rm_fs)
{
    Bloom *blocks_index = NULL;
    Bloom *fs_index = NULL;
    GHashTable *exist_fs = NULL;
    guint64 total_blocks;
    guint64 removed_blocks;
    guint64 reachable_blocks;
    guint64 total_fs = 0;
    gint64 removed_fs = 0;
    gint64 ret;

    total_blocks = seaf_block_manager_get_block_number (seaf->block_mgr,
                                                        repo->store_id, repo->version);
    reachable_blocks = 0;

    if (total_blocks == 0) {
        seaf_message ("No blocks. Skip GC.\n\n");
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
        seaf_message ("GC started. Total block number is %"G_GUINT64_FORMAT", total fs number is %"G_GUINT64_FORMAT".\n", total_blocks, total_fs);
    else
        seaf_message ("GC started. Total block number is %"G_GUINT64_FORMAT".\n", total_blocks);

    /*
     * Store the index of live blocks in bloom filter to save memory.
     * Since bloom filters only have false-positive, we
     * may skip some garbage blocks, but we won't delete
     * blocks that are still alive.
     */
    blocks_index = alloc_gc_index (total_blocks);
    if (!blocks_index) {
        seaf_warning ("GC: Failed to allocate blocks_index.\n");
        ret = -1;
        goto out;
    }

    if (rm_fs && total_fs > 0) {
        fs_index = alloc_gc_index (total_fs);
        if (!fs_index) {
            seaf_warning ("GC: Failed to allocate fs index for repo %.8s, stop gc.\n",
                        repo->id);
            ret = -1;
            goto out;
        }
    }

    seaf_message ("Populating index.\n");

    ret = populate_gc_index_for_repo (repo, blocks_index, fs_index, verbose);
    if (ret < 0)
        goto out;
    
    reachable_blocks += ret;

    /* Since virtual repos share fs and block store with the origin repo,
     * it's necessary to do GC for them together.
     */
    ret = populate_gc_index_for_virtual_repos (repo, blocks_index, fs_index, verbose);
    if (ret < 0)
        goto out;

    reachable_blocks += ret;

    if (!dry_run)
        seaf_message ("Scanning and deleting unused blocks.\n");
    else
        seaf_message ("Scanning unused blocks.\n");

    CheckBlocksData data;
    data.index = blocks_index;
    data.dry_run = dry_run;
    data.removed_blocks = 0;

    ret = seaf_block_manager_foreach_block (seaf->block_mgr,
                                            repo->store_id, repo->version,
                                            check_block_liveness,
                                            &data);
    if (ret < 0) {
        seaf_warning ("GC: Failed to clean dead blocks.\n");
        goto out;
    }

    removed_blocks = data.removed_blocks;
    ret = removed_blocks;

    if (rm_fs && total_fs > 0) {
        removed_fs = check_existing_fs(repo->store_id, repo->version, exist_fs,
                                       fs_index, dry_run);
        if (removed_fs < 0) {
            goto out;
        }
    }

    if (!dry_run) {
        if (rm_fs)
            seaf_message ("GC finished for repo %.8s. %"G_GUINT64_FORMAT" blocks total, "
                          "about %"G_GUINT64_FORMAT" reachable blocks, "
                          "%"G_GUINT64_FORMAT" blocks are removed. "
                          "%"G_GUINT64_FORMAT" fs are removed.\n",
                          repo->id, total_blocks, reachable_blocks, removed_blocks, removed_fs);
        else
            seaf_message ("GC finished. %"G_GUINT64_FORMAT" blocks total, "
                          "about %"G_GUINT64_FORMAT" reachable blocks, "
                          "%"G_GUINT64_FORMAT" blocks are removed.\n",
                          total_blocks, reachable_blocks, removed_blocks);
    } else {
        if (rm_fs)
            seaf_message ("GC finished for repo %.8s. %"G_GUINT64_FORMAT" blocks total, "
                          "about %"G_GUINT64_FORMAT" reachable blocks, "
                          "%"G_GUINT64_FORMAT" blocks can be removed. "
                          "%"G_GUINT64_FORMAT" fs can be removed.\n",
                          repo->id, total_blocks, reachable_blocks, removed_blocks, removed_fs);
        else
            seaf_message ("GC finished. %"G_GUINT64_FORMAT" blocks total, "
                          "about %"G_GUINT64_FORMAT" reachable blocks, "
                          "%"G_GUINT64_FORMAT" blocks can be removed.\n",
                          total_blocks, reachable_blocks, removed_blocks);
    }

out:
    printf ("\n");

    if (exist_fs)
        g_hash_table_destroy (exist_fs);

    if (blocks_index)
        bloom_destroy (blocks_index);
    if (fs_index)
        bloom_destroy (fs_index);
    return ret;
}

void
delete_garbaged_repos (int dry_run)
{
    GList *del_repos = NULL;
    GList *ptr;

    seaf_message ("=== Repos deleted by users ===\n");
    del_repos = seaf_repo_manager_list_garbage_repos (seaf->repo_mgr);
    for (ptr = del_repos; ptr; ptr = ptr->next) {
        char *repo_id = ptr->data;

        /* Confirm repo doesn't exist before removing blocks. */
        if (!seaf_repo_manager_repo_exists (seaf->repo_mgr, repo_id)) {
            if (!dry_run) {
                seaf_message ("GC deleted repo %.8s.\n", repo_id);
                seaf_commit_manager_remove_store (seaf->commit_mgr, repo_id);
                seaf_fs_manager_remove_store (seaf->fs_mgr, repo_id);
                seaf_block_manager_remove_store (seaf->block_mgr, repo_id);
            } else {
                seaf_message ("Repo %.8s can be GC'ed.\n", repo_id);
            }
        }

        if (!dry_run)
            seaf_repo_manager_remove_garbage_repo (seaf->repo_mgr, repo_id);
        g_free (repo_id);
    }
    g_list_free (del_repos);
}

int
gc_core_run (GList *repo_id_list, int dry_run, int verbose, int rm_fs)
{
    GList *ptr;
    SeafRepo *repo;
    GList *corrupt_repos = NULL;
    GList *del_block_repos = NULL;
    gboolean del_garbage = FALSE;
    gint64 gc_ret;
    char *repo_id;

    if (repo_id_list == NULL) {
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
            continue;
        }

        if (!repo->is_virtual) {
            seaf_message ("GC version %d repo %s(%s)\n",
                          repo->version, repo->name, repo->id);
            gc_ret = gc_v1_repo (repo, dry_run, verbose, rm_fs);
            if (gc_ret < 0) {
                corrupt_repos = g_list_prepend (corrupt_repos, g_strdup(repo->id));
            } else if (dry_run && gc_ret) {
                del_block_repos = g_list_prepend (del_block_repos, g_strdup(repo->id));
            }
        }
        seaf_repo_unref (repo);
    }
    g_list_free (repo_id_list);

    if (del_garbage) {
        delete_garbaged_repos (dry_run);
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

    return 0;
}
