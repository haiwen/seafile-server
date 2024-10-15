#include "seafile-session.h"
#include "utils.h"
#include "log.h"

typedef struct VerifyData {
    SeafRepo *repo;
    gint64 truncate_time;
    gboolean traversed_head;
} VerifyData;

static int
check_blocks (VerifyData *data, const char *file_id)
{
    SeafRepo *repo = data->repo;
    Seafile *seafile;
    int i;

    seafile = seaf_fs_manager_get_seafile (seaf->fs_mgr,
                                           repo->store_id,
                                           repo->version,
                                           file_id);
    if (!seafile) {
        seaf_warning ("Failed to find file %s.\n", file_id);
        return -1;
    }

    for (i = 0; i < seafile->n_blocks; ++i) {
        if (!seaf_block_manager_block_exists (seaf->block_mgr,
                                              repo->store_id,
                                              repo->version,
                                              seafile->blk_sha1s[i]))
            g_message ("Block %s is missing.\n", seafile->blk_sha1s[i]);
    }

    seafile_unref (seafile);

    return 0;
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
    VerifyData *data = user_data;

    if (type == SEAF_METADATA_TYPE_FILE && check_blocks (data, obj_id) < 0)
        return FALSE;

    return TRUE;
}

static gboolean
traverse_commit (SeafCommit *commit, void *vdata, gboolean *stop)
{
    VerifyData *data = vdata;
    SeafRepo *repo = data->repo;
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

    ret = seaf_fs_manager_traverse_tree (seaf->fs_mgr,
                                         repo->store_id,
                                         repo->version,
                                         commit->root_id,
                                         fs_callback,
                                         vdata, FALSE);
    if (ret < 0)
        return FALSE;

    return TRUE;
}

static int
verify_virtual_repos (VerifyData *data)
{
    SeafRepo *repo = data->repo;
    if (repo->is_virtual) {
        return 0;
    }

    GList *vrepo_ids = NULL, *ptr;
    char *repo_id;
    SeafVirtRepo *vinfo;
    int ret = 0;

    vrepo_ids = seaf_repo_manager_get_virtual_repo_ids_by_origin (seaf->repo_mgr,
                                                                  repo->id);

    for (ptr = vrepo_ids; ptr; ptr = ptr->next) {
        repo_id = ptr->data;
        vinfo = seaf_repo_manager_get_virtual_repo_info (seaf->repo_mgr, repo_id);
        if (!vinfo) {
            continue;
        }

        gboolean res = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                                 repo->store_id, repo->version,
                                                                 vinfo->base_commit,
                                                                 traverse_commit,
                                                                 data,
                                                                 FALSE);
        seaf_virtual_repo_info_free (vinfo);
        if (!res) {
            seaf_warning ("Failed to traverse base commit %s for virtual repo %s.\n", vinfo->base_commit, repo_id);
            ret = -1;
            goto out;
        }
    }

out:
    string_list_free (vrepo_ids);
    return ret;

}

static int
verify_repo (SeafRepo *repo)
{
    GList *branches, *ptr;
    SeafBranch *branch;
    int ret = 0;
    VerifyData data = {0};

    data.repo = repo;
    data.truncate_time = seaf_repo_manager_get_repo_truncate_time (repo->manager,
                                                                   repo->id);

    branches = seaf_branch_manager_get_branch_list (seaf->branch_mgr, repo->id);
    if (branches == NULL) {
        seaf_warning ("[GC] Failed to get branch list of repo %s.\n", repo->id);
        return -1;
    }

    for (ptr = branches; ptr != NULL; ptr = ptr->next) {
        branch = ptr->data;
        gboolean res = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                                 repo->id,
                                                                 repo->version,
                                                                 branch->commit_id,
                                                                 traverse_commit,
                                                                 &data, FALSE);
        seaf_branch_unref (branch);
        if (!res) {
            ret = -1;
            break;
        }
    }

    g_list_free (branches);

    if (ret < 0) {
        return ret;
    }

    ret = verify_virtual_repos (&data);

    return ret;
}

int
verify_repos (GList *repo_id_list)
{
    if (repo_id_list == NULL)
        repo_id_list = seaf_repo_manager_get_repo_id_list (seaf->repo_mgr);

    GList *ptr;
    SeafRepo *repo;
    int ret = 0;

    for (ptr = repo_id_list; ptr != NULL; ptr = ptr->next) {
        repo = seaf_repo_manager_get_repo_ex (seaf->repo_mgr, (const gchar *)ptr->data);

        g_free (ptr->data);

        if (!repo)
            continue;

        if (repo->is_corrupted) {
           seaf_warning ("Repo %s is corrupted.\n", repo->id);
        } else {
            ret = verify_repo (repo);
            seaf_repo_unref (repo);
            if (ret < 0)
                break;
        }
    }

    g_list_free (repo_id_list);

    return ret;
}
