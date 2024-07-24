#include "common.h"

#include "seafile-session.h"
#include "merge-new.h"
#include "vc-common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_MERGE
#include "log.h"

static int
merge_trees_recursive (const char *store_id, int version,
                       int n, SeafDir *trees[],
                       const char *basedir,
                       MergeOptions *opt);

static const char *
get_nickname_by_modifier (GHashTable *email_to_nickname, const char *modifier)
{
    const char *nickname = NULL;

    if (!modifier) {
        return NULL;
    }

    nickname = g_hash_table_lookup (email_to_nickname, modifier);
    if (nickname) {
        return nickname;
    }

    nickname = http_tx_manager_get_nickname (modifier);

    if (!nickname) {
        nickname = g_strdup (modifier);
    }
    g_hash_table_insert (email_to_nickname, g_strdup(modifier), nickname);

    return nickname;
}

static char *
merge_conflict_filename (const char *store_id, int version,
                         MergeOptions *opt,
                         const char *basedir,
                         const char *filename)
{
    char *path = NULL, *modifier = NULL, *conflict_name = NULL;
    const char *nickname = NULL;
    gint64 mtime;
    SeafCommit *commit;

    path = g_strconcat (basedir, filename, NULL);

    int rc = get_file_modifier_mtime (opt->remote_repo_id,
                                      store_id,
                                      version,
                                      opt->remote_head,
                                      path,
                                      &modifier, &mtime);
    if (rc < 0) {
        commit = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                 opt->remote_repo_id,
                                                 version,
                                                 opt->remote_head);
        if (!commit) {
            seaf_warning ("Failed to find remote head %s:%s.\n",
                          opt->remote_repo_id, opt->remote_head);
            goto out;
        }
        modifier = g_strdup(commit->creator_name);
        mtime = (gint64)time(NULL);
        seaf_commit_unref (commit);
    }

    nickname = modifier;
    if (seaf->seahub_pk)
        nickname = get_nickname_by_modifier (opt->email_to_nickname, modifier);

    conflict_name = gen_conflict_path (filename, nickname, mtime);

out:
    g_free (path);
    g_free (modifier);
    return conflict_name;
}

static char *
merge_conflict_dirname (const char *store_id, int version,
                        MergeOptions *opt,
                        const char *basedir,
                        const char *dirname)
{
    char *modifier = NULL, *conflict_name = NULL;
    const char *nickname = NULL;
    SeafCommit *commit;

    commit = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             opt->remote_repo_id, version,
                                             opt->remote_head);
    if (!commit) {
        seaf_warning ("Failed to find remote head %s:%s.\n",
                      opt->remote_repo_id, opt->remote_head);
        goto out;
    }
    modifier = g_strdup(commit->creator_name);
    seaf_commit_unref (commit);

    nickname = modifier;
    if (seaf->seahub_pk)
        nickname = get_nickname_by_modifier (opt->email_to_nickname, modifier);

    conflict_name = gen_conflict_path (dirname, nickname, (gint64)time(NULL));

out:
    g_free (modifier);
    return conflict_name;
}

int twoway_merge(const char *store_id, int version, const char *basedir,
                 SeafDirent *dents[], GList **dents_out, struct MergeOptions *opt)
{
    SeafDirent *files[2];
    int i;
    int n = opt->n_ways;

    memset (files, 0, sizeof(files[0])*n);
    for (i = 0; i < n; ++i) {
        if (dents[i] && S_ISREG(dents[i]->mode))
            files[i] = dents[i];
    }

    SeafDirent *head, *remote;
    char *conflict_name;

    head = files[0];
    remote = files[1];

    if (head && remote) {
        if (strcmp (head->id, remote->id) == 0) {
            // file match
            seaf_debug ("%s%s: files match\n", basedir, head->name);
            *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(head));
        } else {
            // file content conflict
            seaf_debug ("%s%s: files conflict\n", basedir, head->name);
            conflict_name = merge_conflict_filename(store_id, version,
                                                    opt,
                                                    basedir,
                                                    head->name);
            if (!conflict_name)
                return -1;

            g_free (remote->name);
            remote->name = conflict_name;
            remote->name_len = strlen (remote->name);

            *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(head));
            *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(remote));

            opt->conflict = TRUE;
        }
    } else if (!head && remote) {
        // file not in head, but in remote
        seaf_debug ("%s%s: added in remote\n", basedir, remote->name);
        *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(remote));
    } else if (head && !remote) {
        // file in head, but not in remote
        seaf_debug ("%s%s: added in head\n", basedir, head->name);
        *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(head));
    }

    return 0;
}

static int
threeway_merge (const char *store_id, int version,
                 SeafDirent *dents[],
                 const char *basedir,
                 GList **dents_out,
                 MergeOptions *opt)
{
    SeafDirent *files[3];
    int i;
    gint64 curr_time;
    int n = opt->n_ways;

    memset (files, 0, sizeof(files[0])*n);
    for (i = 0; i < n; ++i) {
        if (dents[i] && S_ISREG(dents[i]->mode))
            files[i] = dents[i];
    }

    SeafDirent *base, *head, *remote;
    char *conflict_name;

    base = files[0];
    head = files[1];
    remote = files[2];

    if (head && remote) {
        if (strcmp (head->id, remote->id) == 0) {
            seaf_debug ("%s%s: files match\n", basedir, head->name);

            *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(head));
        } else if (base && strcmp (base->id, head->id) == 0) {
            seaf_debug ("%s%s: unchanged in head, changed in remote\n",
                        basedir, head->name);

            *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(remote));
        } else if (base && strcmp (base->id, remote->id) == 0) {
            seaf_debug ("%s%s: unchanged in remote, changed in head\n",
                        basedir, head->name);

            *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(head));
        } else {
            /* File content conflict. */

            seaf_debug ("%s%s: files conflict\n", basedir, head->name);

            conflict_name = merge_conflict_filename(store_id, version,
                                                    opt,
                                                    basedir,
                                                    head->name);
            if (!conflict_name)
                return -1;

            /* Change remote entry name in place. So opt->callback
             * will see the conflict name, not the original name.
             */
            g_free (remote->name);
            remote->name = conflict_name;
            remote->name_len = strlen (remote->name);

            *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(head));
            *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(remote));

            opt->conflict = TRUE;
        }
    } else if (base && !head && remote) {
        if (strcmp (base->id, remote->id) != 0) {
            if (dents[1] != NULL) {
                /* D/F conflict:
                 * Head replaces file with dir, while remote change the file.
                 */
                seaf_debug ("%s%s: DFC, file -> dir, file\n",
                            basedir, remote->name);

                conflict_name = merge_conflict_filename(store_id, version,
                                                        opt,
                                                        basedir,
                                                        remote->name);
                if (!conflict_name)
                    return -1;

                /* Change the name of remote, keep dir name in head unchanged. 
                 */
                g_free (remote->name);
                remote->name = conflict_name;
                remote->name_len = strlen (remote->name);

                *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(remote));

                opt->conflict = TRUE;
            } else {
                /* Deleted in head and changed in remote. */

                seaf_debug ("%s%s: deleted in head and changed in remote\n",
                            basedir, remote->name);

                /* Keep version of remote. */
                *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(remote));
            }
        } else {
            /* If base and remote match, the file should not be added to
             * the merge result.
             */
            seaf_debug ("%s%s: file deleted in head, unchanged in remote\n",
                        basedir, remote->name);
        }
    } else if (base && head && !remote) {
        if (strcmp (base->id, head->id) != 0) {
            if (dents[2] != NULL) {
                /* D/F conflict:
                 * Remote replaces file with dir, while head change the file.
                 */
                seaf_debug ("%s%s: DFC, file -> file, dir\n",
                            basedir, head->name);

                /* We use remote head commit author name as conflict
                 * suffix of a dir.
                 */
                conflict_name = merge_conflict_dirname (store_id, version,
                                                        opt,
                                                        basedir, dents[2]->name);
                if (!conflict_name)
                    return -1;

                /* Change remote dir name to conflict name in place. */
                g_free (dents[2]->name);
                dents[2]->name = conflict_name;
                dents[2]->name_len = strlen (dents[2]->name);

                *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(head));

                opt->conflict = TRUE;
            } else {
                /* Deleted in remote and changed in head. */

                seaf_debug ("%s%s: deleted in remote and changed in head\n",
                            basedir, head->name);

                /* Keep version of remote. */
                *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(head));
            }
        } else {
            /* If base and head match, the file should not be added to
             * the merge result.
             */
            seaf_debug ("%s%s: file deleted in remote, unchanged in head\n",
                        basedir, head->name);
        }
    } else if (!base && !head && remote) {
        if (!dents[1]) {
            /* Added in remote. */
            seaf_debug ("%s%s: added in remote\n", basedir, remote->name);

            *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(remote));
        } else if (dents[0] != NULL && strcmp(dents[0]->id, dents[1]->id) == 0) {
            /* Contents in the dir is not changed.
             * The dir will be deleted in merge_directories().
             */
            seaf_debug ("%s%s: dir in head will be replaced by file in remote\n",
                        basedir, remote->name);

            *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(remote));
        } else {
            /* D/F conflict:
             * Contents of the dir is changed in head, while
             * remote replace the dir with a file.
             *
             * Or, head adds a new dir, while remote adds a new file,
             * with the same name.
             */

            seaf_debug ("%s%s: DFC, dir -> dir, file\n", basedir, remote->name);

            conflict_name = merge_conflict_filename(store_id, version,
                                                    opt,
                                                    basedir,
                                                    remote->name);
            if (!conflict_name)
                return -1;

            g_free (remote->name);
            remote->name = conflict_name;
            remote->name_len = strlen (remote->name);

            *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(remote));

            opt->conflict = TRUE;
        }
    } else if (!base && head && !remote) {
        if (!dents[2]) {
            /* Added in remote. */
            seaf_debug ("%s%s: added in head\n", basedir, head->name);

            *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(head));
        } else if (dents[0] != NULL && strcmp(dents[0]->id, dents[2]->id) == 0) {
            /* Contents in the dir is not changed.
             * The dir will be deleted in merge_directories().
             */
            seaf_debug ("%s%s: dir in remote will be replaced by file in head\n",
                        basedir, head->name);

            *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(head));
        } else {
            /* D/F conflict:
             * Contents of the dir is changed in remote, while
             * head replace the dir with a file.
             *
             * Or, remote adds a new dir, while head adds a new file,
             * with the same name.
             */

            seaf_debug ("%s%s: DFC, dir -> file, dir\n", basedir, head->name);

            conflict_name = merge_conflict_dirname (store_id, version,
                                                    opt,
                                                    basedir, dents[2]->name);
            if (!conflict_name)
                return -1;

            g_free (dents[2]->name);
            dents[2]->name = conflict_name;
            dents[2]->name_len = strlen (dents[2]->name);

            *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(head));

            opt->conflict = TRUE;
        }
    } else if (base && !head && !remote) {
        /* Don't need to add anything to dents_out. */
        seaf_debug ("%s%s: deleted in head and remote\n", basedir, base->name);
    }

    return 0;
}

static int
merge_entries (const char *store_id, int version,
               int n, SeafDirent *dents[],
               const char *basedir,
               GList **dents_out,
               MergeOptions *opt)
{
    /* If we're running 2-way merge, it means merge files base on head and remote.
     */
    if (n == 2)
        return twoway_merge (store_id, version, basedir, dents, dents_out, opt);

    /* Otherwise, we're doing a real 3-way merge of the trees.
     * It means merge files and handle any conflicts.
     */

    return threeway_merge (store_id, version, dents, basedir, dents_out, opt);
}

static int
merge_directories (const char *store_id, int version,
                   int n, SeafDirent *dents[],
                   const char *basedir,
                   GList **dents_out,
                   MergeOptions *opt)
{
    SeafDir *dir;
    SeafDir *sub_dirs[3];
    char *dirname = NULL;
    char *new_basedir;
    int ret = 0;
    int dir_mask = 0, i;
    SeafDirent *merged_dent;

    for (i = 0; i < n; ++i) {
        if (dents[i] && S_ISDIR(dents[i]->mode))
            dir_mask |= 1 << i;
    }

    seaf_debug ("dir_mask = %d\n", dir_mask);

    if (n == 3) {
        switch (dir_mask) {
        case 0:
            g_return_val_if_reached (-1);
        case 1:
            /* head and remote are not dirs, nothing to merge. */
            seaf_debug ("%s%s: no dir, no need to merge\n", basedir, dents[0]->name);
            return 0;
        case 2:
            /* only head is dir, add to result directly, no need to merge. */
            seaf_debug ("%s%s: only head is dir\n", basedir, dents[1]->name);
            *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(dents[1]));
            return 0;
        case 3:
            if (strcmp (dents[0]->id, dents[1]->id) == 0) {
                /* Base and head are the same, but deleted in remote. */
                seaf_debug ("%s%s: dir deleted in remote\n", basedir, dents[0]->name);
                return 0;
            }
            seaf_debug ("%s%s: dir changed in head but deleted in remote\n",
                        basedir, dents[1]->name);
            break;
        case 4:
            /* only remote is dir, add to result directly, no need to merge. */
            seaf_debug ("%s%s: only remote is dir\n", basedir, dents[2]->name);
            *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(dents[2]));
            return 0;
        case 5:
            if (strcmp (dents[0]->id, dents[2]->id) == 0) {
                /* Base and remote are the same, but deleted in head. */
                seaf_debug ("%s%s: dir deleted in head\n", basedir, dents[0]->name);
                return 0;
            }
            seaf_debug ("%s%s: dir changed in remote but deleted in head\n",
                        basedir, dents[2]->name);
            break;
        case 6:
        case 7:
            if (strcmp (dents[1]->id, dents[2]->id) == 0) {
                /* Head and remote match. */
                seaf_debug ("%s%s: dir is the same in head and remote\n",
                            basedir, dents[1]->name);
                *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(dents[1]));
                return 0;
            } else if (dents[0] && strcmp(dents[0]->id, dents[1]->id) == 0) {
                seaf_debug ("%s%s: dir changed in remote but unchanged in head\n",
                            basedir, dents[1]->name);
                *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(dents[2]));
                return 0;
            } else if (dents[0] && strcmp(dents[0]->id, dents[2]->id) == 0) {
                seaf_debug ("%s%s: dir changed in head but unchanged in remote\n",
                            basedir, dents[1]->name);
                *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(dents[1]));
                return 0;
            }

            seaf_debug ("%s%s: dir is changed in both head and remote, "
                        "merge recursively\n", basedir, dents[1]->name);
            break;
        default:
            g_return_val_if_reached (-1);
        }
    } else if (n == 2) {
        switch (dir_mask) {
        case 0:
            g_return_val_if_reached (-1);
        case 1:
            /*head is dir, remote is not dir*/
            seaf_debug ("%s%s: only head is dir\n", basedir, dents[0]->name);
            *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(dents[0]));
            return 0;
        case 2:
            /*head is not dir, remote is dir*/
            seaf_debug ("%s%s: only remote is dir\n", basedir, dents[1]->name);
            *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(dents[1]));
            return 0;
        case 3:
            if (strcmp (dents[0]->id, dents[1]->id) == 0) {
                seaf_debug ("%s%s: dir is the same in head and remote\n",
                            basedir, dents[0]->name);
                *dents_out = g_list_prepend (*dents_out, seaf_dirent_dup(dents[1]));
                return 0;
            }
            seaf_debug ("%s%s: dir is changed in head and remote, merge recursively\n",
                        basedir, dents[0]->name);
            break;
        default:
            g_return_val_if_reached (-1);
        }
    }

    memset (sub_dirs, 0, sizeof(sub_dirs[0])*n);
    for (i = 0; i < n; ++i) {
        if (dents[i] != NULL && S_ISDIR(dents[i]->mode)) {
            dir = seaf_fs_manager_get_seafdir (seaf->fs_mgr,
                                               store_id, version,
                                               dents[i]->id);
            if (!dir) {
                seaf_warning ("Failed to find dir %s:%s.\n", store_id, dents[i]->id);
                ret = -1;
                goto free_sub_dirs;
            }
            opt->visit_dirs++;
            sub_dirs[i] = dir;

            dirname = dents[i]->name;
        }
    }

    new_basedir = g_strconcat (basedir, dirname, "/", NULL);

    ret = merge_trees_recursive (store_id, version, n, sub_dirs, new_basedir, opt);

    g_free (new_basedir);

    if (n == 3) {
        if (dir_mask == 3 || dir_mask == 6 || dir_mask == 7) {
            merged_dent = seaf_dirent_dup (dents[1]);
            memcpy (merged_dent->id, opt->merged_tree_root, 40);
            *dents_out = g_list_prepend (*dents_out, merged_dent);
        } else if (dir_mask == 5) {
            merged_dent = seaf_dirent_dup (dents[2]);
            memcpy (merged_dent->id, opt->merged_tree_root, 40);
            *dents_out = g_list_prepend (*dents_out, merged_dent);
        }
    } else if (n == 2) {
        if (dir_mask == 3) {
            merged_dent = seaf_dirent_dup (dents[1]);
            memcpy (merged_dent->id, opt->merged_tree_root, 40);
            *dents_out = g_list_prepend (*dents_out, merged_dent);
        }
    }

free_sub_dirs:
    for (i = 0; i < n; ++i)
        seaf_dir_free (sub_dirs[i]);

    return ret;
}

static gint
compare_dirents (gconstpointer a, gconstpointer b)
{
    const SeafDirent *denta = a, *dentb = b;

    return strcmp (dentb->name, denta->name);
}

static int
merge_trees_recursive (const char *store_id, int version,
                       int n, SeafDir *trees[],
                       const char *basedir,
                       MergeOptions *opt)
{
    GList *ptrs[3];
    SeafDirent *dents[3];
    int i;
    SeafDirent *dent;
    char *first_name;
    gboolean done;
    int ret = 0;
    SeafDir *merged_tree;
    GList *merged_dents = NULL;

    for (i = 0; i < n; ++i) {
        if (trees[i])
            ptrs[i] = trees[i]->entries;
        else
            ptrs[i] = NULL;
    }

    while (1) {
        first_name = NULL;
        memset (dents, 0, sizeof(dents[0])*n);
        done = TRUE;

        /* Find the "largest" name, assuming dirents are sorted. */
        for (i = 0; i < n; ++i) {
            if (ptrs[i] != NULL) {
                done = FALSE;
                dent = ptrs[i]->data;
                if (!first_name)
                    first_name = dent->name;
                else if (strcmp(dent->name, first_name) > 0)
                    first_name = dent->name;
            }
        }

        if (done)
            break;

        /*
         * Setup dir entries for all names that equal to first_name
         */
        int n_files = 0, n_dirs = 0;
        for (i = 0; i < n; ++i) {
            if (ptrs[i] != NULL) {
                dent = ptrs[i]->data;
                if (strcmp(first_name, dent->name) == 0) {
                    if (S_ISREG(dent->mode))
                        ++n_files;
                    else if (S_ISDIR(dent->mode))
                        ++n_dirs;

                    dents[i] = dent;
                    ptrs[i] = ptrs[i]->next;
                }
            }
        }

        /* Merge entries of this level. */
        if (n_files > 0) {
            ret = merge_entries (store_id, version,
                                 n, dents, basedir, &merged_dents, opt);
            if (ret < 0)
                return ret;
        }

        /* Recurse into sub level. */
        if (n_dirs > 0) {
            ret = merge_directories (store_id, version,
                                     n, dents, basedir, &merged_dents, opt);
            if (ret < 0)
                return ret;
        }
    }

    if (n == 3) {
        merged_dents = g_list_sort (merged_dents, compare_dirents);
        merged_tree = seaf_dir_new (NULL, merged_dents,
                                    dir_version_from_repo_version(version));

        memcpy (opt->merged_tree_root, merged_tree->dir_id, 40);

        if ((trees[1] && strcmp (trees[1]->dir_id, merged_tree->dir_id) == 0) ||
            (trees[2] && strcmp (trees[2]->dir_id, merged_tree->dir_id) == 0)) {
            seaf_dir_free (merged_tree);
        } else {
            ret = seaf_dir_save (seaf->fs_mgr, store_id, version, merged_tree);
            seaf_dir_free (merged_tree);
            if (ret < 0) {
                seaf_warning ("Failed to save merged tree %s:%s.\n", store_id, basedir);
            }
        }
    } else if (n == 2) {
        merged_dents = g_list_sort (merged_dents, compare_dirents);
        merged_tree = seaf_dir_new (NULL, merged_dents,
                                    dir_version_from_repo_version(version));

        memcpy (opt->merged_tree_root, merged_tree->dir_id, 40);

        if ((trees[0] && strcmp (trees[0]->dir_id, merged_tree->dir_id) == 0) || 
            (trees[1] && strcmp (trees[1]->dir_id, merged_tree->dir_id) == 0)) {
            seaf_dir_free (merged_tree);
        } else {
            ret = seaf_dir_save (seaf->fs_mgr, store_id, version, merged_tree);
            seaf_dir_free (merged_tree);
            if (ret < 0) {
                seaf_warning ("Failed to save merged tree %s:%s.\n", store_id, basedir);
            }
        }
    }

    return ret;
}

int
seaf_merge_trees (const char *store_id, int version,
                  int n, const char *roots[], MergeOptions *opt)
{
    SeafDir **trees, *root;
    int i, ret;

    g_return_val_if_fail (n == 2 || n == 3, -1);

    opt->email_to_nickname = g_hash_table_new_full(g_str_hash,
                                                   g_str_equal,
                                                   g_free,
                                                   g_free);

    trees = g_new0 (SeafDir *, n);
    for (i = 0; i < n; ++i) {
        root = seaf_fs_manager_get_seafdir (seaf->fs_mgr, store_id, version, roots[i]);
        if (!root) {
            seaf_warning ("Failed to find dir %s:%s.\n", store_id, roots[i]);
            g_free (trees);
            return -1;
        }
        trees[i] = root;
    }

    ret = merge_trees_recursive (store_id, version, n, trees, "", opt);

    for (i = 0; i < n; ++i)
        seaf_dir_free (trees[i]);
    g_free (trees);

    g_hash_table_destroy (opt->email_to_nickname);

    return ret;
}
