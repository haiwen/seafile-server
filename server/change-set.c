/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "seafile-session.h"

#include "utils.h"
#include "log.h"

#include "change-set.h"

struct _ChangeSetDir {
    int version;
    char dir_id[41];
    /* A hash table of dirents for fast lookup and insertion. */
    GHashTable *dents;

};
typedef struct _ChangeSetDir ChangeSetDir;

struct _ChangeSetDirent {
    guint32 mode;
    char id[41];
    char *name;
    gint64 mtime;
    char *modifier;
    gint64 size;
    /* Only used for directory. Most of time this is NULL
     * unless we change the subdir too.
     */
    ChangeSetDir *subdir;
};
typedef struct _ChangeSetDirent ChangeSetDirent;

/* Change set dirent. */

static ChangeSetDirent *
changeset_dirent_new (const char *id, guint32 mode, const char *name,
                      gint64 mtime, const char *modifier, gint64 size)
{
    ChangeSetDirent *dent = g_new0 (ChangeSetDirent, 1);

    dent->mode = mode;
    memcpy (dent->id, id, 40);
    dent->name = g_strdup(name);
    dent->mtime = mtime;
    dent->modifier = g_strdup(modifier);
    dent->size = size;

    return dent;    
}

static ChangeSetDirent *
seaf_dirent_to_changeset_dirent (SeafDirent *seaf_dent)
{
    return changeset_dirent_new (seaf_dent->id, seaf_dent->mode, seaf_dent->name,
                                 seaf_dent->mtime, seaf_dent->modifier, seaf_dent->size);
}

static SeafDirent *
changeset_dirent_to_seaf_dirent (int version, ChangeSetDirent *dent)
{
    return seaf_dirent_new (version, dent->id, dent->mode, dent->name,
                            dent->mtime, dent->modifier, dent->size);
}

static void
changeset_dir_free (ChangeSetDir *dir);

static void
changeset_dirent_free (ChangeSetDirent *dent)
{
    if (!dent)
        return;

    g_free (dent->name);
    g_free (dent->modifier);
    /* Recursively free subdir. */
    if (dent->subdir)
        changeset_dir_free (dent->subdir);
    g_free (dent);
}

/* Change set dir. */

static void
add_dent_to_dir (ChangeSetDir *dir, ChangeSetDirent *dent)
{
    g_hash_table_insert (dir->dents,
                         g_strdup(dent->name),
                         dent);
}

static void
remove_dent_from_dir (ChangeSetDir *dir, const char *dname)
{
    char *key;

    if (g_hash_table_lookup_extended (dir->dents, dname,
                                      (gpointer*)&key, NULL)) {
        g_hash_table_steal (dir->dents, dname);
        g_free (key);
    }
}

static ChangeSetDir *
changeset_dir_new (int version, const char *id, GList *dirents)
{
    ChangeSetDir *dir = g_new0 (ChangeSetDir, 1);
    GList *ptr;
    SeafDirent *dent;
    ChangeSetDirent *changeset_dent;

    dir->version = version;
    if (id)
        memcpy (dir->dir_id, id, 40);
    dir->dents = g_hash_table_new_full (g_str_hash, g_str_equal,
                                        g_free, (GDestroyNotify)changeset_dirent_free);
    for (ptr = dirents; ptr; ptr = ptr->next) {
        dent = ptr->data;
        changeset_dent = seaf_dirent_to_changeset_dirent(dent);
        add_dent_to_dir (dir, changeset_dent);
    }

    return dir;
} 

static void
changeset_dir_free (ChangeSetDir *dir)
{
    if (!dir)
        return;
    g_hash_table_destroy (dir->dents);
    g_free (dir);
}

static ChangeSetDir *
seaf_dir_to_changeset_dir (SeafDir *seaf_dir)
{
    return changeset_dir_new (seaf_dir->version, seaf_dir->dir_id, seaf_dir->entries);
}

static gint
compare_dents (gconstpointer a, gconstpointer b)
{
    const SeafDirent *denta = a, *dentb = b;

    return strcmp(dentb->name, denta->name);
}

static SeafDir *
changeset_dir_to_seaf_dir (ChangeSetDir *dir)
{
    GList *dents = NULL, *seaf_dents = NULL;
    GList *ptr;
    ChangeSetDirent *dent;
    SeafDirent *seaf_dent;
    SeafDir *seaf_dir;

    dents = g_hash_table_get_values (dir->dents);
    for (ptr = dents; ptr; ptr = ptr->next) {
        dent = ptr->data;
        seaf_dent = changeset_dirent_to_seaf_dirent (dir->version, dent);
        seaf_dents = g_list_prepend (seaf_dents, seaf_dent);
    }
    /* Sort it in descending order. */
    seaf_dents = g_list_sort (seaf_dents, compare_dents);

    /* seaf_dir_new() computes the dir id. */
    seaf_dir = seaf_dir_new (NULL, seaf_dents, dir->version);

    g_list_free (dents);
    return seaf_dir;
}

/* Change set. */

ChangeSet *
changeset_new (const char *repo_id, SeafDir *dir)
{
    ChangeSetDir *changeset_dir = NULL;
    ChangeSet *changeset = NULL;

    changeset_dir = seaf_dir_to_changeset_dir (dir);
    if (!changeset_dir)
        goto out;

    changeset = g_new0 (ChangeSet, 1);
    memcpy (changeset->repo_id, repo_id, 36);
    changeset->tree_root = changeset_dir;

out:
    return changeset;
}

void
changeset_free (ChangeSet *changeset)
{
    if (!changeset)
        return;

    changeset_dir_free (changeset->tree_root);
    g_free (changeset);
}

static ChangeSetDirent *
delete_from_tree (ChangeSet *changeset,
                  const char *path,
                  gboolean *parent_empty)
{
    char *repo_id = changeset->repo_id;
    ChangeSetDir *root = changeset->tree_root;
    char **parts, *dname;
    int n, i;
    ChangeSetDir *dir;
    ChangeSetDirent *dent, *ret = NULL;
    ChangeSetDirent *parent_dent = NULL;
    SeafDir *seaf_dir;

    *parent_empty = FALSE;

    parts = g_strsplit (path, "/", 0);
    n = g_strv_length(parts);
    dir = root;
    for (i = 0; i < n; i++) {
        dname = parts[i];

        dent = g_hash_table_lookup (dir->dents, dname);
        if (!dent)
            break;

        if (S_ISDIR(dent->mode)) {
            if (i == (n-1)) {
                /* Remove from hash table without freeing dent. */
                remove_dent_from_dir (dir, dname);
                if (g_hash_table_size (dir->dents) == 0)
                    *parent_empty = TRUE;
                ret = dent;
                // update parent dir mtime when delete dirs locally.
                if (parent_dent) {
                    parent_dent->mtime = time (NULL);
                }
                break;
            }

            if (!dent->subdir) {
                seaf_dir = seaf_fs_manager_get_seafdir(seaf->fs_mgr,
                                                       repo_id,
                                                       root->version,
                                                       dent->id);
                if (!seaf_dir) {
                    seaf_warning ("Failed to load seafdir %s:%s\n",
                                  repo_id, dent->id);
                    break;
                }
                dent->subdir = seaf_dir_to_changeset_dir (seaf_dir);
                seaf_dir_free (seaf_dir);
            }
            dir = dent->subdir;
            parent_dent = dent;
        } else if (S_ISREG(dent->mode)) {
            if (i == (n-1)) {
                /* Remove from hash table without freeing dent. */
                remove_dent_from_dir (dir, dname);
                if (g_hash_table_size (dir->dents) == 0)
                    *parent_empty = TRUE;
                ret = dent;
                // update parent dir mtime when delete files locally.
                if (parent_dent) {
                    parent_dent->mtime = time (NULL);
                }
                break;
            }
        }
    }

    g_strfreev (parts);
    return ret;
}

static void
remove_from_changeset_recursive (ChangeSet *changeset,
                                 const char *path,
                                 gboolean remove_parent,
                                 const char *top_dir,
                                 int *mode)
{
    ChangeSetDirent *dent;
    gboolean parent_empty = FALSE;

    dent = delete_from_tree (changeset, path, &parent_empty);
    if (mode && dent)
        *mode = dent->mode;
    changeset_dirent_free (dent);

    if (remove_parent && parent_empty) {
        char *parent = g_strdup(path);
        char *slash = strrchr (parent, '/');
        if (slash) {
            *slash = '\0';
            if (strlen(parent) >= strlen(top_dir)) {
                /* Recursively remove parent dirs. */
                remove_from_changeset_recursive (changeset,
                                                 parent,
                                                 remove_parent,
                                                 top_dir,
                                                 mode);
            }
        }
        g_free (parent);
    }
}

void
remove_from_changeset (ChangeSet *changeset,
                       const char *path,
                       gboolean remove_parent,
                       const char *top_dir,
                       int *mode)
{
    remove_from_changeset_recursive (changeset, path, remove_parent, top_dir, mode);
}

static char *
commit_tree_recursive (const char *repo_id, ChangeSetDir *dir)
{
    ChangeSetDirent *dent;
    GHashTableIter iter;
    gpointer key, value;
    char *new_id;
    SeafDir *seaf_dir;
    char *ret = NULL;

    g_hash_table_iter_init (&iter, dir->dents);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        dent = value;
        if (dent->subdir) {
            new_id = commit_tree_recursive (repo_id, dent->subdir);
            if (!new_id)
                return NULL;

            memcpy (dent->id, new_id, 40);
            g_free (new_id);
        }
    }

    seaf_dir = changeset_dir_to_seaf_dir (dir);

    memcpy (dir->dir_id, seaf_dir->dir_id, 40);

    if (!seaf_fs_manager_object_exists (seaf->fs_mgr,
                                        repo_id, dir->version,
                                        seaf_dir->dir_id)) {
        if (seaf_dir_save (seaf->fs_mgr, repo_id, dir->version, seaf_dir) < 0) {
            seaf_warning ("Failed to save dir object %s to repo %s.\n",
                          seaf_dir->dir_id, repo_id);
            goto out;
        }
    }

    ret = g_strdup(seaf_dir->dir_id);

out:
    seaf_dir_free (seaf_dir);
    return ret;
}

/*
 * This function does two things:
 * - calculate dir id from bottom up;
 * - create and save seaf dir objects.
 * It returns root dir id of the new commit.
 */
char *
commit_tree_from_changeset (ChangeSet *changeset)
{
    char *root_id = commit_tree_recursive (changeset->repo_id,
                                           changeset->tree_root);

    return root_id;
}
