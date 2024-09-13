/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAF_CHANGE_SET_H
#define SEAF_CHANGE_SET_H

#include <glib.h>
#include "utils.h"

struct _ChangeSetDir;

struct _ChangeSet {
    char repo_id[37];
    /* A partial tree for all changed directories. */
    struct _ChangeSetDir *tree_root;
};
typedef struct _ChangeSet ChangeSet;

ChangeSet *
changeset_new (const char *repo_id, SeafDir *dir);

void
changeset_free (ChangeSet *changeset);

/*
  @remove_parent: remove the parent dir when it becomes empty.
*/
void
remove_from_changeset (ChangeSet *changeset,
                       const char *path,
                       gboolean remove_parent,
                       const char *top_dir,
                       int *mode);

char *
commit_tree_from_changeset (ChangeSet *changeset);

#endif
