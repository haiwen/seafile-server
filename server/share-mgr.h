/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SHARE_MGR_H
#define SHARE_MGR_H

#include <glib.h>

struct _SeafileSession;

typedef struct _SeafShareManager SeafShareManager;
typedef struct _SeafShareManagerPriv SeafShareManagerPriv;
typedef struct _ShareRepoInfo ShareRepoInfo;

struct _SeafShareManager {
    struct _SeafileSession *seaf;

};

SeafShareManager*
seaf_share_manager_new (struct _SeafileSession *seaf);

int
seaf_share_manager_start (SeafShareManager *mgr);

int
seaf_share_manager_add_share (SeafShareManager *mgr, const char *repo_id,
                              const char *from_email, const char *to_email,
                              const char *permission);

int
seaf_share_manager_set_subdir_perm_by_path (SeafShareManager *mgr, const char *repo_id,
                                            const char *from_email, const char *to_email,
                                            const char *permission, const char *path);

int
seaf_share_manager_set_permission (SeafShareManager *mgr, const char *repo_id,
                                   const char *from_email, const char *to_email,
                                   const char *permission);

GList*
seaf_share_manager_list_share_repos (SeafShareManager *mgr, const char *email,
                                     const char *type, int start, int limit);

GList *
seaf_share_manager_list_shared_to (SeafShareManager *mgr,
                                   const char *owner,
                                   const char *repo_id);

GList *
seaf_share_manager_list_repo_shared_to (SeafShareManager *mgr,
                                        const char *owner,
                                        const char *repo_id,
                                        GError **error);

GList *
seaf_share_manager_list_repo_shared_group (SeafShareManager *mgr,
                                           const char *from_email,
                                           const char *repo_id,
                                           GError **error);

int
seaf_share_manager_remove_share (SeafShareManager *mgr, const char *repo_id,
                                 const char *from_email, const char *to_email);

int
seaf_share_manager_unshare_subdir (SeafShareManager* mgr,
                                   const char *orig_repo_id,
                                   const char *path,
                                   const char *from_email,
                                   const char *to_email);


/* Remove all share info of a repo. */
int
seaf_share_manager_remove_repo (SeafShareManager *mgr, const char *repo_id);

char *
seaf_share_manager_check_permission (SeafShareManager *mgr,
                                     const char *repo_id,
                                     const char *email);

GHashTable *
seaf_share_manager_get_shared_sub_dirs (SeafShareManager *mgr,
                                        const char *repo_id,
                                        const char *path);

int
seaf_share_manager_is_repo_shared (SeafShareManager *mgr,
                                   const char *repo_id);

GObject *
seaf_get_shared_repo_by_path (SeafRepoManager *mgr,
                              const char *repo_id,
                              const char *path,
                              const char *shared_to,
                              int is_org,
                              GError **error);
int
seaf_share_manager_unshare_group_subdir (SeafShareManager* mgr,
                                         const char *repo_id,
                                         const char *path,
                                         const char *owner,
                                         int group_id);


GList *
seaf_share_manager_org_get_shared_users_by_repo (SeafShareManager* mgr,
                                                 int org_id,
                                                 const char *repo_id);

GList *
seaf_share_manager_get_shared_users_by_repo (SeafShareManager* mgr,
                                             const char *repo_id);
#endif /* SHARE_MGR_H */

