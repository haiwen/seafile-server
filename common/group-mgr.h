/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef GROUP_MGR_H
#define GROUP_MGR_H

/* #define MAX_GROUP_MEMBERS	16 */

typedef struct _SeafileSession SeafileSession;
typedef struct _CcnetGroupManager CcnetGroupManager;
typedef struct _CcnetGroupManagerPriv CcnetGroupManagerPriv;

struct _CcnetGroupManager
{
    SeafileSession *session;
    
    CcnetGroupManagerPriv	*priv;
};

CcnetGroupManager* ccnet_group_manager_new (SeafileSession *session);

int
ccnet_group_manager_prepare (CcnetGroupManager *manager);

void ccnet_group_manager_start (CcnetGroupManager *manager);

int ccnet_group_manager_create_group (CcnetGroupManager *mgr,
                                      const char *group_name,
                                      const char *user_name,
                                      int parent_group_id,
                                      GError **error);

int ccnet_group_manager_create_org_group (CcnetGroupManager *mgr,
                                          int org_id,
                                          const char *group_name,
                                          const char *user_name,
                                          int parent_group_id,
                                          GError **error);

int ccnet_group_manager_remove_group (CcnetGroupManager *mgr,
                                      int group_id,
                                      gboolean remove_anyway,
                                      GError **error);

int ccnet_group_manager_add_member (CcnetGroupManager *mgr,
                                    int group_id,
                                    const char *user_name,
                                    const char *member_name,
                                    GError **error);

int ccnet_group_manager_remove_member (CcnetGroupManager *mgr,
                                       int group_id,
                                       const char *user_name,
                                       const char *member_name,
                                       GError **error);

int ccnet_group_manager_set_admin (CcnetGroupManager *mgr,
                                   int group_id,
                                   const char *member_name,
                                   GError **error);

int ccnet_group_manager_unset_admin (CcnetGroupManager *mgr,
                                     int group_id,
                                     const char *member_name,
                                     GError **error);

int ccnet_group_manager_set_group_name (CcnetGroupManager *mgr,
                                        int group_id,
                                        const char *group_name,
                                        GError **error);

int ccnet_group_manager_quit_group (CcnetGroupManager *mgr,
                                    int group_id,
                                    const char *user_name,
                                    GError **error);

GList *
ccnet_group_manager_get_groups_by_user (CcnetGroupManager *mgr,
                                        const char *user_name,
                                        gboolean return_ancestors,
                                        GError **error);

CcnetGroup *
ccnet_group_manager_get_group (CcnetGroupManager *mgr, int group_id,
                               GError **error);

GList *
ccnet_group_manager_get_group_members (CcnetGroupManager *mgr, int group_id,
                                       GError **error);

GList *
ccnet_group_manager_get_members_with_prefix (CcnetGroupManager *mgr,
                                             int group_id,
                                             const char *prefix,
                                             GError **error);

int
ccnet_group_manager_check_group_staff (CcnetGroupManager *mgr,
                                       int group_id,
                                       const char *user_name,
                                       int in_structure);

int
ccnet_group_manager_remove_group_user (CcnetGroupManager *mgr,
                                       const char *user);

int
ccnet_group_manager_is_group_user (CcnetGroupManager *mgr,
                                   int group_id,
                                   const char *user,
                                   gboolean in_structure);

GList*
ccnet_group_manager_list_all_departments (CcnetGroupManager *mgr,
                                          GError **error);

GList*
ccnet_group_manager_get_all_groups (CcnetGroupManager *mgr,
                                    int start, int limit, GError **error);

int
ccnet_group_manager_set_group_creator (CcnetGroupManager *mgr,
                                       int group_id,
                                       const char *user_name);

GList*
ccnet_group_manager_search_groups (CcnetGroupManager *mgr,
                                   const char *keyword,
                                   int start, int limit);

GList *
ccnet_group_manager_get_top_groups (CcnetGroupManager *mgr, gboolean including_org, GError **error);

GList *
ccnet_group_manager_get_child_groups (CcnetGroupManager *mgr, int group_id,
                                      GError **error);

GList *
ccnet_group_manager_get_descendants_groups (CcnetGroupManager *mgr, int group_id,
                                            GError **error);

GList *
ccnet_group_manager_get_ancestor_groups (CcnetGroupManager *mgr, int group_id);

GList *
ccnet_group_manager_get_groups_members (CcnetGroupManager *mgr, const char *group_ids,
                                        GError **error);

int
ccnet_group_manager_update_group_user (CcnetGroupManager *mgr,
                                       const char *old_email,
                                       const char *new_email);
#endif /* GROUP_MGR_H */

