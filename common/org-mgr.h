/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef _ORG_MGR_H_
#define _ORG_MGR_H_

typedef struct _SeafileSession SeafileSession;
typedef struct _CcnetOrgManager CcnetOrgManager;
typedef struct _CcnetOrgManagerPriv CcnetOrgManagerPriv;

struct _CcnetOrgManager
{
    SeafileSession	*session;

    CcnetOrgManagerPriv	*priv;
};

CcnetOrgManager* ccnet_org_manager_new (SeafileSession *session);

int
ccnet_org_manager_prepare (CcnetOrgManager *manager);

void
ccnet_org_manager_start (CcnetOrgManager *manager);

int
ccnet_org_manager_create_org (CcnetOrgManager *mgr,
                              const char *org_name,
                              const char *url_prefix,
                              const char *creator,
                              GError **error);

int
ccnet_org_manager_remove_org (CcnetOrgManager *mgr,
                              int org_id,
                              GError **error);

GList *
ccnet_org_manager_get_all_orgs (CcnetOrgManager *mgr,
                                int start,
                                int limit);

int
ccnet_org_manager_count_orgs (CcnetOrgManager *mgr);

CcnetOrganization *
ccnet_org_manager_get_org_by_url_prefix (CcnetOrgManager *mgr,
                                         const char *url_prefix,
                                         GError **error);

CcnetOrganization *
ccnet_org_manager_get_org_by_id (CcnetOrgManager *mgr,
                                 int org_id,
                                 GError **error);

int
ccnet_org_manager_add_org_user (CcnetOrgManager *mgr,
                                int org_id,
                                const char *email,
                                int is_staff,
                                GError **error);

int
ccnet_org_manager_remove_org_user (CcnetOrgManager *mgr,
                                   int org_id,
                                   const char *email,
                                   GError **error);

GList *
ccnet_org_manager_get_orgs_by_user (CcnetOrgManager *mgr,
                                   const char *email,
                                   GError **error);

GList *
ccnet_org_manager_get_org_emailusers (CcnetOrgManager *mgr,
                                      const char *url_prefix,
                                      int start, int limit);

int
ccnet_org_manager_add_org_group (CcnetOrgManager *mgr,
                                 int org_id,
                                 int group_id,
                                 GError **error);
int
ccnet_org_manager_remove_org_group (CcnetOrgManager *mgr,
                                    int org_id,
                                    int group_id,
                                    GError **error);

int
ccnet_org_manager_is_org_group (CcnetOrgManager *mgr,
                                int group_id,
                                GError **error);

int
ccnet_org_manager_get_org_id_by_group (CcnetOrgManager *mgr,
                                       int group_id,
                                       GError **error);

GList *
ccnet_org_manager_get_org_group_ids (CcnetOrgManager *mgr,
                                     int org_id,
                                     int start,
                                     int limit);

GList *
ccnet_org_manager_get_org_groups (CcnetOrgManager *mgr,
                                  int org_id,
                                  int start,
                                  int limit);

GList *
ccnet_org_manager_get_org_groups_by_user (CcnetOrgManager *mgr,
                                          const char *user,
                                          int org_id);

GList *
ccnet_org_manager_get_org_top_groups (CcnetOrgManager *mgr, int org_id, GError **error);

int
ccnet_org_manager_org_user_exists (CcnetOrgManager *mgr,
                                   int org_id,
                                   const char *email,
                                   GError **error);

char *
ccnet_org_manager_get_url_prefix_by_org_id (CcnetOrgManager *mgr,
                                            int org_id,
                                            GError **error);

int
ccnet_org_manager_is_org_staff (CcnetOrgManager *mgr,
                                int org_id,
                                const char *email,
                                GError **error);

int
ccnet_org_manager_set_org_staff (CcnetOrgManager *mgr,
                                 int org_id,
                                 const char *email,
                                 GError **error);

int
ccnet_org_manager_unset_org_staff (CcnetOrgManager *mgr,
                                   int org_id,
                                   const char *email,
                                   GError **error);

int
ccnet_org_manager_set_org_name(CcnetOrgManager *mgr,
                               int org_id,
                               const char *org_name,
                               GError **error);


#endif /* _ORG_MGR_H_ */
