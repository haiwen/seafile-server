/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_SESSION_H
#define SEAFILE_SESSION_H

#include <job-mgr.h>

#include "block-mgr.h"
#include "fs-mgr.h"
#include "commit-mgr.h"
#include "branch-mgr.h"
#include "repo-mgr.h"
#include "db.h"
#include "seaf-db.h"
#include "mq-mgr.h"
#include "user-mgr.h"
#include "group-mgr.h"
#include "org-mgr.h"

#include "share-mgr.h"
#include "web-accesstoken-mgr.h"
#include "passwd-mgr.h"
#include "quota-mgr.h"
#include "size-sched.h"
#include "copy-mgr.h"
#include "config-mgr.h"

#include "http-server.h"
#include "zip-download-mgr.h"
#include "index-blocks-mgr.h"
#include "notif-mgr.h"
#include "http-tx-mgr.h"
#include "obj-cache.h"
#include "metric-mgr.h"

#include <searpc-client.h>

struct _CcnetClient;

typedef struct _SeafileSession SeafileSession;


struct _SeafileSession {
    char                *central_config_dir;
    char                *seaf_dir;
    char                *ccnet_dir;
    char                *tmp_file_dir;
    /* Config that's only loaded on start */
    GKeyFile            *config;
    SeafDB              *db;
    CcnetDB             *ccnet_db;
    char                *seahub_pk;
    char                *seahub_url;
    ConnectionPool      *seahub_conn_pool;

    SeafBlockManager    *block_mgr;
    SeafFSManager       *fs_mgr;
    SeafCommitManager   *commit_mgr;
    SeafBranchManager   *branch_mgr;
    SeafRepoManager     *repo_mgr;
    SeafShareManager	*share_mgr;
    SeafPasswdManager   *passwd_mgr;
    SeafQuotaManager    *quota_mgr;
    SeafCopyManager     *copy_mgr;
    SeafCfgManager      *cfg_mgr;
    CcnetUserManager    *user_mgr;
    CcnetGroupManager   *group_mgr;
    CcnetOrgManager     *org_mgr;
    
    SeafWebAccessTokenManager	*web_at_mgr;

    SeafMqManager       *mq_mgr;
    CcnetJobManager     *job_mgr;

    SizeScheduler       *size_sched;

    int                  cloud_mode;

#ifdef HAVE_EVHTP
    HttpServerStruct    *http_server;
    ZipDownloadMgr      *zip_download_mgr;
#endif
    IndexBlksMgr        *index_blocks_mgr;

    gboolean create_tables;
    gboolean ccnet_create_tables;

    gboolean go_fileserver;

    int web_token_expire_time;
    int max_index_processing_threads;
    gint64 fixed_block_size;
    int max_indexing_threads;

    // For notification server
    NotifManager *notif_mgr;
    char         *notif_server_private_key;
    char         *notif_url;

    // For metric
    SeafMetricManager *metric_mgr; 

    ObjCache *obj_cache;

    gboolean            log_to_stdout;

    gboolean is_repair;
};

extern SeafileSession *seaf;

SeafileSession *
seafile_session_new(const char *central_config_dir, 
                    const char *seafile_dir,
                    const char *ccnet_dir);

SeafileSession *
seafile_repair_session_new(const char *central_config_dir,
                           const char *seafile_dir,
                           const char *ccnet_dir);

int
seafile_session_init (SeafileSession *session);

int
seafile_session_start (SeafileSession *session);

char *
seafile_session_get_tmp_file_path (SeafileSession *session,
                                   const char *basename,
                                   char path[]);

void
schedule_create_system_default_repo (SeafileSession *session);

char *
get_system_default_repo_id (SeafileSession *session);

int
set_system_default_repo_id (SeafileSession *session, const char *repo_id);

#endif /* SEAFILE_H */
