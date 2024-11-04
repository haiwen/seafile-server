#ifndef SEAFILE_SESSION_H
#define SEAFILE_SESSION_H

#include <stdint.h>
#include <glib.h>

#include <seaf-db.h>

#include "block-mgr.h"
#include "fs-mgr.h"
#include "branch-mgr.h"
#include "commit-mgr.h"
#include "repo-mgr.h"
#include "user-mgr.h"
#include "group-mgr.h"
#include "org-mgr.h"

typedef struct _SeafileSession SeafileSession;

struct _SeafileSession {
    char                *seaf_dir;
    char                *ccnet_dir;
    char                *tmp_file_dir;
    /* Config that's only loaded on start */
    GKeyFile            *config;
    SeafDB              *db;
    SeafDB              *ccnet_db;
    SeafDB              *seahub_db;

    SeafBlockManager    *block_mgr;
    SeafFSManager       *fs_mgr;
    SeafBranchManager   *branch_mgr;
    SeafCommitManager   *commit_mgr;
    SeafRepoManager     *repo_mgr;
    CcnetUserManager    *user_mgr;
    CcnetGroupManager   *group_mgr;
    CcnetOrgManager     *org_mgr;

    GHashTable          *excluded_users;

    gboolean create_tables;
    gboolean ccnet_create_tables;
};

extern SeafileSession *seaf;

SeafileSession *
seafile_session_new(const char *central_config_dir,
                    const char *seafile_dir,
                    const char *ccnet_dir);

int
seafile_session_init (SeafileSession *session);

int
seafile_session_start (SeafileSession *session);

#endif
