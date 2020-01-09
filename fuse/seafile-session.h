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
#include "config-mgr.h"

typedef struct _SeafileSession SeafileSession;

struct _SeafileSession {
    char                *seaf_dir;
    char                *ccnet_dir;
    char                *tmp_file_dir;
    /* Config that's only loaded on start */
    GKeyFile            *config;
    SeafDB              *db;

    SeafBlockManager    *block_mgr;
    SeafFSManager       *fs_mgr;
    SeafBranchManager   *branch_mgr;
    SeafCommitManager   *commit_mgr;
    SeafRepoManager     *repo_mgr;
    SeafCfgManager      *cfg_mgr;

    GHashTable          *excluded_users;

    gboolean create_tables;
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
