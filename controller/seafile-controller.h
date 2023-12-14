/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * Seafile-controller is responsible for:
 *
 *    1. Start: start server processes:
 *
 *       - ccnet-server
 *       - seaf-server
 *       - seaf-mon
 *
 *    2. Repair:
 *
 *       - ensure ccnet process availability by watching client->connfd
 *       - ensure server processes availablity by checking process is running periodically
 *         If some process has stopped working, try to restart it.
 *
 */

#ifndef SEAFILE_CONTROLLER_H
#define SEAFILE_CONTROLLER_H

typedef struct _SeafileController SeafileController;

enum {
    PID_CCNET = 0,
    PID_SERVER,
    PID_FILESERVER,
    PID_SEAFDAV,
    PID_SEAFEVENTS,
    N_PID
};

typedef struct SeafDavConfig {
    gboolean enabled;
    int port;
    char *host;
    gboolean debug_mode;

} SeafDavConfig;

struct _SeafileController {
    char *central_config_dir;
    char *config_dir;
    char *seafile_dir;
    char *rpc_pipe_path;
    char *logdir;

    guint               check_process_timer;
    guint               client_io_id;
    /* Decide whether to start seaf-server in cloud mode  */
    gboolean            cloud_mode;

    int                 pid[N_PID];
    char                *pidfile[N_PID];

    SeafDavConfig       seafdav_config;

    gboolean            has_seafevents;
};
#endif
