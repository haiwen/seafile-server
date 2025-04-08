#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#ifdef HAVE_EVHTP
#include <glib.h>

#include "metric-mgr.h"

struct _SeafileSession;

struct _HttpServer;

struct _HttpServerStruct {
    struct _SeafileSession *seaf_session;

    struct _HttpServer *priv;

    char *bind_addr;
    int bind_port;
    char *http_temp_dir;        /* temp dir for file upload */
    char *windows_encoding;
    int worker_threads;
    int cluster_shared_temp_file_mode;

    gboolean verify_client_blocks;
};

typedef struct RequestInfo {
    struct timeval start;
    char *url_path;
} RequestInfo;

typedef struct _HttpServerStruct HttpServerStruct;

HttpServerStruct *
seaf_http_server_new (struct _SeafileSession *session);

int
seaf_http_server_start (HttpServerStruct *htp_server);

int
seaf_http_server_invalidate_tokens (HttpServerStruct *htp_server,
                                    const GList *tokens);

void
send_statistic_msg (const char *repo_id, char *user, char *operation, guint64 bytes);

char *
get_client_ip_addr (void *data);

#endif

#endif
