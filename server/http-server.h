#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <glib.h>

struct _SeafileSession;

struct _HttpServer;

struct _HttpServerStruct {
    struct _SeafileSession *seaf_session;

    struct _HttpServer *priv;
};

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

#endif
