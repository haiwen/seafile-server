#ifndef HTTP_TX_MGR_H
#define HTTP_TX_MGR_H

#include <curl/curl.h>

#define HTTP_OK 200
#define HTTP_BAD_REQUEST 400
#define HTTP_FORBIDDEN 403
#define HTTP_NOT_FOUND 404
#define HTTP_NO_QUOTA 443
#define HTTP_REPO_DELETED 444
#define HTTP_INTERNAL_SERVER_ERROR 500

typedef struct _Connection Connection;
typedef struct _ConnectionPool ConnectionPool;

ConnectionPool *
connection_pool_new ();

Connection *
connection_pool_get_connection (ConnectionPool *pool);

void
connection_pool_return_connection (ConnectionPool *pool, Connection *conn);

void
connection_pool_free (ConnectionPool *pool);

char*
http_code_to_str (int http_code);

typedef size_t (*HttpRecvCallback) (void *, size_t, size_t, void *);

int
http_get (Connection *conn, const char *url, const char *token,
          int *rsp_status, char **rsp_content, gint64 *rsp_size,
          HttpRecvCallback callback, void *cb_data,
          gboolean timeout);

int
http_post (Connection *conn, const char *url, const char *token,
           const char *req_content, gint64 req_size,
           int *rsp_status, char **rsp_content, gint64 *rsp_size,
           gboolean timeout, int timeout_sec);

void
http_tx_manager_init ();
#endif
