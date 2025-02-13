#include "common.h"

#include <pthread.h>
#include <curl/curl.h>
#include <jansson.h>

#include <timer.h>
#include <jwt.h>

#include "seafile-session.h"
#include "http-tx-mgr.h"

#include "utils.h"
#include "seaf-db.h"
#include "seafile-error.h"

#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

/* Http connection and connection pool. */

struct _Connection {
    CURL *curl;
    gint64 ctime;               /* Used to clean up unused connection. */
    gboolean release;           /* If TRUE, the connection will be released. */
};

struct _ConnectionPool {
    GQueue *queue;
    pthread_mutex_t lock;
};

static Connection *
connection_new ()
{
    Connection *conn = g_new0 (Connection, 1);
    if (!conn)
        return NULL;

    conn->curl = curl_easy_init();
    conn->ctime = (gint64)time(NULL);

    return conn;
}

static void
connection_free (Connection *conn)
{
    if (!conn)
        return;

    curl_easy_cleanup (conn->curl);
    g_free (conn);
}

ConnectionPool *
connection_pool_new ()
{
    ConnectionPool *pool = g_new0 (ConnectionPool, 1);
    if (!pool)
        return NULL;

    pool->queue = g_queue_new ();
    pthread_mutex_init (&pool->lock, NULL);
    return pool;
}

void
connection_pool_free (ConnectionPool *pool)
{
    if (!pool)
        return;

    g_queue_free (pool->queue);
    g_free (pool);
}

Connection *
connection_pool_get_connection (ConnectionPool *pool)
{
    Connection *conn = NULL;

    pthread_mutex_lock (&pool->lock);
    conn = g_queue_pop_head (pool->queue);
    if (!conn) {
        conn = connection_new ();
    }
    pthread_mutex_unlock (&pool->lock);

    return conn;
}

void
connection_pool_return_connection (ConnectionPool *pool, Connection *conn)
{
    if (!conn)
        return;

    if (conn->release) {
        connection_free (conn);
        return;
    }

    curl_easy_reset (conn->curl);

    pthread_mutex_lock (&pool->lock);
    g_queue_push_tail (pool->queue, conn);
    pthread_mutex_unlock (&pool->lock);
}

char*
http_code_to_str (int http_code)
{
    switch (http_code) {
        case HTTP_OK:
            return "Successful";
        case HTTP_BAD_REQUEST:
            return "Bad request";
        case HTTP_FORBIDDEN:
            return "Permission denied";
        case HTTP_NOT_FOUND:
            return "Resource not found";
    }

    if (http_code >= HTTP_INTERNAL_SERVER_ERROR)
        return "Internal server error";

    return "Unknown error";
}

void
http_tx_manager_init ()
{
    curl_global_init (CURL_GLOBAL_ALL);
}

typedef struct _HttpResponse {
    char *content;
    size_t size;
} HttpResponse;

static size_t
recv_response (void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    HttpResponse *rsp = userp;

    rsp->content = g_realloc (rsp->content, rsp->size + realsize);
    if (!rsp->content) {
        seaf_warning ("Not enough memory.\n");
        /* return a value other than realsize to signify an error. */
        return 0;
    }

    memcpy (rsp->content + rsp->size, contents, realsize);
    rsp->size += realsize;

    return realsize;
}

#define HTTP_TIMEOUT_SEC 45

/*
 * The @timeout parameter is for detecting network connection problems. 
 * The @timeout parameter should be set to TRUE for data-transfer-only operations,
 * such as getting objects, blocks. For operations that requires calculations
 * on the server side, the timeout should be set to FALSE. Otherwise when
 * the server sometimes takes more than 45 seconds to calculate the result,
 * the client will time out.
 */
static int
http_get_common (CURL *curl, const char *url,
                 struct curl_slist **headers,
                 const char *token,
                 int *rsp_status, char **rsp_content, gint64 *rsp_size,
                 HttpRecvCallback callback, void *cb_data,
                 gboolean timeout)
{
    int ret = 0;

    if (token) {
        char *token_header = g_strdup_printf ("Authorization: Token %s", token);
        *headers = curl_slist_append (*headers, token_header);
        g_free (token_header);
    }
    *headers = curl_slist_append (*headers, "User-Agent: Seafile Server");
    *headers = curl_slist_append (*headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, *headers);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    if (timeout) {
        /* Set low speed limit to 1 bytes. This effectively means no data. */
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, HTTP_TIMEOUT_SEC);
    }

    /*if (seaf->disable_verify_certificate) {
        curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }*/

    HttpResponse rsp;
    memset (&rsp, 0, sizeof(rsp));
    if (rsp_content) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, recv_response);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rsp);
    } else if (callback) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, cb_data);
    }

    /*gboolean is_https = (strncasecmp(url, "https", strlen("https")) == 0);
    set_proxy (curl, is_https);*/

    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    int rc = curl_easy_perform (curl);
    if (rc != 0) {
        seaf_warning ("libcurl failed to GET %s: %s.\n",
                      url, curl_easy_strerror(rc));
        ret = -1;
        goto out;
    }

    long status;
    rc = curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &status);
    if (rc != CURLE_OK) {
        seaf_warning ("Failed to get status code for GET %s.\n", url);
        ret = -1;
        goto out;
    }

    *rsp_status = status;

    if (rsp_content) {
        *rsp_content = rsp.content;
        *rsp_size = rsp.size;
    }

out:
    if (ret < 0) {
        g_free (rsp.content);
    }
    return ret;
}

typedef struct _HttpRequest {
    const char *content;
    size_t size;
} HttpRequest;

static size_t
send_request (void *ptr, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size *nmemb;
    size_t copy_size;
    HttpRequest *req = userp;

    if (req->size == 0)
        return 0;

    copy_size = MIN(req->size, realsize);
    memcpy (ptr, req->content, copy_size);
    req->size -= copy_size;
    req->content = req->content + copy_size;

    return copy_size;
}

static int
http_post_common (CURL *curl, const char *url, 
                  struct curl_slist **headers,
                  const char *token,
                  const char *req_content, gint64 req_size,
                  int *rsp_status, char **rsp_content, gint64 *rsp_size,
                  gboolean timeout, int timeout_sec)
{
    int ret = 0;

    if (token) {
        char *token_header = g_strdup_printf ("Authorization: Token %s", token);
        *headers = curl_slist_append (*headers, token_header);
        g_free (token_header);
    }
    *headers = curl_slist_append (*headers, "User-Agent: Seafile Server");
    *headers = curl_slist_append (*headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, *headers);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    if (timeout) {
        /* Set low speed limit to 1 bytes. This effectively means no data. */
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, timeout_sec);
    }

    /*if (seaf->disable_verify_certificate) {
        curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }*/

    HttpRequest req;
    if (req_content) {
        memset (&req, 0, sizeof(req));
        req.content = req_content;
        req.size = req_size;
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, send_request);
        curl_easy_setopt(curl, CURLOPT_READDATA, &req);
    }
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)req_size);

    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    HttpResponse rsp;
    memset (&rsp, 0, sizeof(rsp));
    if (rsp_content) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, recv_response);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rsp);
    }

    /*gboolean is_https = (strncasecmp(url, "https", strlen("https")) == 0);
    set_proxy (curl, is_https);*/

    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    /* All POST requests should remain POST after redirect. */
    curl_easy_setopt(curl, CURLOPT_POSTREDIR, CURL_REDIR_POST_ALL);

    int rc = curl_easy_perform (curl);
    if (rc != 0) {
        seaf_warning ("libcurl failed to POST %s: %s.\n",
                      url, curl_easy_strerror(rc));
        ret = -1;
        goto out;
    }

    long status;
    rc = curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &status);
    if (rc != CURLE_OK) {
        seaf_warning ("Failed to get status code for POST %s.\n", url);
        ret = -1;
        goto out;
    }

    *rsp_status = status;

    if (rsp_content) {
        *rsp_content = rsp.content;
        *rsp_size = rsp.size;
    }

out:
    if (ret < 0) {
        g_free (rsp.content);
    }
    return ret;
}

int
http_post (Connection *conn, const char *url, const char *token,
           const char *req_content, gint64 req_size,
           int *rsp_status, char **rsp_content, gint64 *rsp_size,
           gboolean timeout, int timeout_sec)
{
    struct curl_slist *headers = NULL;
    int ret = 0;
    CURL *curl;

    curl = conn->curl;

    g_return_val_if_fail (req_content != NULL, -1);

    ret = http_post_common (curl, url, &headers, token, req_content, req_size,
                            rsp_status, rsp_content, rsp_size, timeout, timeout_sec);
    if (ret < 0) {
        conn->release = TRUE;
    }
    curl_slist_free_all (headers);
    return ret;
}

static char *
parse_nickname (const char *rsp_content, int rsp_size)
{
    json_t *array = NULL, *object, *member;
    json_error_t jerror;
    size_t n;
    int i;
    char *nickname = NULL;

    object = json_loadb (rsp_content, rsp_size, 0, &jerror);
    if (!object) {
        seaf_warning ("Parse response failed: %s.\n", jerror.text);
        return NULL;
    }

    array = json_object_get (object, "user_list");
    if (!array) {
        goto out;
    }

    n = json_array_size (array);
    for (i = 0; i < n; ++i) {
        json_t *obj = json_array_get (array, i);

        member = json_object_get (obj, "name");
        if (!member) {
            continue;
        }
        nickname = g_strdup (json_string_value(member));
        break;
    }
out:
    json_decref (object);
    return nickname;
}

static char *
gen_jwt_token ()
{
    char *jwt_token = NULL;
    gint64 now = (gint64)time(NULL);

    jwt_t *jwt = NULL;

    if (!seaf->seahub_pk) {
        return NULL;
    }

    int ret = jwt_new (&jwt);
    if (ret != 0 || jwt == NULL) {
        seaf_warning ("Failed to create jwt\n");
        goto out;
    }

    ret = jwt_add_grant_bool (jwt, "is_internal", TRUE);
    if (ret != 0) {
        seaf_warning ("Failed to add is_internal to jwt\n");
        goto out;
    }

    ret = jwt_add_grant_int (jwt, "exp", now + 300);
    if (ret != 0) {
        seaf_warning ("Failed to add expire time to jwt\n");
        goto out;
    }
    ret = jwt_set_alg (jwt, JWT_ALG_HS256, (unsigned char *)seaf->seahub_pk, strlen(seaf->seahub_pk));
    if (ret != 0) {
        seaf_warning ("Failed to set alg\n");
        goto out;
    }

    jwt_token = jwt_encode_str (jwt);

out:
    jwt_free (jwt);
    return jwt_token;
}

char *
http_tx_manager_get_nickname (const char *modifier)
{
    Connection *conn = NULL;
    struct curl_slist *headers = NULL;
    int ret = 0;
    CURL *curl;
    json_t *content = NULL;
    json_t *array = NULL;
    int rsp_status;
    char *req_content = NULL;
    char *jwt_token = NULL;
    char *rsp_content = NULL;
    char *nickname = NULL;
    gint64 rsp_size;
    char *url = NULL;

    jwt_token = gen_jwt_token ();
    if (!jwt_token) {
        return NULL;
    }

    conn = connection_pool_get_connection (seaf->seahub_conn_pool);
    if (!conn) {
        g_free (jwt_token);
        seaf_warning ("Failed to get connection: out of memory.\n");
        return NULL;
    }

    content = json_object ();
    array = json_array ();
    json_array_append_new (array, json_string (modifier));
    json_object_set_new (content, "user_id_list", array);
    req_content  = json_dumps (content, JSON_COMPACT);
    if (!req_content) {
        json_decref (content);
        seaf_warning ("Failed to dump json request.\n");
        goto out;
    }
    json_decref (content);

    curl = conn->curl;

    url = g_strdup_printf("%s/user-list/", seaf->seahub_url);
    ret = http_post_common (curl, url, &headers, jwt_token, req_content, strlen(req_content),
                            &rsp_status, &rsp_content, &rsp_size, TRUE, 45);
    if (ret < 0) {
        conn->release = TRUE;
        goto out;
    }

    if (rsp_status != HTTP_OK) {
        goto out;
    }

    nickname = parse_nickname (rsp_content, rsp_size);

out:
    g_free (url);
    g_free (jwt_token);
    g_free (req_content);
    g_free (rsp_content);
    curl_slist_free_all (headers);
    connection_pool_return_connection (seaf->seahub_conn_pool, conn);

    return nickname;
}

static SeafileShareLinkInfo *
parse_share_link_info (const char *rsp_content, int rsp_size)
{
    json_t *object;
    json_error_t jerror;
    size_t n;
    int i;
    const char *repo_id = NULL;
    const char *file_path = NULL;
    const char *parent_dir = NULL;
    const char *share_type = NULL;
    SeafileShareLinkInfo *info = NULL;

    object = json_loadb (rsp_content, rsp_size, 0, &jerror);
    if (!object) {
        seaf_warning ("Parse response failed: %s.\n", jerror.text);
        return NULL;
    }

    repo_id = json_object_get_string_member (object, "repo_id");
    if (!repo_id) {
        seaf_warning ("Failed to find repo_id in json.\n");
        goto out;
    }
    file_path = json_object_get_string_member (object, "file_path");
    parent_dir = json_object_get_string_member (object, "parent_dir");
    share_type = json_object_get_string_member (object, "share_type");

    info = g_object_new (SEAFILE_TYPE_SHARE_LINK_INFO,
                         "repo_id", repo_id,
                         "file_path", file_path,
                         "parent_dir", parent_dir,
                         "share_type", share_type,
                         NULL);

out:
    json_decref (object);
    return info;
}

char *
parse_error_message (const char *rsp_content, int rsp_size)
{
    json_t *object;
    json_error_t jerror;
    const char *err_msg = NULL;
    char *ret = NULL;

    if (!rsp_content) {
        return NULL;
    }

    object = json_loadb (rsp_content, rsp_size, 0, &jerror);
    if (!object) {
        ret = g_strdup (rsp_content);
        return ret;
    }

    err_msg = json_object_get_string_member (object, "error_msg");
    if (!err_msg) {
        ret = g_strdup (rsp_content);
        goto out;
    }
    ret = g_strdup (err_msg);

out:
    json_decref (object);

    return ret;
}

SeafileShareLinkInfo *
http_tx_manager_query_share_link_info (const char *token, const char *cookie, const char *type,
                                       const char *ip_addr, const char *user_agent, int *status, char **err_msg)
{
    Connection *conn = NULL;
    char *cookie_header;
    struct curl_slist *headers = NULL;
    int ret = 0;
    CURL *curl;
    json_t *content = NULL;
    char *req_content = NULL;
    int rsp_status;
    char *jwt_token = NULL;
    char *rsp_content = NULL;
    gint64 rsp_size;
    SeafileShareLinkInfo *info = NULL;
    char *url = NULL;

    jwt_token = gen_jwt_token ();
    if (!jwt_token) {
        return NULL;
    }

    conn = connection_pool_get_connection (seaf->seahub_conn_pool);
    if (!conn) {
        g_free (jwt_token);
        seaf_warning ("Failed to get connection: out of memory.\n");
        return NULL;
    }

    content = json_object ();
    json_object_set_new (content, "token", json_string(token));
    if (ip_addr)
        json_object_set_new (content, "ip_addr", json_string(ip_addr));
    if (user_agent)
        json_object_set_new (content, "user_agent", json_string(user_agent));
    req_content  = json_dumps (content, JSON_COMPACT);
    if (!req_content) {
        seaf_warning ("Failed to dump json request.\n");
        goto out;
    }

    curl = conn->curl;
    if (cookie) {
        cookie_header = g_strdup_printf ("Cookie: %s", cookie);
        headers = curl_slist_append (headers, cookie_header);
        g_free (cookie_header);
    }

    url = g_strdup_printf("%s/check-share-link-access/?type=%s", seaf->seahub_url, type);
    ret = http_post_common (curl, url, &headers, jwt_token, req_content, strlen(req_content),
                            &rsp_status, &rsp_content, &rsp_size, TRUE, 45);
    if (ret < 0) {
        conn->release = TRUE;
        goto out;
    }

    *status = rsp_status;
    if (rsp_status != HTTP_OK) {
        *err_msg = parse_error_message (rsp_content, rsp_size);
        goto out;
    }

    info = parse_share_link_info (rsp_content, rsp_size);

out:
    if (content)
        json_decref (content);
    g_free (url);
    g_free (jwt_token);
    g_free (req_content);
    g_free (rsp_content);
    curl_slist_free_all (headers);
    connection_pool_return_connection (seaf->seahub_conn_pool, conn);

    return info;
}

char *
parse_file_access_info (const char *rsp_content, int rsp_size)
{
    json_t *object;
    json_error_t jerror;
    const char *user = NULL;
    char *ret = NULL;

    object = json_loadb (rsp_content, rsp_size, 0, &jerror);
    if (!object) {
        seaf_warning ("Failed to parse response when check file access in Seahub: %s.\n", jerror.text);
        return NULL;
    }

    user = json_object_get_string_member (object, "user");
    if (!user) {
        seaf_warning ("Failed to find user in json when check file access in Seahub.\n");
        goto out;
    }
    ret = g_strdup (user);

out:
    json_decref (object);

    return ret;
}

int
http_tx_manager_check_file_access (const char *repo_id, const char *token, const char *cookie,
                                   const char *path, const char *op, const char *ip_addr,
                                   const char *user_agent, char **user,
                                   int *status, char **err_msg)
{
    Connection *conn = NULL;
    char *cookie_header;
    struct curl_slist *headers = NULL;
    int ret = -1;
    CURL *curl;
    json_t *content = NULL;
    int rsp_status;
    char *req_content = NULL;
    char *jwt_token = NULL;
    char *rsp_content = NULL;
    gint64 rsp_size;
    char *url = NULL;

    jwt_token = gen_jwt_token ();
    if (!jwt_token) {
        return -1;
    }

    conn = connection_pool_get_connection (seaf->seahub_conn_pool);
    if (!conn) {
        g_free (jwt_token);
        seaf_warning ("Failed to get connection: out of memory.\n");
        return -1;
    }

    content = json_object ();
    json_object_set_new (content, "op", json_string(op));
    if (token) {
        json_object_set_new (content, "token", json_string(token));
    }
    json_object_set_new (content, "path", json_string(path));
    if (ip_addr)
        json_object_set_new (content, "ip_addr", json_string(ip_addr));
    if (user_agent)
        json_object_set_new (content, "user_agent", json_string(user_agent));
    req_content  = json_dumps (content, JSON_COMPACT);
    if (!req_content) {
        ret = -1;
        seaf_warning ("Failed to dump json request.\n");
        goto out;
    }

    curl = conn->curl;
    if (cookie) {
        cookie_header = g_strdup_printf ("Cookie: %s", cookie);
        headers = curl_slist_append (headers, cookie_header);
        g_free (cookie_header);
    }

    url = g_strdup_printf("%s/repos/%s/check-access/", seaf->seahub_url, repo_id);
    ret = http_post_common (curl, url, &headers, jwt_token, req_content, strlen(req_content),
                            &rsp_status, &rsp_content, &rsp_size, TRUE, 45);
    if (ret < 0) {
        conn->release = TRUE;
        goto out;
    }

    *status = rsp_status;
    if (rsp_status != HTTP_OK) {
        *err_msg = parse_error_message (rsp_content, rsp_size);
        ret = -1;
        goto out;
    }

    *user = parse_file_access_info (rsp_content, rsp_size);
    if (*user == NULL) {
        ret = -1;
        goto out;
    }

out:
    if (content)
        json_decref (content);
    g_free (url);
    g_free (jwt_token);
    g_free (req_content);
    g_free (rsp_content);
    curl_slist_free_all (headers);
    connection_pool_return_connection (seaf->seahub_conn_pool, conn);

    return ret;
}
