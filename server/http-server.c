#include "common.h"

#ifdef HAVE_EVHTP
#include <pthread.h>
#include <string.h>
#include <jansson.h>
#include <locale.h>
#include <sys/types.h>

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <event2/event.h>
#else
#include <event.h>
#endif

#include <evhtp.h>

#include <jwt.h>

#include "mq-mgr.h"
#include "utils.h"
#include "log.h"
#include "http-server.h"
#include "seafile-session.h"
#include "diff-simple.h"
#include "merge-new.h"
#include "seaf-db.h"
#include "seaf-utils.h"

#include "access-file.h"
#include "upload-file.h"
#include "fileserver-config.h"

#include "http-status-codes.h"

#define DEFAULT_BIND_HOST "0.0.0.0"
#define DEFAULT_BIND_PORT 8082
#define DEFAULT_WORKER_THREADS 10
#define DEFAULT_MAX_DOWNLOAD_DIR_SIZE 100 * ((gint64)1 << 20) /* 100MB */
#define DEFAULT_MAX_INDEXING_THREADS 1
#define DEFAULT_MAX_INDEX_PROCESSING_THREADS 3
#define DEFAULT_FIXED_BLOCK_SIZE ((gint64)1 << 23) /* 8MB */
#define DEFAULT_CLUSTER_SHARED_TEMP_FILE_MODE 0600

#define HOST "host"
#define PORT "port"

#define HTTP_TEMP_FILE_SCAN_INTERVAL  3600 /*1h*/
#define HTTP_TEMP_FILE_DEFAULT_TTL 3600 * 24 * 3 /*3days*/
#define HTTP_TEMP_FILE_TTL "http_temp_file_ttl"
#define HTTP_SCAN_INTERVAL "http_temp_scan_interval"

#define INIT_INFO "If you see this page, Seafile HTTP syncing component works."
#define PROTO_VERSION "{\"version\": 2}"

#define CLEANING_INTERVAL_SEC 300	/* 5 minutes */
#define TOKEN_EXPIRE_TIME 7200	    /* 2 hours */
#define PERM_EXPIRE_TIME 7200       /* 2 hours */
#define VIRINFO_EXPIRE_TIME 7200       /* 2 hours */

#define FS_ID_LIST_MAX_WORKERS 3
#define FS_ID_LIST_TOKEN_LEN 36

struct _HttpServer {
    evbase_t *evbase;
    evhtp_t *evhtp;
    event_t *reap_timer;
    pthread_t thread_id;

    GHashTable *token_cache;
    pthread_mutex_t token_cache_lock; /* token -> username */

    GHashTable *perm_cache;
    pthread_mutex_t perm_cache_lock; /* repo_id:username -> permission */

    GHashTable *vir_repo_info_cache;
    pthread_mutex_t vir_repo_info_cache_lock;

    GThreadPool *compute_fs_obj_id_pool;

    GHashTable *fs_obj_ids;
    pthread_mutex_t fs_obj_ids_lock;
};
typedef struct _HttpServer HttpServer;

struct _StatsEventData {
    char *etype;
    char *user;
    char *operation;
    char repo_id[37];
    guint64 bytes;
};
typedef struct _StatsEventData StatsEventData;

typedef struct TokenInfo {
    char *repo_id;
    char *email;
    gint64 expire_time;
} TokenInfo;

// PermInfo caches the results from the last permission check for accessing a repo.
// They're cached in a hash table having "repo_Id:username:op" as key.
// The cached result is updated on the next call to get_check_permission_cb function, or when the cache expires.
// The result is only cached if the permission check passed.
typedef struct PermInfo {
    gint64 expire_time;
} PermInfo;

typedef struct VirRepoInfo {
    char *store_id;
    gint64 expire_time;
} VirRepoInfo;

typedef struct FsHdr {
    char obj_id[40];
    guint32 obj_size;
} __attribute__((__packed__)) FsHdr;

typedef enum CheckExistType {
    CHECK_FS_EXIST,
    CHECK_BLOCK_EXIST
} CheckExistType;

const char *GET_PROTO_PATH = "/protocol-version";
const char *OP_PERM_CHECK_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/permission-check/.*";
const char *GET_CHECK_QUOTA_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/quota-check/.*";
const char *HEAD_COMMIT_OPER_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/commit/HEAD";
const char *GET_HEAD_COMMITS_MULTI_REGEX = "^/repo/head-commits-multi";
const char *COMMIT_OPER_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/commit/[\\da-z]{40}";
const char *PUT_COMMIT_INFO_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/commit/[\\da-z]{40}";
const char *GET_FS_OBJ_ID_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/fs-id-list/.*";
const char *START_FS_OBJ_ID_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/start-fs-id-list/.*";
const char *QUERY_FS_OBJ_ID_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/query-fs-id-list/.*";
const char *RETRIEVE_FS_OBJ_ID_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/retrieve-fs-id-list/.*";
const char *BLOCK_OPER_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/block/[\\da-z]{40}";
const char *POST_CHECK_FS_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/check-fs";
const char *POST_CHECK_BLOCK_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/check-blocks";
const char *POST_RECV_FS_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/recv-fs";
const char *POST_PACK_FS_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/pack-fs";
const char *GET_BLOCK_MAP_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/block-map/[\\da-z]{40}";
const char *GET_JWT_TOKEN_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/jwt-token";

//accessible repos
const char *GET_ACCESSIBLE_REPO_LIST_REGEX = "/accessible-repos";

static void
load_http_config (HttpServerStruct *htp_server, SeafileSession *session)
{
    GError *error = NULL;
    char *host = NULL;
    int port = 0;
    int worker_threads;
    char *encoding;
    char *cluster_shared_temp_file_mode = NULL;
    gboolean verify_client_blocks;

    host = fileserver_config_get_string (session->config, HOST, &error);
    if (!error) {
        htp_server->bind_addr = host;
    } else {
        if (error->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND &&
            error->code != G_KEY_FILE_ERROR_GROUP_NOT_FOUND) {
            seaf_warning ("[conf] Error: failed to read the value of 'host'\n");
            exit (1);
        }

        htp_server->bind_addr = g_strdup (DEFAULT_BIND_HOST);
        g_clear_error (&error);
    }

    port = fileserver_config_get_integer (session->config, PORT, &error);
    if (!error) {
        htp_server->bind_port = port;
    } else {
        if (error->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND &&
            error->code != G_KEY_FILE_ERROR_GROUP_NOT_FOUND) {
            seaf_warning ("[conf] Error: failed to read the value of 'port'\n");
            exit (1);
        }

        htp_server->bind_port = DEFAULT_BIND_PORT;
        g_clear_error (&error);
    }

    worker_threads = fileserver_config_get_integer (session->config, "worker_threads",
                                                    &error);
    if (error) {
        htp_server->worker_threads = DEFAULT_WORKER_THREADS;
        g_clear_error (&error);
    } else {
        if (worker_threads <= 0)
            htp_server->worker_threads = DEFAULT_WORKER_THREADS;
        else
            htp_server->worker_threads = worker_threads;
    }
    seaf_message ("fileserver: worker_threads = %d\n", htp_server->worker_threads);

    verify_client_blocks  = fileserver_config_get_boolean (session->config,
                                                           "verify_client_blocks_after_sync",
                                                           &error);
    if (error) {
        htp_server->verify_client_blocks = TRUE;
        g_clear_error(&error);
    } else {
        htp_server->verify_client_blocks = verify_client_blocks;
    }
    seaf_message ("fileserver: verify_client_blocks = %d\n",
                  htp_server->verify_client_blocks);

    cluster_shared_temp_file_mode = fileserver_config_get_string (session->config,
                                                                  "cluster_shared_temp_file_mode",
                                                                  &error);
    if (error) {
        htp_server->cluster_shared_temp_file_mode = DEFAULT_CLUSTER_SHARED_TEMP_FILE_MODE;
        g_clear_error (&error);
    } else {
        if (!cluster_shared_temp_file_mode) {
            htp_server->cluster_shared_temp_file_mode = DEFAULT_CLUSTER_SHARED_TEMP_FILE_MODE;
        } else {
            htp_server->cluster_shared_temp_file_mode = strtol(cluster_shared_temp_file_mode, NULL, 8);

            if (htp_server->cluster_shared_temp_file_mode < 0001 ||
                htp_server->cluster_shared_temp_file_mode > 0777)
                htp_server->cluster_shared_temp_file_mode = DEFAULT_CLUSTER_SHARED_TEMP_FILE_MODE;

            g_free (cluster_shared_temp_file_mode);
        }
    }
    seaf_message ("fileserver: cluster_shared_temp_file_mode = %o\n",
                  htp_server->cluster_shared_temp_file_mode);

    encoding = g_key_file_get_string (session->config,
                                      "zip", "windows_encoding",
                                      &error);
    if (encoding) {
        htp_server->windows_encoding = encoding;
    } else {
        g_clear_error (&error);
        /* No windows specific encoding is specified. Set the ZIP_UTF8 flag. */
        setlocale (LC_ALL, "en_US.UTF-8");
    }
}

static int
validate_token (HttpServer *htp_server, evhtp_request_t *req,
                const char *repo_id, char **username,
                gboolean skip_cache)
{
    char *email = NULL;
    TokenInfo *token_info;
    char *tmp_token = NULL;

    const char *token = evhtp_kv_find (req->headers_in, "Seafile-Repo-Token");
    if (token == NULL) {
        const char *auth_token = evhtp_kv_find (req->headers_in, "Authorization");
        tmp_token = seaf_parse_auth_token (auth_token);
        if (tmp_token == NULL) {
            evhtp_send_reply (req, EVHTP_RES_BADREQ);
            return EVHTP_RES_BADREQ;
        }
        token = tmp_token;
    }

    if (!skip_cache) {
        pthread_mutex_lock (&htp_server->token_cache_lock);

        token_info = g_hash_table_lookup (htp_server->token_cache, token);
        if (token_info) {
            if (strcmp (token_info->repo_id, repo_id) != 0) {
                pthread_mutex_unlock (&htp_server->token_cache_lock);
                g_free (tmp_token);
                return EVHTP_RES_FORBIDDEN;
            }

            if (username)
                *username = g_strdup(token_info->email);
            pthread_mutex_unlock (&htp_server->token_cache_lock);
            g_free (tmp_token);
            return EVHTP_RES_OK;
        }

        pthread_mutex_unlock (&htp_server->token_cache_lock);
    }

    email = seaf_repo_manager_get_email_by_token (seaf->repo_mgr,
                                                  repo_id, token);
    if (email == NULL) {
        pthread_mutex_lock (&htp_server->token_cache_lock);
        g_hash_table_remove (htp_server->token_cache, token);
        pthread_mutex_unlock (&htp_server->token_cache_lock);
        g_free (tmp_token);
        return EVHTP_RES_FORBIDDEN;
    }

    token_info = g_new0 (TokenInfo, 1);
    token_info->repo_id = g_strdup (repo_id);
    token_info->expire_time = (gint64)time(NULL) + TOKEN_EXPIRE_TIME;
    token_info->email = email;

    pthread_mutex_lock (&htp_server->token_cache_lock);
    g_hash_table_insert (htp_server->token_cache, g_strdup (token), token_info);
    pthread_mutex_unlock (&htp_server->token_cache_lock);

    if (username)
        *username = g_strdup(email);
    g_free (tmp_token);
    return EVHTP_RES_OK;
}

static PermInfo *
lookup_perm_cache (HttpServer *htp_server, const char *repo_id, const char *username, const char *op)
{
    PermInfo *ret = NULL;
    PermInfo *perm = NULL;
    char *key = g_strdup_printf ("%s:%s:%s", repo_id, username, op);

    pthread_mutex_lock (&htp_server->perm_cache_lock);
    ret = g_hash_table_lookup (htp_server->perm_cache, key);
    if (ret) {
        perm = g_new0 (PermInfo, 1);
        perm->expire_time = ret->expire_time;
    }
    pthread_mutex_unlock (&htp_server->perm_cache_lock);
    g_free (key);

    return perm;
}

static char *
get_auth_token (evhtp_request_t *req)
{
    const char *token = evhtp_kv_find (req->headers_in, "Seafile-Repo-Token");
    if (token) {
        return g_strdup (token);
    }

    char *tmp_token = NULL;
    const char *auth_token = evhtp_kv_find (req->headers_in, "Authorization");
    tmp_token = seaf_parse_auth_token (auth_token);

    return tmp_token;
}

static void
insert_perm_cache (HttpServer *htp_server,
                   const char *repo_id, const char *username,
                   const char *op,
                   PermInfo *perm)
{
    char *key = g_strdup_printf ("%s:%s:%s", repo_id, username, op);

    pthread_mutex_lock (&htp_server->perm_cache_lock);
    g_hash_table_insert (htp_server->perm_cache, key, perm);
    pthread_mutex_unlock (&htp_server->perm_cache_lock);
}

static void
remove_perm_cache (HttpServer *htp_server,
                   const char *repo_id, const char *username,
                   const char *op)
{
    char *key = g_strdup_printf ("%s:%s:%s", repo_id, username, op);

    pthread_mutex_lock (&htp_server->perm_cache_lock);
    g_hash_table_remove (htp_server->perm_cache, key);
    pthread_mutex_unlock (&htp_server->perm_cache_lock);

    g_free (key);
}

static void perm_cache_value_free (gpointer data);

static int
check_permission (HttpServer *htp_server, const char *repo_id, const char *username,
                  const char *op, gboolean skip_cache)
{
    PermInfo *perm_info = NULL;

    if (!skip_cache)
        perm_info = lookup_perm_cache (htp_server, repo_id, username, op);

    if (perm_info) {
        perm_cache_value_free (perm_info);
        return EVHTP_RES_OK;
    }

    remove_perm_cache (htp_server, repo_id, username, op);

    if (strcmp(op, "upload") == 0) {
        int status = seaf_repo_manager_get_repo_status(seaf->repo_mgr, repo_id);
        if (status != REPO_STATUS_NORMAL && status != -1)
            return EVHTP_RES_FORBIDDEN;
    }

    char *perm = seaf_repo_manager_check_permission (seaf->repo_mgr,
                                                     repo_id, username, NULL);
    if (perm) {
        if ((strcmp (perm, "r") == 0 && strcmp (op, "upload") == 0)) {
            g_free (perm);
            return EVHTP_RES_FORBIDDEN;
        }

        g_free (perm);
        perm_info = g_new0 (PermInfo, 1);
        /* Take the reference of perm. */
        perm_info->expire_time = (gint64)time(NULL) + PERM_EXPIRE_TIME;
        insert_perm_cache (htp_server, repo_id, username, op, perm_info);
        return EVHTP_RES_OK;
    }

    /* Invalidate cache if perm not found in db. */
    return EVHTP_RES_FORBIDDEN;
}

static gboolean
get_vir_repo_info (SeafDBRow *row, void *data)
{
    const char *repo_id = seaf_db_row_get_column_text (row, 0);
    if (!repo_id)
        return FALSE;
    const char *origin_id = seaf_db_row_get_column_text (row, 1);
    if (!origin_id)
        return FALSE;

    VirRepoInfo **vinfo = data;
    *vinfo = g_new0 (VirRepoInfo, 1);
    if (!*vinfo)
        return FALSE;
    (*vinfo)->store_id = g_strdup (origin_id);
    if (!(*vinfo)->store_id)
        return FALSE;
    (*vinfo)->expire_time = time (NULL) + VIRINFO_EXPIRE_TIME;

    return TRUE;
}

static char *
get_store_id_from_vir_repo_info_cache (HttpServer *htp_server, const char *repo_id)
{
    char *store_id = NULL;
    VirRepoInfo *vinfo = NULL;

    pthread_mutex_lock (&htp_server->vir_repo_info_cache_lock);
    vinfo = g_hash_table_lookup (htp_server->vir_repo_info_cache, repo_id);

    if (vinfo) {
        if (vinfo->store_id)
            store_id = g_strdup (vinfo->store_id);
        else
            store_id = g_strdup (repo_id);

        vinfo->expire_time = time (NULL) + VIRINFO_EXPIRE_TIME;
    }

    pthread_mutex_unlock (&htp_server->vir_repo_info_cache_lock);

    return store_id;
}

static void
add_vir_info_to_cache (HttpServer *htp_server, const char *repo_id,
                       VirRepoInfo *vinfo)
{
    pthread_mutex_lock (&htp_server->vir_repo_info_cache_lock);
    g_hash_table_insert (htp_server->vir_repo_info_cache, g_strdup (repo_id), vinfo);
    pthread_mutex_unlock (&htp_server->vir_repo_info_cache_lock);
}

static char *
get_repo_store_id (HttpServer *htp_server, const char *repo_id)
{
    char *store_id = get_store_id_from_vir_repo_info_cache (htp_server,
                                                            repo_id);
    if (store_id) {
        return store_id;
    }

    VirRepoInfo *vinfo = NULL;
    char *sql = "SELECT repo_id, origin_repo FROM VirtualRepo where repo_id = ?";
    int n_row = seaf_db_statement_foreach_row (seaf->db, sql, get_vir_repo_info,
                                               &vinfo, 1, "string", repo_id);
    if (n_row < 0) {
        // db error, return NULL
        return NULL;
    } else if (n_row == 0) {
        // repo is not virtual repo
        vinfo = g_new0 (VirRepoInfo, 1);
        if (!vinfo)
            return NULL;
        vinfo->expire_time = time (NULL) + VIRINFO_EXPIRE_TIME;

        add_vir_info_to_cache (htp_server, repo_id, vinfo);

        return g_strdup (repo_id);
    } else if (!vinfo || !vinfo->store_id) {
        // out of memory, return NULL
        return NULL;
    }

    add_vir_info_to_cache (htp_server, repo_id, vinfo);

    return g_strdup (vinfo->store_id);
}

typedef struct {
    char *etype;
    char *user;
    char *ip;
    char repo_id[37];
    char *path;
    char *client_name;
} RepoEventData;


static void
free_repo_event_data (RepoEventData *data)
{
    if (!data)
        return;

    g_free (data->etype);
    g_free (data->user);
    g_free (data->ip);
    g_free (data->path);
    g_free (data->client_name);
    g_free (data);
}

static void
free_stats_event_data (StatsEventData *data)
{
    if (!data)
        return;

    g_free (data->etype);
    g_free (data->user);
    g_free (data->operation);
    g_free (data);
}

static void
publish_repo_event (RepoEventData *rdata)
{
    json_t *msg = json_object ();
    char *msg_str = NULL;

    json_object_set_new (msg, "msg_type", json_string(rdata->etype));
    json_object_set_new (msg, "user_name", json_string(rdata->user));
    json_object_set_new (msg, "ip", json_string(rdata->ip));
    if (rdata->client_name) {
        json_object_set_new (msg, "user_agent", json_string(rdata->client_name));
    } else {
        json_object_set_new (msg, "user_agent", json_string(""));
    }
    json_object_set_new (msg, "repo_id", json_string(rdata->repo_id));
    if (rdata->path) {
        json_object_set_new (msg, "file_path", json_string(rdata->path));
    } else {
        json_object_set_new (msg, "file_path", json_string("/"));
    }

    msg_str = json_dumps (msg, JSON_PRESERVE_ORDER);

    seaf_mq_manager_publish_event (seaf->mq_mgr, SEAFILE_SERVER_CHANNEL_EVENT, msg_str);

    g_free (msg_str);
    json_decref (msg);
}

static void
publish_stats_event (StatsEventData *rdata)
{
    json_t *msg = json_object ();
    char *msg_str = NULL;

    json_object_set_new (msg, "msg_type", json_string(rdata->etype));
    json_object_set_new (msg, "user_name", json_string(rdata->user));
    json_object_set_new (msg, "repo_id", json_string(rdata->repo_id));
    json_object_set_new (msg, "bytes", json_integer(rdata->bytes));

    msg_str = json_dumps (msg, JSON_PRESERVE_ORDER);

    seaf_mq_manager_publish_event (seaf->mq_mgr, SEAFILE_SERVER_CHANNEL_STATS, msg_str);

    g_free (msg_str);
    json_decref (msg);
}

static void
on_repo_oper (HttpServer *htp_server, const char *etype,
              const char *repo_id, char *user, char *ip, char *client_name)
{
    RepoEventData *rdata = g_new0 (RepoEventData, 1);
    SeafVirtRepo *vinfo = seaf_repo_manager_get_virtual_repo_info (seaf->repo_mgr,
                                                                   repo_id);

    if (vinfo) {
        memcpy (rdata->repo_id, vinfo->origin_repo_id, 36);
        rdata->path = g_strdup(vinfo->path);
    } else
        memcpy (rdata->repo_id, repo_id, 36);
    rdata->etype = g_strdup (etype);
    rdata->user = g_strdup (user);
    rdata->ip = g_strdup (ip);
    rdata->client_name = g_strdup(client_name);

    publish_repo_event(rdata);
    if (vinfo) {
        g_free (vinfo->path);
        g_free (vinfo);
    }
    free_repo_event_data (rdata);    
    return;
}

void
send_statistic_msg (const char *repo_id, char *user, char *operation, guint64 bytes)
{
    StatsEventData *rdata = g_new0 (StatsEventData, 1);

    memcpy (rdata->repo_id, repo_id, 36);
    rdata->etype = g_strdup (operation);
    rdata->user = g_strdup (user);
    rdata->bytes = bytes;

    publish_stats_event(rdata);

    free_stats_event_data (rdata);    
    return;
}

char *
get_client_ip_addr (void *data)
{
    evhtp_request_t *req = data;
    const char *xff = evhtp_kv_find (req->headers_in, "X-Forwarded-For");
    if (xff) {
        struct in_addr addr;
        const char *comma = strchr (xff, ',');
        char *copy;
        if (comma)
            copy = g_strndup(xff, comma-xff);
        else
            copy = g_strdup(xff);
        if (evutil_inet_pton (AF_INET, copy, &addr) == 1)
            return copy;
        else if (evutil_inet_pton (AF_INET6, copy, &addr) == 1)
            return copy;
        g_free (copy);
    }

    evhtp_connection_t *conn = req->conn;
    if (conn->saddr->sa_family == AF_INET) {
        char ip_addr[17];
        const char *ip = NULL;
        struct sockaddr_in *addr_in = (struct sockaddr_in *)conn->saddr;

        memset (ip_addr, '\0', 17);
        ip = evutil_inet_ntop (AF_INET, &addr_in->sin_addr, ip_addr, 16);

        return g_strdup (ip);
    }

    char ip_addr[47];
    const char *ip = NULL;
    struct sockaddr_in6 *addr_in = (struct sockaddr_in6 *)conn->saddr;

    memset (ip_addr, '\0', 47);
    ip = evutil_inet_ntop (AF_INET6, &addr_in->sin6_addr, ip_addr, 46);

    return g_strdup (ip);
}

static int
validate_client_ver (const char *client_ver)
{
    char **versions = NULL;
    char *next_str = NULL;

    versions = g_strsplit (client_ver, ".", 3);
    if (g_strv_length (versions) != 3) {
        g_strfreev (versions);
        return EVHTP_RES_BADREQ;
    }

    strtoll (versions[0], &next_str, 10);
    if (versions[0] == next_str) {
        g_strfreev (versions);
        return EVHTP_RES_BADREQ;
    }

    strtoll (versions[1], &next_str, 10);
    if (versions[1] == next_str) {
        g_strfreev (versions);
        return EVHTP_RES_BADREQ;
    }

    strtoll (versions[2], &next_str, 10);
    if (versions[2] == next_str) {
        g_strfreev (versions);
        return EVHTP_RES_BADREQ;
    }

    // todo: judge whether version is too old, then return 426

    g_strfreev (versions);
    return EVHTP_RES_OK;
}

static void
get_check_permission_cb (evhtp_request_t *req, void *arg)
{
    const char *op = evhtp_kv_find (req->uri->query, "op");
    if (op == NULL || (strcmp (op, "upload") != 0 && strcmp (op, "download") != 0)) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    const char *client_id = evhtp_kv_find (req->uri->query, "client_id");
    if (client_id && strlen(client_id) != 40) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    const char *client_ver = evhtp_kv_find (req->uri->query, "client_ver");
    if (client_ver) {
        int status = validate_client_ver (client_ver);
        if (status != EVHTP_RES_OK) {
            evhtp_send_reply (req, status);
            return;
        }
    }

    char *client_name = NULL;
    const char *client_name_in = evhtp_kv_find (req->uri->query, "client_name");
    if (client_name_in)
        client_name = g_uri_unescape_string (client_name_in, NULL);

    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];
    HttpServer *htp_server = seaf->http_server->priv;
    char *username = NULL;
    char *ip = NULL;
    const char *token;
    SeafRepo *repo = NULL;

    repo = seaf_repo_manager_get_repo_ex (seaf->repo_mgr, repo_id);
    if (!repo) {
        evhtp_send_reply (req, SEAF_HTTP_RES_REPO_DELETED);
        goto out;
    }
    if (repo->is_corrupted || repo->repaired) {
        evhtp_send_reply (req, SEAF_HTTP_RES_REPO_CORRUPTED);
        goto out;
    }

    int token_status = validate_token (htp_server, req, repo_id, &username, TRUE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    /* We shall actually check the permission from database, don't rely on
     * the cache here.
     */
    int perm_status = check_permission (htp_server, repo_id, username, op, TRUE);
    if (perm_status == EVHTP_RES_FORBIDDEN) {
        evhtp_send_reply (req, EVHTP_RES_FORBIDDEN);
        goto out;
    }

    ip = get_client_ip_addr (req);
    if (!ip) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        token = evhtp_kv_find (req->headers_in, "Seafile-Repo-Token");
        seaf_warning ("[%s] Failed to get client ip.\n", token);
        goto out;
    }

    if (strcmp (op, "download") == 0) {
        on_repo_oper (htp_server, "repo-download-sync", repo_id, username, ip, client_name);
    }
    /* else if (strcmp (op, "upload") == 0) { */
    /*     on_repo_oper (htp_server, "repo-upload-sync", repo_id, username, ip, client_name); */
    /* } */

    if (client_id && client_name) {
        token = evhtp_kv_find (req->headers_in, "Seafile-Repo-Token");

        /* Record the (token, email, <peer info>) information, <peer info> may
         * include peer_id, peer_ip, peer_name, etc.
         */
        if (!seaf_repo_manager_token_peer_info_exists (seaf->repo_mgr, token))
            seaf_repo_manager_add_token_peer_info (seaf->repo_mgr,
                                                   token,
                                                   client_id,
                                                   ip,
                                                   client_name,
                                                   (gint64)time(NULL),
                                                   client_ver);
        else
            seaf_repo_manager_update_token_peer_info (seaf->repo_mgr,
                                                      token,
                                                      ip,
                                                      (gint64)time(NULL),
                                                      client_ver);
    }

    evhtp_send_reply (req, EVHTP_RES_OK);

out:
    g_free (username);
    g_strfreev (parts);
    g_free (ip);
    g_free (client_name);
    if (repo) {
        seaf_repo_unref (repo);
    }
}

static void
get_protocol_cb (evhtp_request_t *req, void *arg)
{
    evbuffer_add (req->buffer_out, PROTO_VERSION, strlen (PROTO_VERSION));
    evhtp_send_reply (req, EVHTP_RES_OK);
}

static void
get_check_quota_cb (evhtp_request_t *req, void *arg)
{
    HttpServer *htp_server = seaf->http_server->priv;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];

    int token_status = validate_token (htp_server, req, repo_id, NULL, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    const char *delta = evhtp_kv_find (req->uri->query, "delta");
    if (delta == NULL) {
        char *error = "Invalid delta parameter.\n";
        seaf_warning ("%s", error);
        evbuffer_add (req->buffer_out, error, strlen (error));
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    char *next_ptr = NULL;
    gint64 delta_num = strtoll(delta, &next_ptr, 10);
    if (!(*delta != '\0' && *next_ptr == '\0')) {
        char *error = "Invalid delta parameter.\n";
        seaf_warning ("%s", error);
        evbuffer_add (req->buffer_out, error, strlen (error));
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    int ret = seaf_quota_manager_check_quota_with_delta (seaf->quota_mgr,
                                                         repo_id, delta_num);
    if (ret < 0) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
    } else if (ret == 0) {
        evhtp_send_reply (req, EVHTP_RES_OK);
    } else {
        evhtp_send_reply (req, SEAF_HTTP_RES_NOQUOTA);
    }

out:
    g_strfreev (parts);
}

static gboolean
get_branch (SeafDBRow *row, void *vid)
{
    char *ret = vid;
    const char *commit_id;

    commit_id = seaf_db_row_get_column_text (row, 0);
    memcpy (ret, commit_id, 41);

    return FALSE;
}

static void
get_head_commit_cb (evhtp_request_t *req, void *arg)
{
    HttpServer *htp_server = seaf->http_server->priv;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];
    gboolean db_err = FALSE, exists = TRUE;
    int token_status;
    char commit_id[41];
    char *sql;

    sql = "SELECT 1 FROM Repo WHERE repo_id=?";
    exists = seaf_db_statement_exists (seaf->db, sql, &db_err, 1, "string", repo_id);
    if (!exists) {
        if (db_err) {
            seaf_warning ("DB error when check repo existence.\n");
            evbuffer_add_printf (req->buffer_out,
                                 "{\"is_corrupted\": 1}");
            evhtp_send_reply (req, EVHTP_RES_OK);
            goto out;
        }
        evhtp_send_reply (req, SEAF_HTTP_RES_REPO_DELETED);
        goto out;
    }

    token_status = validate_token (htp_server, req, repo_id, NULL, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    commit_id[0] = 0;

    sql = "SELECT commit_id FROM Branch WHERE name='master' AND repo_id=?";
    if (seaf_db_statement_foreach_row (seaf->db, sql,
                                       get_branch, commit_id,
                                       1, "string", repo_id) < 0) {
        seaf_warning ("DB error when get branch master.\n");
        evbuffer_add_printf (req->buffer_out,
                             "{\"is_corrupted\": 1}");
        evhtp_send_reply (req, EVHTP_RES_OK);
        goto out;
    }

    if (commit_id[0] == 0) {
        evhtp_send_reply (req, SEAF_HTTP_RES_REPO_DELETED);
        goto out;
    }

    evbuffer_add_printf (req->buffer_out,
                         "{\"is_corrupted\": 0, \"head_commit_id\": \"%s\"}",
                         commit_id);
    evhtp_send_reply (req, EVHTP_RES_OK);

out:
    g_strfreev (parts);
}

static char *
gen_merge_description (SeafRepo *repo,
                       const char *merged_root,
                       const char *p1_root,
                       const char *p2_root)
{
    GList *p;
    GList *results = NULL;
    char *desc;

    diff_merge_roots (repo->store_id, repo->version,
                      merged_root, p1_root, p2_root, &results, TRUE);

    desc = diff_results_to_description (results);

    for (p = results; p; p = p->next) {
        DiffEntry *de = p->data;
        diff_entry_free (de);
    }
    g_list_free (results);

    return desc;
}

static int
fast_forward_or_merge (const char *repo_id,
                       SeafCommit *base,
                       SeafCommit *new_commit,
                       const char *token,
                       gboolean *is_gc_conflict)
{
#define MAX_RETRY_COUNT 3

    SeafRepo *repo = NULL;
    SeafCommit *current_head = NULL, *merged_commit = NULL;
    int retry_cnt = 0;
    int ret = 0;
    char *last_gc_id = NULL;
    gboolean check_gc;
    gboolean gc_conflict = FALSE;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Repo %s doesn't exist.\n", repo_id);
        ret = -1;
        goto out;
    }

    /* In some uploads, no blocks need to be uploaded. For example, deleting
     * a file or folder. In such cases, checkbl won't be called.
     * So the last gc id is not inserted to the database. We don't need to
     * check gc for these cases since no new blocks are uploaded.
     *
     * Note that having a 'NULL' gc id in database is not the same as not having
     * a last gc id record. The former one indicates that, before block upload,
     * no GC has been performed; the latter one indicates no _new_ blocks are
     * being referenced by this new commit.
     */
    if (seaf_db_type(seaf->db) == SEAF_DB_TYPE_SQLITE)
        check_gc = FALSE;
    else
        check_gc = seaf_repo_has_last_gc_id (repo, token);

    if (check_gc) {
        last_gc_id = seaf_repo_get_last_gc_id (repo, token);
        seaf_repo_remove_last_gc_id (repo, token);
    }

retry:
    current_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                   repo->id, repo->version,
                                                   repo->head->commit_id);
    if (!current_head) {
        seaf_warning ("Failed to find head commit of %s.\n", repo_id);
        ret = -1;
        goto out;
    }

    /* Merge if base and head are not the same. */
    if (strcmp (base->commit_id, current_head->commit_id) != 0) {
        MergeOptions opt;
        const char *roots[3];
        char *desc = NULL;

        memset (&opt, 0, sizeof(opt));
        opt.n_ways = 3;
        memcpy (opt.remote_repo_id, repo_id, 36);
        memcpy (opt.remote_head, new_commit->commit_id, 40);
        opt.do_merge = TRUE;

        roots[0] = base->root_id; /* base */
        roots[1] = current_head->root_id; /* head */
        roots[2] = new_commit->root_id;      /* remote */

        if (seaf_merge_trees (repo->store_id, repo->version, 3, roots, &opt) < 0) {
            seaf_warning ("Failed to merge.\n");
            ret = -1;
            goto out;
        }

        if (!opt.conflict)
            desc = g_strdup("Auto merge by system");
        else {
            desc = gen_merge_description (repo,
                                          opt.merged_tree_root,
                                          current_head->root_id,
                                          new_commit->root_id);
            if (!desc)
                desc = g_strdup("Auto merge by system");
        }

        merged_commit = seaf_commit_new(NULL, repo->id, opt.merged_tree_root,
                                        new_commit->creator_name, EMPTY_SHA1,
                                        desc,
                                        0);
        g_free (desc);

        merged_commit->parent_id = g_strdup (current_head->commit_id);
        merged_commit->second_parent_id = g_strdup (new_commit->commit_id);
        merged_commit->new_merge = TRUE;
        if (opt.conflict)
            merged_commit->conflict = TRUE;
        seaf_repo_to_commit (repo, merged_commit);

        if (seaf_commit_manager_add_commit (seaf->commit_mgr, merged_commit) < 0) {
            seaf_warning ("Failed to add commit.\n");
            ret = -1;
            goto out;
        }
    } else {
        seaf_commit_ref (new_commit);
        merged_commit = new_commit;
    }

    seaf_branch_set_commit(repo->head, merged_commit->commit_id);

    gc_conflict = FALSE;

    if (seaf_branch_manager_test_and_update_branch(seaf->branch_mgr,
                                                   repo->head,
                                                   current_head->commit_id,
                                                   check_gc, last_gc_id,
                                                   repo->store_id,
                                                   &gc_conflict) < 0)
    {
        if (gc_conflict) {
            if (is_gc_conflict) {
                *is_gc_conflict = TRUE;
            }
            seaf_warning ("Head branch update for repo %s conflicts with GC.\n",
                          repo_id);
            ret = -1;
            goto out;
        }

        seaf_repo_unref (repo);
        repo = NULL;
        seaf_commit_unref (current_head);
        current_head = NULL;
        seaf_commit_unref (merged_commit);
        merged_commit = NULL;

        if (++retry_cnt <= MAX_RETRY_COUNT) {
            /* Sleep random time between 100 and 1000 millisecs. */
            usleep (g_random_int_range(1, 11) * 100 * 1000);

            repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
            if (!repo) {
                seaf_warning ("Repo %s doesn't exist.\n", repo_id);
                ret = -1;
                goto out;
            }

            goto retry;
        } else {
            ret = -1;
            goto out;
        }
    }

out:
    g_free (last_gc_id);
    seaf_commit_unref (current_head);
    seaf_commit_unref (merged_commit);
    seaf_repo_unref (repo);
    return ret;
}

typedef struct CheckBlockAux {
    GList *file_list;
    const char *store_id;
    int version;
} CheckBlockAux;

static int
check_file_blocks (int n, const char *basedir, SeafDirent *files[], void *data)
{
    Seafile *file = NULL;
    char *block_id;
    int i = 0;
    SeafDirent *file1 = files[0];
    SeafDirent *file2 = files[1];
    CheckBlockAux *aux = (CheckBlockAux*)data;

    if (!file2 || strcmp (file2->id, EMPTY_SHA1) == 0 || (file1 && strcmp (file1->id, file2->id) == 0)) {
        return 0;
    }

    file = seaf_fs_manager_get_seafile (seaf->fs_mgr, aux->store_id, aux->version, file2->id);
    if (!file) {
        return -1;
    }

    for (i = 0; i < file->n_blocks; ++i) {
        block_id = file->blk_sha1s[i];
        if (!seaf_block_manager_block_exists (seaf->block_mgr, aux->store_id, aux->version, block_id)) {
            aux->file_list = g_list_prepend (aux->file_list, g_strdup (file2->name));
            goto out;
        }
    }

out:
    seafile_unref (file);
    return 0;
}

static int
check_dir_cb (int n, const char *basedir, SeafDirent *dirs[], void *data,
              gboolean *recurse)
{
    return 0;
}

static int
check_blocks (SeafRepo *repo, SeafCommit *base, SeafCommit *remote, char **ret_body) {
    DiffOptions opts;
    memset (&opts, 0, sizeof(opts));
    memcpy (opts.store_id, repo->store_id, 36);
    opts.version = repo->version;

    opts.file_cb = check_file_blocks;
    opts.dir_cb = check_dir_cb;

    CheckBlockAux aux;
    memset (&aux, 0, sizeof(aux));
    aux.store_id = repo->store_id;
    aux.version = repo->version;
    opts.data = &aux;

    const char *trees[2];
    trees[0] = base->root_id;
    trees[1] = remote->root_id;

    if (diff_trees (2, trees, &opts) < 0) {
        seaf_warning ("Failed to diff base and remote head for repo %.8s.\n",
                      repo->id);
        return -1;
    }

    if (!aux.file_list) {
        return 0;
    }

    json_t *obj_array = json_array ();
    GList *ptr;
    for (ptr = aux.file_list; ptr; ptr = ptr->next) {
        json_array_append_new (obj_array, json_string (ptr->data));
        g_free (ptr->data);
    }
    g_list_free (aux.file_list);

    *ret_body = json_dumps (obj_array, JSON_COMPACT);
    json_decref (obj_array);

    return -1;
}

gboolean
should_ignore (const char *filename)
{
    char **components = g_strsplit (filename, "/", -1);
    int n_comps = g_strv_length (components);
    int j = 0;
    char *file_name;

    for (; j < n_comps; ++j) {
        file_name = components[j];
        if (g_strcmp0(file_name, "..") == 0) {
            g_strfreev (components);
            return TRUE;
        }
    }
    g_strfreev (components);

    return FALSE;
}

static gboolean
include_invalid_path (SeafCommit *base_commit, SeafCommit *new_commit) {
    GList *diff_entries = NULL;
    gboolean ret = FALSE;

    int rc = diff_commits (base_commit, new_commit, &diff_entries, TRUE);
    if (rc < 0) {
        seaf_warning ("Failed to check invalid path.\n");
        return FALSE;
    }

    GList *ptr;
    DiffEntry *diff_entry;
    for (ptr = diff_entries; ptr; ptr = ptr->next) {
        diff_entry = ptr->data;
        if (diff_entry->new_name) {
            if (should_ignore(diff_entry->new_name)) {
                ret = TRUE;
                break;
            }
        } else {
            if (should_ignore(diff_entry->name)) {
                ret = TRUE;
                break;
            }
        }
    }

    return ret;
}

static void
put_update_branch_cb (evhtp_request_t *req, void *arg)
{
    HttpServer *htp_server = seaf->http_server->priv;
    char **parts;
    char *repo_id;
    char *username = NULL;
    SeafRepo *repo = NULL;
    SeafCommit *new_commit = NULL, *base = NULL;
    char *token = NULL;

    const char *new_commit_id = evhtp_kv_find (req->uri->query, "head");
    if (new_commit_id == NULL || !is_object_id_valid (new_commit_id)) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    repo_id = parts[1];

    int token_status = validate_token (htp_server, req, repo_id, &username, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    int perm_status = check_permission (htp_server, repo_id, username,
                                        "upload", FALSE);
    if (perm_status == EVHTP_RES_FORBIDDEN) {
        evhtp_send_reply (req, EVHTP_RES_FORBIDDEN);
        goto out;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Repo %s is missing or corrupted.\n", repo_id);
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    /* Since this is the last step of upload procedure, commit should exist. */
    new_commit = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                 repo->id, repo->version,
                                                 new_commit_id);
    if (!new_commit) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    base = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                           repo->id, repo->version,
                                           new_commit->parent_id);
    if (!base) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    if (include_invalid_path (base, new_commit)) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    if (seaf_quota_manager_check_quota (seaf->quota_mgr, repo_id) < 0) {
        evhtp_send_reply (req, SEAF_HTTP_RES_NOQUOTA);
        goto out;
    }

    token = get_auth_token (req);

    if (seaf->http_server->verify_client_blocks) {
        char *ret_body = NULL;
        int rc = check_blocks(repo, base, new_commit, &ret_body);
        if (rc < 0) {
            if (ret_body) {
                evbuffer_add (req->buffer_out, ret_body, strlen (ret_body));
            }
            evhtp_send_reply (req, SEAF_HTTP_RES_BLOCK_MISSING);
            g_free (ret_body);
            goto out;
        }
    }

    gboolean gc_conflict = FALSE;
    if (fast_forward_or_merge (repo_id, base, new_commit, token, &gc_conflict) < 0) {
        if (gc_conflict) {
            char *msg = "GC Conflict.\n";
            evbuffer_add (req->buffer_out, msg, strlen (msg));
            evhtp_send_reply (req, EVHTP_RES_CONFLICT);
        } else {
            seaf_warning ("Fast forward merge for repo %s is failed.\n", repo_id);
            evhtp_send_reply (req, EVHTP_RES_SERVERR);
        }
        goto out;
    }

    seaf_repo_manager_merge_virtual_repo (seaf->repo_mgr, repo_id, NULL);

    schedule_repo_size_computation (seaf->size_sched, repo_id);

    evhtp_send_reply (req, EVHTP_RES_OK);

out:
    g_free (token);
    seaf_repo_unref (repo);
    seaf_commit_unref (new_commit);
    seaf_commit_unref (base);
    g_free (username);
    g_strfreev (parts);
}

static void
head_commit_oper_cb (evhtp_request_t *req, void *arg)
{
   htp_method req_method = evhtp_request_get_method (req);

   if (req_method == htp_method_GET) {
       get_head_commit_cb (req, arg);
   } else if (req_method == htp_method_PUT) {
       put_update_branch_cb (req, arg);
   }
}

static gboolean
collect_head_commit_ids (SeafDBRow *row, void *data)
{
    json_t *map = (json_t *)data;
    const char *repo_id = seaf_db_row_get_column_text (row, 0);
    const char *commit_id = seaf_db_row_get_column_text (row, 1);

    json_object_set_new (map, repo_id, json_string(commit_id));

    return TRUE;
}

static void
head_commits_multi_cb (evhtp_request_t *req, void *arg)
{
    size_t list_len;
    json_t *repo_id_array = NULL;
    size_t n, i;
    GString *id_list_str = NULL;
    char *sql = NULL;
    json_t *commit_id_map = NULL;
    char *data = NULL;

    list_len = evbuffer_get_length (req->buffer_in);
    if (list_len == 0) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    char *repo_id_list_con = g_new0 (char, list_len);
    if (!repo_id_list_con) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        seaf_warning ("Failed to allocate %lu bytes memory.\n", list_len);
        goto out;
    }

    json_error_t jerror;
    evbuffer_remove (req->buffer_in, repo_id_list_con, list_len);
    repo_id_array = json_loadb (repo_id_list_con, list_len, 0, &jerror);
    g_free (repo_id_list_con);

    if (!repo_id_array) {
        seaf_warning ("load repo_id_list to json failed, error: %s\n", jerror.text);
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    n = json_array_size (repo_id_array);
    if (n == 0) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    json_t *id;
    id_list_str = g_string_new ("");
    for (i = 0; i < n; ++i) {
        id = json_array_get (repo_id_array, i);
        if (json_typeof(id) != JSON_STRING) {
            evhtp_send_reply (req, EVHTP_RES_BADREQ);
            goto out;
        }
        /* Make sure ids are in UUID format. */
        if (!is_uuid_valid (json_string_value (id))) {
            evhtp_send_reply (req, EVHTP_RES_BADREQ);
            goto out;
        }
        if (i == 0)
            g_string_append_printf (id_list_str, "'%s'", json_string_value(id));
        else
            g_string_append_printf (id_list_str, ",'%s'", json_string_value(id));
    }

    if (seaf_db_type (seaf->db) == SEAF_DB_TYPE_MYSQL)
        sql = g_strdup_printf ("SELECT repo_id, commit_id FROM Branch WHERE name='master' AND repo_id IN (%s) LOCK IN SHARE MODE",
                                id_list_str->str);
    else
        sql = g_strdup_printf ("SELECT repo_id, commit_id FROM Branch WHERE name='master' AND repo_id IN (%s)",
                                id_list_str->str);
    commit_id_map = json_object();
    if (seaf_db_statement_foreach_row (seaf->db, sql,
                                       collect_head_commit_ids, commit_id_map, 0) < 0) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    data = json_dumps (commit_id_map, JSON_COMPACT);
    if (!data) {
        seaf_warning ("failed to dump json.\n");
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    evbuffer_add (req->buffer_out, data, strlen(data));
    evhtp_send_reply (req, EVHTP_RES_OK);

out:
    if (repo_id_array)
        json_decref (repo_id_array);
    if (id_list_str)
        g_string_free (id_list_str, TRUE);
    g_free (sql);
    if (commit_id_map)
        json_decref (commit_id_map);
    if (data)
        free (data);
}

static void
get_commit_info_cb (evhtp_request_t *req, void *arg)
{
    HttpServer *htp_server = seaf->http_server->priv;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];
    char *commit_id = parts[3];
    char *username = NULL;

    int token_status = validate_token (htp_server, req, repo_id, &username, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    int perm_status = check_permission (htp_server, repo_id, username,
                                        "download", FALSE);
    if (perm_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, EVHTP_RES_FORBIDDEN);
        goto out;
    }

    char *data = NULL;
    int len;

    int ret = seaf_obj_store_read_obj (seaf->commit_mgr->obj_store, repo_id, 1,
                                       commit_id, (void **)&data, &len);
    if (ret < 0) {
        seaf_warning ("Get commit info failed: commit %s is missing.\n", commit_id);
        evhtp_send_reply (req, EVHTP_RES_NOTFOUND);
        goto out;
    }

    evbuffer_add (req->buffer_out, data, len);
    evhtp_send_reply (req, EVHTP_RES_OK);
    g_free (data);

out:
    g_free (username);
    g_strfreev (parts);
}

static int
save_last_gc_id (const char *repo_id, const char *token)
{
    SeafRepo *repo;
    char *gc_id;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Failed to find repo %s.\n", repo_id);
        return -1;
    }

    gc_id = seaf_repo_get_current_gc_id (repo);

    seaf_repo_set_last_gc_id (repo, token, gc_id);

    g_free (gc_id);
    seaf_repo_unref (repo);

    return 0;
}

static void
put_commit_cb (evhtp_request_t *req, void *arg)
{
    HttpServer *htp_server = seaf->http_server->priv;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];
    char *commit_id = parts[3];
    char *username = NULL;
    void *data = NULL;

    int token_status = validate_token (htp_server, req, repo_id, &username, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    int perm_status = check_permission (htp_server, repo_id, username,
                                        "upload", FALSE);
    if (perm_status == EVHTP_RES_FORBIDDEN) {
        evhtp_send_reply (req, EVHTP_RES_FORBIDDEN);
        goto out;
    }

    int con_len = evbuffer_get_length (req->buffer_in);
    if(con_len == 0) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    data = g_new0 (char, con_len);
    if (!data) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        seaf_warning ("Failed to allocate %d bytes memory.\n", con_len);
        goto out;
    }

    evbuffer_remove (req->buffer_in, data, con_len);
    SeafCommit *commit = seaf_commit_from_data (commit_id, (char *)data, con_len);
    if (!commit) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    if (strcmp (commit->repo_id, repo_id) != 0) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    if (seaf_commit_manager_add_commit (seaf->commit_mgr, commit) < 0) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
    } else {
        /* Last GCID must be set before checking blocks. However, in http sync,
         * block list may be sent in multiple http requests. There is no way to
         * tell which one is the first check block request.
         * 
         * So we set the last GCID just before replying to upload commit
         * request. One consequence is that even if the following upload
         * doesn't upload new blocks, we still need to check gc conflict in
         * update-branch request. Since gc conflict is a rare case, this solution
         * won't introduce many more gc conflicts.
         */
        char *token = get_auth_token (req);
        if (save_last_gc_id (repo_id, token) < 0) {
            evhtp_send_reply (req, EVHTP_RES_SERVERR);
        } else
            evhtp_send_reply (req, EVHTP_RES_OK);
        g_free (token);
    }
    seaf_commit_unref (commit);

out:
    g_free (username);
    g_free (data);
    g_strfreev (parts);
}

static void
commit_oper_cb (evhtp_request_t *req, void *arg)
{
    htp_method req_method = evhtp_request_get_method (req);

    if (req_method == htp_method_PUT) {
        put_commit_cb (req, arg);
    } else if (req_method == htp_method_GET) {
        get_commit_info_cb (req, arg);
    }
}

static int
collect_file_ids (int n, const char *basedir, SeafDirent *files[], void *data)
{
    SeafDirent *file1 = files[0];
    SeafDirent *file2 = files[1];
    GList **pret = data;

    if (file1 && (!file2 || strcmp(file1->id, file2->id) != 0) &&
        strcmp (file1->id, EMPTY_SHA1) != 0)
        *pret = g_list_prepend (*pret, g_strdup(file1->id));

    return 0;
}

static int
collect_file_ids_nop (int n, const char *basedir, SeafDirent *files[], void *data)
{
    return 0;
}

static int
collect_dir_ids (int n, const char *basedir, SeafDirent *dirs[], void *data,
                 gboolean *recurse)
{
    SeafDirent *dir1 = dirs[0];
    SeafDirent *dir2 = dirs[1];
    GList **pret = data;

    if (dir1 && (!dir2 || strcmp(dir1->id, dir2->id) != 0) &&
        strcmp (dir1->id, EMPTY_SHA1) != 0)
        *pret = g_list_prepend (*pret, g_strdup(dir1->id));

    return 0;
}

static int
calculate_send_object_list (SeafRepo *repo,
                            const char *server_head,
                            const char *client_head,
                            gboolean dir_only,
                            GList **results)
{
    SeafCommit *remote_head = NULL, *master_head = NULL;
    char *remote_head_root;
    int ret = 0;

    *results = NULL;

    master_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                  repo->id, repo->version,
                                                  server_head);
    if (!master_head) {
        seaf_warning ("Server head commit %s:%s not found.\n", repo->id, server_head);
        return -1;
    }

    if (client_head) {
        remote_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                      repo->id, repo->version,
                                                      client_head);
        if (!remote_head) {
            ret = -1;
            goto out;
        }
        remote_head_root = remote_head->root_id;
    } else
        remote_head_root = EMPTY_SHA1;

    /* Diff won't traverse the root object itself. */
    if (strcmp (remote_head_root, master_head->root_id) != 0 &&
        strcmp (master_head->root_id, EMPTY_SHA1) != 0)
        *results = g_list_prepend (*results, g_strdup(master_head->root_id));

    DiffOptions opts;
    memset (&opts, 0, sizeof(opts));
    memcpy (opts.store_id, repo->store_id, 36);
    opts.version = repo->version;
    if (!dir_only)
        opts.file_cb = collect_file_ids;
    else
        opts.file_cb = collect_file_ids_nop;
    opts.dir_cb = collect_dir_ids;
    opts.data = results;

    const char *trees[2];
    trees[0] = master_head->root_id;
    trees[1] = remote_head_root;
    if (diff_trees (2, trees, &opts) < 0) {
        seaf_warning ("Failed to diff remote and master head for repo %.8s.\n",
                      repo->id);
        string_list_free (*results);
        ret = -1;
    }

out:
    seaf_commit_unref (remote_head);
    seaf_commit_unref (master_head);
    return ret;
}

static void
get_fs_obj_id_cb (evhtp_request_t *req, void *arg)
{
    HttpServer *htp_server = seaf->http_server->priv;
    char **parts;
    char *repo_id;
    SeafRepo *repo = NULL;
    gboolean dir_only = FALSE;
    char *username = NULL;

    const char *server_head = evhtp_kv_find (req->uri->query, "server-head");
    if (server_head == NULL || !is_object_id_valid (server_head)) {
        char *error = "Invalid server-head parameter.\n";
        seaf_warning ("%s", error);
        evbuffer_add (req->buffer_out, error, strlen (error));
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    const char *client_head = evhtp_kv_find (req->uri->query, "client-head");
    if (client_head && !is_object_id_valid (client_head)) {
        char *error = "Invalid client-head parameter.\n";
        seaf_warning ("%s", error);
        evbuffer_add (req->buffer_out, error, strlen (error));
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    const char *dir_only_arg = evhtp_kv_find (req->uri->query, "dir-only");
    if (dir_only_arg)
        dir_only = TRUE;

    parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    repo_id = parts[1];

    int token_status = validate_token (htp_server, req, repo_id, &username, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    int perm_status = check_permission (htp_server, repo_id, username,
                                        "download", FALSE);
    if (perm_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, EVHTP_RES_FORBIDDEN);
        goto out;
    }

    GList *list = NULL, *ptr;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Failed to find repo %.8s.\n", repo_id);
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    if (calculate_send_object_list (repo, server_head, client_head, dir_only, &list) < 0) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    json_t *obj_array = json_array ();

    for (ptr = list; ptr; ptr = ptr->next) {
        json_array_append_new (obj_array, json_string (ptr->data));
        g_free (ptr->data);
    }
    g_list_free (list);

    char *obj_list = json_dumps (obj_array, JSON_COMPACT);
    evbuffer_add (req->buffer_out, obj_list, strlen (obj_list));
    evhtp_send_reply (req, EVHTP_RES_OK);

    g_free (obj_list);
    json_decref (obj_array);

out:
    g_free (username);
    g_strfreev (parts);
    seaf_repo_unref (repo);
}

typedef struct ComputeObjTask {
    HttpServer *htp_server;
    char *token;
    char *repo_id;
    char *client_head;
    char *server_head;
    gboolean dir_only;
} ComputeObjTask;

typedef struct CalObjResult {
    GList *list;
    gboolean done;
} CalObjResult;

static void
free_compute_obj_task(ComputeObjTask *task)
{
    if (!task)
        return;

    if (task->token)
        g_free(task->token);
    if (task->repo_id)
        g_free(task->repo_id);
    if (task->client_head)
        g_free(task->client_head);
    if (task->server_head)
        g_free(task->server_head);
    g_free(task);
}

static void
free_obj_cal_result (gpointer data)
{
    CalObjResult *result = (CalObjResult *)data;
    if (!result)
        return;

    if (result->list)
        g_list_free (result->list);

    g_free(result);
}

static void
compute_fs_obj_id (gpointer ptask, gpointer ppara)
{
    SeafRepo *repo = NULL;
    ComputeObjTask *task = ptask;
    const char *client_head = task->client_head;
    const char *server_head = task->server_head;
    char *repo_id = task->repo_id;
    gboolean dir_only = task->dir_only;
    HttpServer *htp_server = task->htp_server;
    CalObjResult *result = NULL;

    pthread_mutex_lock (&htp_server->fs_obj_ids_lock);
    result = g_hash_table_lookup (htp_server->fs_obj_ids, task->token);
    pthread_mutex_unlock (&htp_server->fs_obj_ids_lock);
    if (!result) {
        goto out;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Failed to find repo %.8s.\n", repo_id);
        goto out;
    }

    if (calculate_send_object_list (repo, server_head, client_head, dir_only, &result->list) < 0) {
        pthread_mutex_lock (&htp_server->fs_obj_ids_lock);
        g_hash_table_remove (htp_server->fs_obj_ids, task->token);
        pthread_mutex_unlock (&htp_server->fs_obj_ids_lock);
        goto out;
    }

    result->done = TRUE;
out:
    seaf_repo_unref (repo);
    free_compute_obj_task(task);
}

static void
start_fs_obj_id_cb (evhtp_request_t *req, void *arg)
{
    HttpServer *htp_server = seaf->http_server->priv;
    char **parts;
    char *repo_id;
    gboolean dir_only = FALSE;
    json_t *obj;

    const char *server_head = evhtp_kv_find (req->uri->query, "server-head");
    if (server_head == NULL || !is_object_id_valid (server_head)) {
        char *error = "Invalid server-head parameter.\n";
        evbuffer_add (req->buffer_out, error, strlen (error));
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    const char *client_head = evhtp_kv_find (req->uri->query, "client-head");
    if (client_head && !is_object_id_valid (client_head)) {
        char *error = "Invalid client-head parameter.\n";
        evbuffer_add (req->buffer_out, error, strlen (error));
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    const char *dir_only_arg = evhtp_kv_find (req->uri->query, "dir-only");
    if (dir_only_arg)
        dir_only = TRUE;

    parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    repo_id = parts[1];

    int token_status = validate_token (htp_server, req, repo_id, NULL, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    char uuid[37];
    char *new_token;
    gen_uuid_inplace (uuid);
    new_token = g_strndup(uuid, FS_ID_LIST_TOKEN_LEN);

    CalObjResult *result = g_new0(CalObjResult, 1);
    if (!result) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }
    result->done = FALSE;

    ComputeObjTask *task = g_new0 (ComputeObjTask, 1);
    if (!task) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    task->token = new_token;
    task->dir_only = dir_only;
    task->htp_server = htp_server;
    task->repo_id = g_strdup(repo_id);
    task->client_head = g_strdup(client_head);
    task->server_head = g_strdup(server_head);

    pthread_mutex_lock (&htp_server->fs_obj_ids_lock);
    g_hash_table_insert (htp_server->fs_obj_ids, g_strdup(task->token), result);
    pthread_mutex_unlock (&htp_server->fs_obj_ids_lock);
    g_thread_pool_push (htp_server->compute_fs_obj_id_pool, task, NULL);
    obj = json_object ();
    json_object_set_new (obj, "token", json_string (new_token));

    char *json_str = json_dumps (obj, JSON_COMPACT);
    evbuffer_add (req->buffer_out, json_str, strlen(json_str));
    evhtp_send_reply (req, EVHTP_RES_OK);

    g_free (json_str);
    json_decref (obj);
out:
    g_strfreev (parts);
}

static void
query_fs_obj_id_cb (evhtp_request_t *req, void *arg)
{
    json_t *obj;
    const char *token = NULL;
    CalObjResult *result = NULL;
    char **parts;
    char *repo_id = NULL;
    HttpServer *htp_server = seaf->http_server->priv;

    parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    repo_id = parts[1];

    int token_status = validate_token (htp_server, req, repo_id, NULL, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    token = evhtp_kv_find (req->uri->query, "token");
    if (!token || strlen(token)!=FS_ID_LIST_TOKEN_LEN) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    obj = json_object ();

    pthread_mutex_lock (&htp_server->fs_obj_ids_lock);
    result = g_hash_table_lookup (htp_server->fs_obj_ids, token);
    if (!result) {
        pthread_mutex_unlock (&htp_server->fs_obj_ids_lock);
        evhtp_send_reply (req, EVHTP_RES_NOTFOUND);
        goto out;
    } else {
        if (!result->done) {
            json_object_set_new (obj, "success", json_false());
        } else {
            json_object_set_new (obj, "success", json_true());
        }
    }
    pthread_mutex_unlock (&htp_server->fs_obj_ids_lock);

    json_object_set_new (obj, "token", json_string (token));

    char *json_str = json_dumps (obj, JSON_COMPACT);
    evbuffer_add (req->buffer_out, json_str, strlen(json_str));
    evhtp_send_reply (req, EVHTP_RES_OK);

    g_free (json_str);

out:
    if (obj)
        json_decref (obj);
    g_strfreev (parts);
    return;
}

static void
retrieve_fs_obj_id_cb (evhtp_request_t *req, void *arg)
{
    char **parts;
    const char *token = NULL;
    char *repo_id = NULL;
    GList *list = NULL;
    CalObjResult *result = NULL;
    HttpServer *htp_server = seaf->http_server->priv;

    parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    repo_id = parts[1];

    int token_status = validate_token (htp_server, req, repo_id, NULL, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    token = evhtp_kv_find (req->uri->query, "token");
    if (!token || strlen(token)!=FS_ID_LIST_TOKEN_LEN) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    pthread_mutex_lock (&htp_server->fs_obj_ids_lock);
    result = g_hash_table_lookup (htp_server->fs_obj_ids, token);
    if (!result) {
        pthread_mutex_unlock (&htp_server->fs_obj_ids_lock);
        evhtp_send_reply (req, EVHTP_RES_NOTFOUND);

        return;
    }
    if (!result->done) {
        pthread_mutex_unlock (&htp_server->fs_obj_ids_lock);

        char *error = "The cauculation task is not completed.\n";
        evbuffer_add (req->buffer_out, error, strlen(error));
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }
    list = result->list;
    pthread_mutex_unlock (&htp_server->fs_obj_ids_lock);

    GList *ptr;
    json_t *obj_array = json_array ();

    for (ptr = list; ptr; ptr = ptr->next) {
        json_array_append_new (obj_array, json_string (ptr->data));
        g_free (ptr->data);
    }

    pthread_mutex_lock (&htp_server->fs_obj_ids_lock);
    g_hash_table_remove (htp_server->fs_obj_ids, token);
    pthread_mutex_unlock (&htp_server->fs_obj_ids_lock);

    char *obj_list = json_dumps (obj_array, JSON_COMPACT);
    evbuffer_add (req->buffer_out, obj_list, strlen (obj_list));
    evhtp_send_reply (req, EVHTP_RES_OK);

    g_free (obj_list);
    json_decref (obj_array);

out:
    g_strfreev (parts);
    return;
}

static void
get_block_cb (evhtp_request_t *req, void *arg)
{
    const char *repo_id = NULL;
    char *block_id = NULL;
    char *store_id = NULL;
    HttpServer *htp_server = seaf->http_server->priv;
    BlockMetadata *blk_meta = NULL;
    char *username = NULL;

    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    repo_id = parts[1];
    block_id = parts[3];

    int token_status = validate_token (htp_server, req, repo_id, &username, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    int perm_status = check_permission (htp_server, repo_id, username,
                                        "download", FALSE);
    if (perm_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, EVHTP_RES_FORBIDDEN);
        goto out;
    }

    store_id = get_repo_store_id (htp_server, repo_id);
    if (!store_id) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    blk_meta = seaf_block_manager_stat_block (seaf->block_mgr,
                                              store_id, 1, block_id);
    if (blk_meta == NULL || blk_meta->size <= 0) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    BlockHandle *blk_handle = NULL;
    blk_handle = seaf_block_manager_open_block(seaf->block_mgr,
                                               store_id, 1, block_id, BLOCK_READ);
    if (!blk_handle) {
        seaf_warning ("Failed to open block %.8s:%s.\n", store_id, block_id);
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    void *block_con = g_new0 (char, blk_meta->size);
    if (!block_con) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        seaf_warning ("Failed to allocate %d bytes memeory.\n", blk_meta->size);
        goto free_handle;
    }

    int rsize = seaf_block_manager_read_block (seaf->block_mgr,
                                               blk_handle, block_con,
                                               blk_meta->size);
    if (rsize != blk_meta->size) {
        seaf_warning ("Failed to read block %.8s:%s.\n", store_id, block_id);
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
    } else {
        evbuffer_add (req->buffer_out, block_con, blk_meta->size);
        evhtp_send_reply (req, EVHTP_RES_OK);
    }
    g_free (block_con);
    send_statistic_msg (store_id, username, "sync-file-download", (guint64)rsize);

free_handle:
    seaf_block_manager_close_block (seaf->block_mgr, blk_handle);
    seaf_block_manager_block_handle_free (seaf->block_mgr, blk_handle);

out:
    g_free (username);
    g_free (blk_meta);
    g_free (store_id);
    g_strfreev (parts);
}

static void
put_send_block_cb (evhtp_request_t *req, void *arg)
{
    const char *repo_id = NULL;
    char *block_id = NULL;
    char *store_id = NULL;
    char *username = NULL;
    HttpServer *htp_server = seaf->http_server->priv;
    char **parts = NULL;
    void *blk_con = NULL;

    parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    repo_id = parts[1];
    block_id = parts[3];

    int token_status = validate_token (htp_server, req, repo_id, &username, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    int perm_status = check_permission (htp_server, repo_id, username,
                                        "upload", FALSE);
    if (perm_status == EVHTP_RES_FORBIDDEN) {
        evhtp_send_reply (req, EVHTP_RES_FORBIDDEN);
        goto out;
    }

    store_id = get_repo_store_id (htp_server, repo_id);
    if (!store_id) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    int blk_len = evbuffer_get_length (req->buffer_in);
    if (blk_len == 0) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    blk_con = g_new0 (char, blk_len);
    if (!blk_con) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        seaf_warning ("Failed to allocate %d bytes memory.\n", blk_len);
        goto out;
    }

    evbuffer_remove (req->buffer_in, blk_con, blk_len);

    BlockHandle *blk_handle = NULL;
    blk_handle = seaf_block_manager_open_block (seaf->block_mgr,
                                                store_id, 1, block_id, BLOCK_WRITE);
    if (blk_handle == NULL) {
        seaf_warning ("Failed to open block %.8s:%s.\n", store_id, block_id);
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    if (seaf_block_manager_write_block (seaf->block_mgr, blk_handle,
                                        blk_con, blk_len) != blk_len) {
        seaf_warning ("Failed to write block %.8s:%s.\n", store_id, block_id);
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        seaf_block_manager_close_block (seaf->block_mgr, blk_handle);
        seaf_block_manager_block_handle_free (seaf->block_mgr, blk_handle);
        goto out;
    }

    if (seaf_block_manager_close_block (seaf->block_mgr, blk_handle) < 0) {
        seaf_warning ("Failed to close block %.8s:%s.\n", store_id, block_id);
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        seaf_block_manager_block_handle_free (seaf->block_mgr, blk_handle);
        goto out;
    }

    if (seaf_block_manager_commit_block (seaf->block_mgr,
                                         blk_handle) < 0) {
        seaf_warning ("Failed to commit block %.8s:%s.\n", store_id, block_id);
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        seaf_block_manager_block_handle_free (seaf->block_mgr, blk_handle);
        goto out;
    }

    seaf_block_manager_block_handle_free (seaf->block_mgr, blk_handle);

    evhtp_send_reply (req, EVHTP_RES_OK);

    send_statistic_msg (store_id, username, "sync-file-upload", (guint64)blk_len);

out:
    g_free (username);
    g_free (store_id);
    g_strfreev (parts);
    g_free (blk_con);
}

static void
block_oper_cb (evhtp_request_t *req, void *arg)
{
    htp_method req_method = evhtp_request_get_method (req);

    if (req_method == htp_method_GET) {
        get_block_cb (req, arg);
    } else if (req_method == htp_method_PUT) {
        put_send_block_cb (req, arg);
    }
}

static void
post_check_exist_cb (evhtp_request_t *req, void *arg, CheckExistType type)
{
    HttpServer *htp_server = seaf->http_server->priv;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];
    char *store_id = NULL;
    char *username = NULL;

    int token_status = validate_token (htp_server, req, repo_id, &username, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    int perm_status = check_permission (htp_server, repo_id, username,
                                        "download", FALSE);
    if (perm_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, EVHTP_RES_FORBIDDEN);
        goto out;
    }

    store_id = get_repo_store_id (htp_server, repo_id);
    if (!store_id) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    size_t list_len = evbuffer_get_length (req->buffer_in);
    if (list_len == 0) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    char *obj_list_con = g_new0 (char, list_len);
    if (!obj_list_con) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        seaf_warning ("Failed to allocate %zu bytes memory.\n", list_len);
        goto out;
    }

    json_error_t jerror;
    evbuffer_remove (req->buffer_in, obj_list_con, list_len);
    json_t *obj_array = json_loadb (obj_list_con, list_len, 0, &jerror);
    g_free (obj_list_con);

    if (!obj_array) {
        seaf_warning ("dump obj_id to json failed, error: %s\n", jerror.text);
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    json_t *obj = NULL;
    gboolean ret = TRUE;
    const char *obj_id = NULL;
    int index = 0;

    int array_size = json_array_size (obj_array);
    json_t *needed_objs = json_array();

    for (; index < array_size; ++index) {
        obj = json_array_get (obj_array, index);
        obj_id = json_string_value (obj);
        if (!is_object_id_valid (obj_id))
            continue;

        if (type == CHECK_FS_EXIST) {
            ret = seaf_fs_manager_object_exists (seaf->fs_mgr, store_id, 1,
                                                 obj_id);
        } else if (type == CHECK_BLOCK_EXIST) {
            ret = seaf_block_manager_block_exists (seaf->block_mgr, store_id, 1,
                                                   obj_id);
        }

        if (!ret) {
            json_array_append (needed_objs, obj);
        }
    }

    char *ret_array = json_dumps (needed_objs, JSON_COMPACT);
    evbuffer_add (req->buffer_out, ret_array, strlen (ret_array));
    evhtp_send_reply (req, EVHTP_RES_OK);

    g_free (ret_array);
    json_decref (needed_objs);
    json_decref (obj_array);

out:
    g_free (username);
    g_free (store_id);
    g_strfreev (parts);
}

static void
post_check_fs_cb (evhtp_request_t *req, void *arg)
{
   post_check_exist_cb (req, arg, CHECK_FS_EXIST);
}

static void
post_check_block_cb (evhtp_request_t *req, void *arg)
{
   post_check_exist_cb (req, arg, CHECK_BLOCK_EXIST);
}

static void
post_recv_fs_cb (evhtp_request_t *req, void *arg)
{
    HttpServer *htp_server = seaf->http_server->priv;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    const char *repo_id = parts[1];
    char *store_id = NULL;
    char *username = NULL;
    FsHdr *hdr = NULL;

    int token_status = validate_token (htp_server, req, repo_id, &username, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    int perm_status = check_permission (htp_server, repo_id, username,
                                        "upload", FALSE);
    if (perm_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, EVHTP_RES_FORBIDDEN);
        goto out;
    }

    store_id = get_repo_store_id (htp_server, repo_id);
    if (!store_id) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    int fs_con_len = evbuffer_get_length (req->buffer_in);
    if (fs_con_len < sizeof(FsHdr)) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    hdr = g_new0 (FsHdr, 1);
    if (!hdr) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    char obj_id[41];
    void *obj_con = NULL;
    int con_len;

    while (fs_con_len > 0) {
        if (fs_con_len < sizeof(FsHdr)) {
            seaf_warning ("Bad fs object content format from %.8s:%s.\n",
                          repo_id, username);
            evhtp_send_reply (req, EVHTP_RES_BADREQ);
            break;
        }

        evbuffer_remove (req->buffer_in, hdr, sizeof(FsHdr));
        con_len = ntohl (hdr->obj_size);
        memcpy (obj_id, hdr->obj_id, 40);
        obj_id[40] = 0;

        if (!is_object_id_valid (obj_id)) {
            evhtp_send_reply (req, EVHTP_RES_BADREQ);
            break;
        }

        obj_con = g_new0 (char, con_len);
        if (!obj_con) {
            evhtp_send_reply (req, EVHTP_RES_SERVERR);
            break;
        }
        evbuffer_remove (req->buffer_in, obj_con, con_len);

        if (seaf_obj_store_write_obj (seaf->fs_mgr->obj_store,
                                      store_id, 1, obj_id, obj_con,
                                      con_len, FALSE) < 0) {
            seaf_warning ("Failed to write fs object %.8s to disk.\n",
                          obj_id);
            g_free (obj_con);
            evhtp_send_reply (req, EVHTP_RES_SERVERR);
            break;
        }

        fs_con_len -= (con_len + sizeof(FsHdr));
        g_free (obj_con);
    }

    if (fs_con_len == 0) {
        evhtp_send_reply (req, EVHTP_RES_OK);
    }

out:
    g_free (store_id);
    g_free (hdr);
    g_free (username);
    g_strfreev (parts);
}

#define MAX_OBJECT_PACK_SIZE (1 << 20) /* 1MB */

static void
post_pack_fs_cb (evhtp_request_t *req, void *arg)
{
    HttpServer *htp_server = seaf->http_server->priv;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    const char *repo_id = parts[1];
    char *store_id = NULL;
    char *username = NULL;

    int token_status = validate_token (htp_server, req, repo_id, &username, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    int perm_status = check_permission (htp_server, repo_id, username,
                                        "download", FALSE);
    if (perm_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, EVHTP_RES_FORBIDDEN);
        goto out;
    }
    store_id = get_repo_store_id (htp_server, repo_id);
    if (!store_id) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    int fs_id_list_len = evbuffer_get_length (req->buffer_in);
    if (fs_id_list_len == 0) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    char *fs_id_list = g_new0 (char, fs_id_list_len);
    if (!fs_id_list) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        seaf_warning ("Failed to allocate %d bytes memory.\n", fs_id_list_len);
        goto out;
    }

    json_error_t jerror;
    evbuffer_remove (req->buffer_in, fs_id_list, fs_id_list_len);
    json_t *fs_id_array = json_loadb (fs_id_list, fs_id_list_len, 0, &jerror);

    g_free (fs_id_list);

    if (!fs_id_array) {
        seaf_warning ("dump fs obj_id from json failed, error: %s\n", jerror.text);
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    json_t *obj = NULL;
    const char *obj_id = NULL;
    int index = 0;
    void *fs_data = NULL;
    int data_len;
    int data_len_net;
    int total_size = 0;

    int array_size = json_array_size (fs_id_array);

    for (; index < array_size; ++index) {
        obj = json_array_get (fs_id_array, index);
        obj_id = json_string_value (obj);

        if (!is_object_id_valid (obj_id)) {
            seaf_warning ("Invalid fs id %s.\n", obj_id);
            evhtp_send_reply (req, EVHTP_RES_BADREQ);
            json_decref (fs_id_array);
            goto out;
        }
        if (seaf_obj_store_read_obj (seaf->fs_mgr->obj_store, store_id, 1,
                                     obj_id, &fs_data, &data_len) < 0) {
            seaf_warning ("Failed to read seafile object %s:%s.\n", store_id, obj_id);
            evhtp_send_reply (req, EVHTP_RES_SERVERR);
            json_decref (fs_id_array);
            goto out;
        }

        evbuffer_add (req->buffer_out, obj_id, 40);
        data_len_net = htonl (data_len);
        evbuffer_add (req->buffer_out, &data_len_net, 4);
        evbuffer_add (req->buffer_out, fs_data, data_len);

        total_size += data_len;
        g_free (fs_data);

        if (total_size >= MAX_OBJECT_PACK_SIZE)
            break;
    }

    evhtp_send_reply (req, EVHTP_RES_OK);

    json_decref (fs_id_array);
out:
    g_free (username);
    g_free (store_id);
    g_strfreev (parts);
}

static void
get_block_map_cb (evhtp_request_t *req, void *arg)
{
    const char *repo_id = NULL;
    char *file_id = NULL;
    char *store_id = NULL;
    HttpServer *htp_server = seaf->http_server->priv;
    Seafile *file = NULL;
    char *block_id;
    BlockMetadata *blk_meta = NULL;
    json_t *array = NULL;
    char *data = NULL;
    char *username = NULL;

    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    repo_id = parts[1];
    file_id = parts[3];

    int token_status = validate_token (htp_server, req, repo_id, &username, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    int perm_status = check_permission (htp_server, repo_id, username,
                                        "download", FALSE);
    if (perm_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, EVHTP_RES_FORBIDDEN);
        goto out;
    }

    store_id = get_repo_store_id (htp_server, repo_id);
    if (!store_id) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    file = seaf_fs_manager_get_seafile (seaf->fs_mgr, store_id, 1, file_id);
    if (!file) {
        evhtp_send_reply (req, EVHTP_RES_NOTFOUND);
        goto out;
    }

    array = json_array ();

    int i;
    for (i = 0; i < file->n_blocks; ++i) {
        block_id = file->blk_sha1s[i];
        blk_meta = seaf_block_manager_stat_block (seaf->block_mgr,
                                                  store_id, 1, block_id);
        if (blk_meta == NULL) {
            seaf_warning ("Failed to find block %s/%s\n", store_id, block_id);
            evhtp_send_reply (req, EVHTP_RES_SERVERR);
            g_free (blk_meta);
            goto out;
        }
        json_array_append_new (array, json_integer(blk_meta->size));
        g_free (blk_meta);
    }

    data = json_dumps (array, JSON_COMPACT);
    evbuffer_add (req->buffer_out, data, strlen (data));
    evhtp_send_reply (req, EVHTP_RES_OK);

out:
    g_free (username);
    g_free (store_id);
    seafile_unref (file);
    if (array)
        json_decref (array);
    if (data)
        free (data);
    g_strfreev (parts);
}

static void
get_jwt_token_cb (evhtp_request_t *req, void *arg)
{
    const char *repo_id = NULL;
    HttpServer *htp_server = seaf->http_server->priv;
    json_t *obj = NULL;
    char *data = NULL;
    char *username = NULL;
    char *jwt_token = NULL;

    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    repo_id = parts[1];

    int token_status = validate_token (htp_server, req, repo_id, &username, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    if (!seaf->notif_mgr) {
        evhtp_send_reply (req, EVHTP_RES_NOTFOUND);
        goto out;
    }

    jwt_token = seaf_gen_notif_server_jwt (repo_id, username);
    if (!jwt_token) {
        seaf_warning ("Failed to gen jwt token for repo %s\n", repo_id);
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    obj = json_object ();
    json_object_set_new (obj, "jwt_token", json_string (jwt_token));

    data = json_dumps (obj, JSON_COMPACT);
    evbuffer_add (req->buffer_out, data, strlen (data));
    evhtp_send_reply (req, EVHTP_RES_OK);

out:
    g_free (jwt_token);
    g_free (username);
    if (obj)
        json_decref (obj);
    if (data)
        free (data);
    g_strfreev (parts);
}

static json_t *
fill_obj_from_seafilerepo (SeafileRepo *srepo, GHashTable *table)
{
    int version = 0;
    char *repo_id = NULL;
    char *commit_id = NULL;
    char *repo_name = NULL;
    char *permission = NULL;
    char *owner = NULL;
    char *type = NULL;
    gint64 last_modify = 0;
    json_t *obj = NULL;

    g_object_get (srepo, "version", &version,
                         "id", &repo_id,
                         "head_cmmt_id", &commit_id,
                         "name", &repo_name,
                         "last_modify", &last_modify,
                         "permission", &permission,
                         "user", &owner,
                         "repo_type", &type,
                         NULL);

    if (!repo_id)
        goto out;
    if (type) {
        g_free (repo_id);
        goto out;
    }
    //the repo_id will be free when the table is destroyed.
    if (g_hash_table_lookup (table, repo_id)) {
        g_free (repo_id);
        goto out;
    }
    g_hash_table_insert (table, repo_id, repo_id);
    obj = json_object ();
    json_object_set_new (obj, "version", json_integer (version));
    json_object_set_new (obj, "id", json_string (repo_id));
    json_object_set_new (obj, "head_commit_id", json_string (commit_id));
    json_object_set_new (obj, "name", json_string (repo_name));
    json_object_set_new (obj, "mtime", json_integer (last_modify));
    json_object_set_new (obj, "permission", json_string (permission));
    json_object_set_new (obj, "owner", json_string (owner));

out:
    g_free (commit_id);
    g_free (repo_name);
    g_free (permission);
    g_free (owner);
    g_free (type);
    return obj;
}

static GHashTable *
filter_group_repos (GList *repos)
{
    if (!repos)
        return NULL;

    SeafileRepo *srepo = NULL;
    SeafileRepo *srepo_tmp = NULL;
    GList *iter;
    GHashTable *table = NULL;
    char *permission = NULL;
    char *permission_prev = NULL;
    char *repo_id = NULL;
    char *type = NULL;

    table = g_hash_table_new_full (g_str_hash, g_str_equal,
                                   g_free,
                                   NULL);

    for (iter = repos; iter; iter = iter->next) {
        srepo = iter->data;
        g_object_get (srepo, "id", &repo_id,
                             "permission", &permission,
                             "repo_type", &type,
                             NULL);
        if (type) {
            g_free (repo_id);
            g_free (permission);
            g_free (type);
            g_object_unref (srepo);
            continue;
        }
        srepo_tmp = g_hash_table_lookup (table, repo_id);
        if (srepo_tmp) {
            g_object_get (srepo_tmp, "permission", &permission_prev,
                          NULL);
            if (g_strcmp0 (permission, "rw") == 0 && g_strcmp0 (permission_prev, "r") == 0) {
                g_object_unref (srepo_tmp);
                g_hash_table_remove (table, repo_id);
                g_hash_table_insert (table, g_strdup (repo_id), srepo);
            } else {
                g_object_unref (srepo);
            }
            g_free (permission_prev);
        } else {
            g_hash_table_insert (table, g_strdup (repo_id), srepo);
        }
        g_free (repo_id);
        g_free (permission);
        g_free (type);
    }

    return table;
}

static void
group_repos_to_json (json_t *repo_array, GHashTable *group_repos,
                     GHashTable *obtained_repos)
{
    GHashTableIter iter;
    gpointer key, value;
    SeafileRepo *srepo = NULL;
    json_t *obj;

    g_hash_table_iter_init (&iter, group_repos);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        srepo = value;
        obj = fill_obj_from_seafilerepo (srepo, obtained_repos);
        if (!obj) {
            g_object_unref (srepo);
            continue;
        }
        json_object_set_new (obj, "type", json_string ("grepo"));

        json_array_append_new (repo_array, obj);
        g_object_unref (srepo);
    }
}

static void
get_accessible_repo_list_cb (evhtp_request_t *req, void *arg)
{
    GList *iter;
    HttpServer *htp_server = seaf->http_server->priv;
    SeafRepo *repo = NULL;
    char *user = NULL;
    GList *repos = NULL;
    int org_id = -1;
    const char *repo_id = evhtp_kv_find (req->uri->query, "repo_id");

    if (!repo_id || !is_uuid_valid (repo_id)) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        seaf_warning ("Invalid repo id.\n");
        return;
    }

    int token_status = validate_token (htp_server, req, repo_id, &user, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        return;
    }

    json_t *obj;
    json_t *repo_array = json_array ();

    gboolean db_err = FALSE;
    GHashTable *obtained_repos = NULL;
    char *repo_id_tmp = NULL;
    obtained_repos = g_hash_table_new_full (g_str_hash, g_str_equal,
                                            g_free,
                                            NULL);
    //get personal repo list
    repos = seaf_repo_manager_get_repos_by_owner (seaf->repo_mgr, user, 0, -1, -1, &db_err);
    if (db_err)
        goto out;

    for (iter = repos; iter; iter = iter->next) {
        repo = iter->data;
        if (repo->type) {
            seaf_repo_unref (repo);
            continue;
        }

        if (!repo->is_corrupted) {
            if (!g_hash_table_lookup (obtained_repos, repo->id)) {
                repo_id_tmp = g_strdup (repo->id);
                g_hash_table_insert (obtained_repos, repo_id_tmp, repo_id_tmp);
            }
            obj = json_object ();
            json_object_set_new (obj, "version", json_integer (repo->version));
            json_object_set_new (obj, "id", json_string (repo->id));
            json_object_set_new (obj, "head_commit_id", json_string (repo->head->commit_id));
            json_object_set_new (obj, "name", json_string (repo->name));
            json_object_set_new (obj, "mtime", json_integer (repo->last_modify));
            json_object_set_new (obj, "permission", json_string ("rw"));
            json_object_set_new (obj, "type", json_string ("repo"));
            json_object_set_new (obj, "owner", json_string (user));

            json_array_append_new (repo_array, obj);
        }
        seaf_repo_unref (repo);
    }
    g_list_free (repos);

    GError *error = NULL;
    SeafileRepo *srepo = NULL;
    //get shared repo list
    repos = seaf_share_manager_list_share_repos (seaf->share_mgr, user, "to_email", -1, -1, &db_err);
    if (db_err)
        goto out;

    for (iter = repos; iter; iter = iter->next) {
        srepo = iter->data;
        obj = fill_obj_from_seafilerepo (srepo, obtained_repos);
        if (!obj) {
            g_object_unref (srepo);
            continue;
        }
        json_object_set_new (obj, "type", json_string ("srepo"));

        json_array_append_new (repo_array, obj);
        g_object_unref (srepo);
    }
    g_list_free (repos);

    //get group repo list
    GHashTable *group_repos = NULL;
    repos = seaf_get_group_repos_by_user (seaf->repo_mgr, user, org_id, &error);
    if (error) {
        g_clear_error (&error);
        goto out;
    }

    if (repos) {
        group_repos = filter_group_repos (repos);
        group_repos_to_json (repo_array, group_repos, obtained_repos);
        g_hash_table_destroy (group_repos);
        g_list_free (repos);
    }

    //get inner public repo list
    repos = seaf_repo_manager_list_inner_pub_repos (seaf->repo_mgr, &db_err);
    if (db_err)
        goto out;

    for (iter = repos; iter; iter = iter->next) {
        srepo = iter->data;
        obj = fill_obj_from_seafilerepo (srepo, obtained_repos);
        if (!obj) {
            g_object_unref (srepo);
            continue;
        }
        json_object_set_new (obj, "type", json_string ("grepo"));
        json_object_set_new (obj, "owner", json_string ("Organization"));

        json_array_append_new (repo_array, obj);
        g_object_unref (srepo);
    }
    g_list_free (repos);

out:
    g_free (user);
    g_hash_table_destroy (obtained_repos);

    if (db_err) {
        json_decref (repo_array);
        seaf_warning ("DB error when get accessible repo list.\n");
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        return;
    }

    char *json_str = json_dumps (repo_array, JSON_COMPACT);
    evbuffer_add (req->buffer_out, json_str, strlen(json_str));
    evhtp_send_reply (req, EVHTP_RES_OK);

    g_free (json_str);
    json_decref (repo_array);
}

static evhtp_res
http_request_finish_cb (evhtp_request_t *req, void *arg)
{
    RequestInfo *info = arg;
    struct timeval end, intv;

    seaf_metric_manager_in_flight_request_dec (seaf->metric_mgr);

    if (!info)
        return EVHTP_RES_OK;

    g_free (info->url_path);
    g_free (info);
    return EVHTP_RES_OK;
}

static evhtp_res
http_request_start_cb (evhtp_request_t *req, evhtp_headers_t *hdr, void *arg)
{
    RequestInfo *info = NULL;
    info = g_new0 (RequestInfo, 1);
    info->url_path = g_strdup (req->uri->path->full);

    gettimeofday (&info->start, NULL);

    seaf_metric_manager_in_flight_request_inc (seaf->metric_mgr);
    evhtp_set_hook (&req->hooks, evhtp_hook_on_request_fini, http_request_finish_cb, info);
    req->cbarg = info;

    return EVHTP_RES_OK;
}

static void
http_request_init (HttpServerStruct *server)
{
    HttpServer *priv = server->priv;
    evhtp_callback_t *cb;

    cb = evhtp_set_cb (priv->evhtp,
                  GET_PROTO_PATH, get_protocol_cb,
                  NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, http_request_start_cb, NULL);

    cb = evhtp_set_regex_cb (priv->evhtp,
                        GET_CHECK_QUOTA_REGEX, get_check_quota_cb,
                        NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, http_request_start_cb, NULL);

    cb = evhtp_set_regex_cb (priv->evhtp,
                        OP_PERM_CHECK_REGEX, get_check_permission_cb,
                        NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, http_request_start_cb, NULL);

    cb = evhtp_set_regex_cb (priv->evhtp,
                        HEAD_COMMIT_OPER_REGEX, head_commit_oper_cb,
                        NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, http_request_start_cb, NULL);

    cb = evhtp_set_regex_cb (priv->evhtp,
                        GET_HEAD_COMMITS_MULTI_REGEX, head_commits_multi_cb,
                        NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, http_request_start_cb, NULL);

    cb = evhtp_set_regex_cb (priv->evhtp,
                        COMMIT_OPER_REGEX, commit_oper_cb,
                        NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, http_request_start_cb, NULL);

    cb = evhtp_set_regex_cb (priv->evhtp,
                        GET_FS_OBJ_ID_REGEX, get_fs_obj_id_cb,
                        NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, http_request_start_cb, NULL);

    // evhtp_set_regex_cb (priv->evhtp,
    //                     START_FS_OBJ_ID_REGEX, start_fs_obj_id_cb,
    //                     priv);

    // evhtp_set_regex_cb (priv->evhtp,
    //                     QUERY_FS_OBJ_ID_REGEX, query_fs_obj_id_cb,
    //                     priv);

    // evhtp_set_regex_cb (priv->evhtp,
    //                     RETRIEVE_FS_OBJ_ID_REGEX, retrieve_fs_obj_id_cb,
    //                     priv);

    cb = evhtp_set_regex_cb (priv->evhtp,
                        BLOCK_OPER_REGEX, block_oper_cb,
                        NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, http_request_start_cb, NULL);

    cb = evhtp_set_regex_cb (priv->evhtp,
                        POST_CHECK_FS_REGEX, post_check_fs_cb,
                        NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, http_request_start_cb, NULL);

    cb = evhtp_set_regex_cb (priv->evhtp,
                        POST_CHECK_BLOCK_REGEX, post_check_block_cb,
                        NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, http_request_start_cb, NULL);

    cb = evhtp_set_regex_cb (priv->evhtp,
                        POST_RECV_FS_REGEX, post_recv_fs_cb,
                        NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, http_request_start_cb, NULL);

    cb = evhtp_set_regex_cb (priv->evhtp,
                        POST_PACK_FS_REGEX, post_pack_fs_cb,
                        NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, http_request_start_cb, NULL);

    cb = evhtp_set_regex_cb (priv->evhtp,
                        GET_BLOCK_MAP_REGEX, get_block_map_cb,
                        NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, http_request_start_cb, NULL);

    cb = evhtp_set_regex_cb (priv->evhtp,
                        GET_JWT_TOKEN_REGEX, get_jwt_token_cb,
                        NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, http_request_start_cb, NULL);

    cb = evhtp_set_regex_cb (priv->evhtp,
                        GET_ACCESSIBLE_REPO_LIST_REGEX, get_accessible_repo_list_cb,
                        NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, http_request_start_cb, NULL);

    /* Web access file */
    access_file_init (priv->evhtp);

    /* Web upload file */
    if (upload_file_init (priv->evhtp, server->http_temp_dir) < 0)
        exit(-1);
}

static void
token_cache_value_free (gpointer data)
{
    TokenInfo *token_info = (TokenInfo *)data;
    if (token_info != NULL) {
        g_free (token_info->repo_id);
        g_free (token_info->email);
        g_free (token_info);
    }
}

static gboolean
is_token_expire (gpointer key, gpointer value, gpointer arg)
{
    TokenInfo *token_info = (TokenInfo *)value;

    if(token_info && token_info->expire_time <= (gint64)time(NULL)) {
        return TRUE;
    }

    return FALSE;
}

static void
perm_cache_value_free (gpointer data)
{
    PermInfo *perm_info = data;
    g_free (perm_info);
}

static gboolean
is_perm_expire (gpointer key, gpointer value, gpointer arg)
{
    PermInfo *perm_info = (PermInfo *)value;

    if(perm_info && perm_info->expire_time <= (gint64)time(NULL)) {
        return TRUE;
    }

    return FALSE;
}

static gboolean
is_vir_repo_info_expire (gpointer key, gpointer value, gpointer arg)
{
    VirRepoInfo *vinfo = (VirRepoInfo *)value;

    if(vinfo && vinfo->expire_time <= (gint64)time(NULL)) {
        return TRUE;
    }

    return FALSE;
}

static void
free_vir_repo_info (gpointer data)
{
    if (!data)
        return;

    VirRepoInfo *vinfo = data;

    if (vinfo->store_id)
        g_free (vinfo->store_id);

    g_free (vinfo);
}

static void
remove_expire_cache_cb (evutil_socket_t sock, short type, void *data)
{
    HttpServer *htp_server = data;

    pthread_mutex_lock (&htp_server->token_cache_lock);
    g_hash_table_foreach_remove (htp_server->token_cache, is_token_expire, NULL);
    pthread_mutex_unlock (&htp_server->token_cache_lock);

    pthread_mutex_lock (&htp_server->perm_cache_lock);
    g_hash_table_foreach_remove (htp_server->perm_cache, is_perm_expire, NULL);
    pthread_mutex_unlock (&htp_server->perm_cache_lock);

    pthread_mutex_lock (&htp_server->vir_repo_info_cache_lock);
    g_hash_table_foreach_remove (htp_server->vir_repo_info_cache,
                                 is_vir_repo_info_expire, NULL);
    pthread_mutex_unlock (&htp_server->vir_repo_info_cache_lock);
}

static void *
http_server_run (void *arg)
{
    HttpServerStruct *server = arg;
    HttpServer *priv = server->priv;

    priv->evbase = event_base_new();
    priv->evhtp = evhtp_new(priv->evbase, NULL);

    if (evhtp_bind_socket(priv->evhtp,
                          server->bind_addr,
                          server->bind_port, 128) < 0) {
        seaf_warning ("Could not bind socket: %s\n", strerror (errno));
        exit(-1);
    }

    http_request_init (server);

    evhtp_use_threads (priv->evhtp, NULL, server->worker_threads, NULL);

    struct timeval tv;
    tv.tv_sec = CLEANING_INTERVAL_SEC;
    tv.tv_usec = 0;
    priv->reap_timer = event_new (priv->evbase,
                                  -1,
                                  EV_PERSIST,
                                  remove_expire_cache_cb,
                                  priv);
    evtimer_add (priv->reap_timer, &tv);

    event_base_loop (priv->evbase, 0);

    return NULL;
}

HttpServerStruct *
seaf_http_server_new (struct _SeafileSession *session)
{
    HttpServerStruct *server = g_new0 (HttpServerStruct, 1);
    HttpServer *priv = g_new0 (HttpServer, 1);

    priv->evbase = NULL;
    priv->evhtp = NULL;

    load_http_config (server, session);

    priv->token_cache = g_hash_table_new_full (g_str_hash, g_str_equal,
                                               g_free, token_cache_value_free);
    pthread_mutex_init (&priv->token_cache_lock, NULL);

    priv->perm_cache = g_hash_table_new_full (g_str_hash, g_str_equal,
                                              g_free, perm_cache_value_free);
    pthread_mutex_init (&priv->perm_cache_lock, NULL);

    priv->vir_repo_info_cache = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                       g_free, free_vir_repo_info);
    pthread_mutex_init (&priv->vir_repo_info_cache_lock, NULL);

    server->http_temp_dir = g_build_filename (session->seaf_dir, "httptemp", NULL);

    // priv->compute_fs_obj_id_pool = g_thread_pool_new (compute_fs_obj_id, NULL,
    //                                                   FS_ID_LIST_MAX_WORKERS, FALSE, NULL);

    // priv->fs_obj_ids = g_hash_table_new_full (g_str_hash, g_str_equal,
    //                                           g_free, free_obj_cal_result);
    // pthread_mutex_init (&priv->fs_obj_ids_lock, NULL);

    server->seaf_session = session;
    server->priv = priv;

    return server;
}

gint64
get_last_modify_time (const char *path)
{
    struct stat st;
    if (stat (path, &st) < 0) {
        return -1;
    }

    return st.st_mtime;
}

static gint64
check_httptemp_dir_recursive (const char *parent_dir, gint64 expired_time)
{
    char *full_path;
    const char *dname;
    gint64 cur_time;
    gint64 last_modify = -1;
    GDir *dir = NULL;
    gint64 file_num = 0;

    dir = g_dir_open (parent_dir, 0, NULL);

    while ((dname = g_dir_read_name(dir)) != NULL) {
        full_path = g_build_path ("/", parent_dir, dname, NULL);

        if (g_file_test (full_path, G_FILE_TEST_IS_DIR)) {
            file_num += check_httptemp_dir_recursive (full_path, expired_time);
        } else {
            cur_time = time (NULL);
            last_modify = get_last_modify_time (full_path);
            if (last_modify == -1) {
                g_free (full_path);
                continue;
            }
            /*remove blokc cache from local*/
            if (last_modify + expired_time <= cur_time) {
                g_unlink (full_path);
                file_num ++;
            }
        }
        g_free (full_path);
    }

    g_dir_close (dir);

    return file_num;
}

static int
scan_httptemp_dir (const char *httptemp_dir, gint64 expired_time)
{
    return check_httptemp_dir_recursive (httptemp_dir, expired_time);
}

static void *
cleanup_expired_httptemp_file (void *arg)
{
    GError *error = NULL;
    HttpServerStruct *server = arg;
    SeafileSession *session = server->seaf_session;
    gint64 ttl = 0;
    gint64 scan_interval = 0;
    gint64 file_num = 0;

    ttl = fileserver_config_get_int64 (session->config, HTTP_TEMP_FILE_TTL, &error);
    if (error) {
        ttl = HTTP_TEMP_FILE_DEFAULT_TTL;
        g_clear_error (&error);
    }

    scan_interval = fileserver_config_get_int64 (session->config, HTTP_SCAN_INTERVAL, &error);
    if (error) {
        scan_interval = HTTP_TEMP_FILE_SCAN_INTERVAL;
        g_clear_error (&error);
    }

    while (TRUE) {
        sleep (scan_interval);
        file_num = scan_httptemp_dir (server->http_temp_dir, ttl);
        if (file_num) {
            seaf_message ("Clean up %ld http temp files\n", file_num);
            file_num = 0;
        }
    }

    return NULL;
}

int
seaf_http_server_start (HttpServerStruct *server)
{
   int ret = pthread_create (&server->priv->thread_id, NULL, http_server_run, server);
   if (ret != 0)
       return -1;

   pthread_detach (server->priv->thread_id);

   pthread_t tid;
   ret = pthread_create (&tid, NULL, cleanup_expired_httptemp_file, server);
   if (ret != 0)
       return -1;

   pthread_detach (tid);
   return 0;
}

int
seaf_http_server_invalidate_tokens (HttpServerStruct *htp_server,
                                    const GList *tokens)
{
    const GList *p;

    pthread_mutex_lock (&htp_server->priv->token_cache_lock);
    for (p = tokens; p; p = p->next) {
        const char *token = (char *)p->data;
        g_hash_table_remove (htp_server->priv->token_cache, token);
    }
    pthread_mutex_unlock (&htp_server->priv->token_cache_lock);
    return 0;
}

#endif
