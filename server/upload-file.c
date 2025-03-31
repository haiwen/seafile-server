#include "common.h"

#ifdef HAVE_EVHTP
#define DEBUG_FLAG SEAFILE_DEBUG_HTTP
#include "log.h"

#include <getopt.h>
#include <fcntl.h>

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <event2/event.h>
#else
#include <event.h>
#endif

#include <evhtp.h>

#include <jansson.h>

#include <pthread.h>

#include "seafile-object.h"

#include "utils.h"

#include "seafile-session.h"
#include "upload-file.h"
#include "http-status-codes.h"
#include "http-server.h"

#include "seafile-error.h"

enum RecvState {
    RECV_INIT,
    RECV_HEADERS,
    RECV_CONTENT,
    RECV_ERROR,
};

enum UploadError {
    ERROR_FILENAME,
    ERROR_EXISTS,
    ERROR_NOT_EXIST,
    ERROR_SIZE,
    ERROR_QUOTA,
    ERROR_FORBIDDEN,
    ERROR_RECV,
    ERROR_BLOCK_MISSING,
    ERROR_INTERNAL,
};

typedef struct Progress {
    gint64 uploaded;
    gint64 size;
} Progress;

typedef struct RecvFSM {
    int state;

    char *repo_id;
    char *user;
    char *boundary;        /* boundary of multipart form-data. */
    char *input_name;      /* input name of the current form field. */
    char *parent_dir;
    evbuf_t *line;          /* buffer for a line */

    GHashTable *form_kvs;       /* key/value of form fields */
    GList *filenames;           /* uploaded file names */
    GList *files;               /* paths for completely uploaded tmp files. */

    gboolean recved_crlf; /* Did we recv a CRLF when write out the last line? */
    char *file_name;
    char *tmp_file; /* tmp file path for the currently uploading file */
    int fd;
    char *resumable_tmp_file;        /* resumable upload tmp file path. In resumable uploads, contents of the chunks are appended to this tmp file. */

    /* For upload progress. */
    char *progress_id;
    Progress *progress;

    char *token_type; /* For sending statistic type */

    gboolean need_idx_progress;

    gint64 rstart;
    gint64 rend;
    gint64 fsize;
} RecvFSM;

#define MAX_CONTENT_LINE 10240

static GHashTable *upload_progress;
static pthread_mutex_t pg_lock;
static int
write_block_data_to_tmp_file (RecvFSM *fsm, const char *parent_dir,
                              const char *file_name);

/* IE8 will set filename to the full path of the uploaded file.
 * So we need to strip out the basename from it.
 */
static char *
get_basename (const char *path)
{
    int i = strlen(path) - 1;

    while (i >= 0) {
        if (path[i] == '/' || path[i] == '\\')
            break;
        --i;
    }

    if (i < 0)
        return g_strdup(path);

    return g_strdup(&path[i+1]);
}

/* It's a bug of libevhtp that it doesn't set Content-Length automatically
 * in response to a multipart request.
 * Just add it in our code.
 */
static void
set_content_length_header (evhtp_request_t *req)
{
    char lstr[128];

#ifdef WIN32
    snprintf(lstr, sizeof(lstr), "%lu", (unsigned long)(evbuffer_get_length(req->buffer_out)));
#else
    snprintf(lstr, sizeof(lstr), "%zu", evbuffer_get_length(req->buffer_out));
#endif

    evhtp_headers_add_header(req->headers_out,
                             evhtp_header_new("Content-Length", lstr, 1, 1));
}

static gint64
get_content_length (evhtp_request_t *req)
{
    const char *content_len_str = evhtp_kv_find (req->headers_in, "Content-Length");
    if (!content_len_str) {
        return -1;
    }

    return strtoll (content_len_str, NULL, 10);
}

static void
send_error_reply (evhtp_request_t *req, evhtp_res code, char *error)
{
    if (error)
        evbuffer_add_printf (req->buffer_out, "{\"error\": \"%s\"}", error);
    set_content_length_header (req);
    evhtp_headers_add_header (
        req->headers_out,
        evhtp_header_new("Content-Type", "application/json; charset=utf-8", 1, 1));
    evhtp_send_reply (req, code);
}

static void
send_success_reply (evhtp_request_t *req)
{
    set_content_length_header (req);
    evhtp_headers_add_header (
        req->headers_out,
        evhtp_header_new("Content-Type", "application/json; charset=utf-8", 1, 1));
    evhtp_send_reply (req, EVHTP_RES_OK);
}

static void
send_success_reply_ie8_compatible (evhtp_request_t *req, evhtp_res code)
{
    set_content_length_header (req);

    const char *accept = evhtp_kv_find (req->headers_in, "Accept");
    if (accept && strstr (accept, "application/json") != NULL) {
        evhtp_headers_add_header (
            req->headers_out,
            evhtp_header_new("Content-Type", "application/json; charset=utf-8", 1, 1));
    } else {
        evhtp_headers_add_header (
            req->headers_out,
            evhtp_header_new("Content-Type", "text/plain", 1, 1));
    }
    evhtp_send_reply (req, code);
}

static void
send_reply_by_error_code (evhtp_request_t *req, int error_code)
{
    switch (error_code) {
    case ERROR_FILENAME:
        send_error_reply (req, SEAF_HTTP_RES_BADFILENAME, "Invalid filename.\n");
        break;
    case ERROR_EXISTS:
        send_error_reply (req, SEAF_HTTP_RES_EXISTS, "File already exists.\n");
        break;
    case ERROR_NOT_EXIST:
        send_error_reply (req, SEAF_HTTP_RES_NOT_EXISTS, "File does not exist.\n");
        break;
    case ERROR_SIZE:
        send_error_reply (req, SEAF_HTTP_RES_TOOLARGE, "File size is too large.\n");
        break;
    case ERROR_QUOTA:
        send_error_reply (req, SEAF_HTTP_RES_NOQUOTA, "Out of quota.\n");
        break;
    case ERROR_BLOCK_MISSING:
        send_error_reply (req, SEAF_HTTP_RES_BLOCK_MISSING, "Block missing.\n");
        break;
    case ERROR_FORBIDDEN:
        send_error_reply (req, SEAF_HTTP_RES_FORBIDDEN, "Permission denied.");
        break;
    case ERROR_RECV:
    case ERROR_INTERNAL:
        send_error_reply (req, EVHTP_RES_SERVERR, "Internal error\n");
        break;
    }
}

static gboolean
check_tmp_file_list (GList *tmp_files, int *error_code)
{
    GList *ptr;
    char *tmp_file;
    SeafStat st;
    gint64 total_size = 0;
    gint64 max_upload_size;

    for (ptr = tmp_files; ptr; ptr = ptr->next) {
        tmp_file = ptr->data;

        if (seaf_stat (tmp_file, &st) < 0) {
            seaf_warning ("[upload] Failed to stat temp file %s.\n", tmp_file);
            *error_code = ERROR_RECV;
            return FALSE;
        }

        total_size += (gint64)st.st_size;
    }
    /* default is MB */
    max_upload_size = seaf_cfg_manager_get_config_int64 (seaf->cfg_mgr, "fileserver",
                                                         "max_upload_size");
    if (max_upload_size > 0)
        max_upload_size = max_upload_size * 1000000;
    else
        max_upload_size = -1;
    
    if (max_upload_size > 0 && total_size > max_upload_size) {
        seaf_debug ("[upload] File size is too large.\n");
        *error_code = ERROR_SIZE;
        return FALSE;
    }

    return TRUE;
}

static char *
get_canonical_path (const char *path)
{
    char *ret = g_strdup (path);
    char *p;

    for (p = ret; *p != 0; ++p) {
        if (*p == '\\')
            *p = '/';
    }

    /* Remove trailing slashes from dir path. */
    int len = strlen(ret);
    int i = len - 1;
    while (i >= 0 && ret[i] == '/')
        ret[i--] = 0;

    return ret;
}

static gboolean
check_parent_dir (evhtp_request_t *req, const char *repo_id,
                  const char *parent_dir)
{
    char *canon_path = NULL;
    SeafRepo *repo = NULL;
    SeafCommit *commit = NULL;
    SeafDir *dir = NULL;
    GError *error = NULL;
    gboolean ret = TRUE;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("[upload] Failed to get repo %.8s.\n", repo_id);
        send_error_reply (req, EVHTP_RES_SERVERR, "Failed to get repo.\n");
        return FALSE;
    }

    commit = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             repo->id, repo->version,
                                             repo->head->commit_id);
    if (!commit) {
        seaf_warning ("[upload] Failed to get head commit for repo %.8s.\n", repo_id);
        send_error_reply (req, EVHTP_RES_SERVERR, "Failed to get head commit.\n");
        seaf_repo_unref (repo);
        return FALSE;
    }

    canon_path = get_canonical_path (parent_dir);

    dir = seaf_fs_manager_get_seafdir_by_path (seaf->fs_mgr,
                                               repo->store_id, repo->version,
                                               commit->root_id,
                                               canon_path, &error);
    if (dir) {
        seaf_dir_free (dir);
    } else {
        send_error_reply (req, EVHTP_RES_BADREQ, "Parent dir doesn't exist.\n");
        ret = FALSE;
    }

    g_clear_error (&error);
    g_free (canon_path);
    seaf_commit_unref (commit);
    seaf_repo_unref (repo);

    return ret;
}

static gboolean
is_parent_matched (const char *upload_dir,
                   const char *parent_dir)
{
    gboolean ret = TRUE;
    char *upload_dir_canon = NULL;
    char *parent_dir_canon = NULL;

    upload_dir_canon = get_canonical_path (upload_dir);
    parent_dir_canon = get_canonical_path (parent_dir);

    if (strcmp (upload_dir_canon,parent_dir_canon) != 0) {
        ret = FALSE;
    }

    g_free (upload_dir_canon);
    g_free (parent_dir_canon);

    return ret;
}

static char *
file_list_to_json (GList *files)
{
    json_t *array;
    GList *ptr;
    char *file;
    char *json_data;
    char *ret;

    array = json_array ();

    for (ptr = files; ptr; ptr = ptr->next) {
        file = ptr->data;
        json_array_append_new (array, json_string(file));
    }

    json_data = json_dumps (array, 0);
    json_decref (array);

    ret = g_strdup (json_data);
    free (json_data);
    return ret;
}

static int
create_relative_path (RecvFSM *fsm, char *parent_dir, char *relative_path)
{
    int rc = 0;
    GError *error = NULL;

    if (!relative_path)
        return 0;

    rc = seaf_repo_manager_mkdir_with_parents (seaf->repo_mgr,
                                               fsm->repo_id,
                                               parent_dir,
                                               relative_path,
                                               fsm->user,
                                               &error);
    if (rc < 0) {
        if (error) {
            seaf_warning ("[upload folder] %s.", error->message);
            g_clear_error (&error);
        }
    }

    return rc;
}

static char *
file_id_list_from_json (const char *ret_json)
{
    json_t *array, *obj, *value;
    json_error_t err;
    size_t index;
    GString *id_list;

    array = json_loadb (ret_json, strlen(ret_json), 0, &err);
    if (!array) {
        seaf_warning ("Failed to load ret_json: %s.\n", err.text);
        return NULL;
    }

    id_list = g_string_new (NULL);
    size_t n = json_array_size (array);
    for (index = 0; index < n; index++) {
        obj = json_array_get (array, index);
        value = json_object_get (obj, "id");
        const char *id = json_string_value (value);
        g_string_append (id_list, id);
        if (index != n - 1)
            g_string_append (id_list, "\t");
    }

    json_decref (array);
    return g_string_free (id_list, FALSE);
}

static gint64
rfc3339_to_timestamp (const char *last_modify)
{
    if (!last_modify) {
        return -1;
    }
    GDateTime *date_time = g_date_time_new_from_iso8601(last_modify, NULL);
    if (!date_time) {
        return -1;
    }
    gint64 mtime = g_date_time_to_unix(date_time);

    g_date_time_unref(date_time);
    return mtime;
}

static void
upload_api_cb(evhtp_request_t *req, void *arg)
{
    RecvFSM *fsm = arg;
    char *parent_dir, *replace_str;
    char *relative_path = NULL, *new_parent_dir = NULL;
    char *last_modify = NULL;
    gint64 mtime = 0;
    GError *error = NULL;
    int error_code = -1;
    char *filenames_json, *tmp_files_json;
    int replace = 0;
    int rc;

    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Access-Control-Allow-Headers",
                                               "x-requested-with, content-type, content-range, content-disposition, accept, origin, authorization", 1, 1));
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Access-Control-Allow-Methods",
                                               "GET, POST, PUT, PATCH, DELETE, OPTIONS", 1, 1));
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Access-Control-Allow-Origin",
                                               "*", 1, 1));
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Access-Control-Max-Age",
                                               "86400", 1, 1));

    if (evhtp_request_get_method(req) == htp_method_OPTIONS) {
        /* If CORS preflight header, then create an empty body response (200 OK)
         * and return it.
         */
        send_success_reply (req);
        return;
    }

    /* After upload_headers_cb() returns an error, libevhtp may still
     * receive data from the web browser and call into this cb.
     * In this case fsm will be NULL.
     */
    if (!fsm || fsm->state == RECV_ERROR)
        return;

    if (!fsm->filenames) {
        seaf_debug ("[upload] No file uploaded.\n");
        send_error_reply (req, EVHTP_RES_BADREQ, "No file uploaded.\n");
        return;
    }

    last_modify = g_hash_table_lookup (fsm->form_kvs, "last_modify");
    if (last_modify) {
        mtime = rfc3339_to_timestamp (last_modify);
    }

    replace_str = g_hash_table_lookup (fsm->form_kvs, "replace");
    if (replace_str) {
        replace = atoi(replace_str);
        if (replace != 0 && replace != 1) {
            seaf_debug ("[Upload] Invalid argument replace: %s.\n", replace_str);
            send_error_reply (req, EVHTP_RES_BADREQ, "Invalid argument replace.\n");
            return;
        }
    }
    parent_dir = g_hash_table_lookup (fsm->form_kvs, "parent_dir");
    if (!parent_dir) {
        seaf_debug ("[upload] No parent dir given.\n");
        send_error_reply (req, EVHTP_RES_BADREQ, "Invalid parent dir.\n");
        return;
    }
    relative_path = g_hash_table_lookup (fsm->form_kvs, "relative_path");
    if (relative_path != NULL) {
        if (relative_path[0] == '/' || relative_path[0] == '\\') {
            seaf_warning ("Invalid relative path %s.\n", relative_path);
            send_error_reply (req, EVHTP_RES_BADREQ, "Invalid relative path.");
            return;
        }
        char *tmp_p = get_canonical_path(parent_dir);
        char *tmp_r = get_canonical_path(relative_path);
        new_parent_dir = g_build_path("/", tmp_p, tmp_r, NULL);
        g_free(tmp_p);
        g_free(tmp_r);
    } else {
        new_parent_dir = get_canonical_path(parent_dir);
    }

    if (fsm->rstart >= 0) {
        if (fsm->filenames->next) {
            seaf_debug ("[upload] Breakpoint transfer only support one file in one request.\n");
            send_error_reply (req, EVHTP_RES_BADREQ, "More files in one request.\n");
            goto out;
        }

        if (parent_dir[0] != '/') {
            seaf_debug ("[upload] Invalid parent dir, should start with /.\n");
            send_error_reply (req, EVHTP_RES_BADREQ, "Invalid parent dir.\n");
            goto out;
        }

        if (!fsm->resumable_tmp_file)
            fsm->resumable_tmp_file = g_build_path ("/", new_parent_dir, (char *)fsm->filenames->data, NULL);

        if (write_block_data_to_tmp_file (fsm, new_parent_dir,
                                          (char *)fsm->filenames->data) < 0) {
            error_code = ERROR_INTERNAL;
            goto out;
        }
        if (fsm->rend != fsm->fsize - 1) {
            const char *success_str = "{\"success\": true}";
            evbuffer_add (req->buffer_out, success_str, strlen(success_str));
            send_success_reply_ie8_compatible (req, EVHTP_RES_OK);
            goto out;
        }
    }

    if (!fsm->files) {
        seaf_debug ("[upload] No file uploaded.\n");
        send_error_reply (req, EVHTP_RES_BADREQ, "No file uploaded.\n");
        goto out;
    }

    if (!check_parent_dir (req, fsm->repo_id, parent_dir))
        goto out;

    if (!fsm->parent_dir || !is_parent_matched (fsm->parent_dir, parent_dir)){
        error_code = ERROR_FORBIDDEN;
        goto out;
    }

    if (!check_tmp_file_list (fsm->files, &error_code))
        goto out;

    gint64 content_len;
    if (fsm->fsize > 0)
        content_len = fsm->fsize;
    else
        content_len = get_content_length (req);
    if (seaf_quota_manager_check_quota_with_delta (seaf->quota_mgr,
                                                   fsm->repo_id,
                                                   content_len) != 0) {
        error_code = ERROR_QUOTA;
        goto out;
    }

    rc = create_relative_path (fsm, parent_dir, relative_path);
    if (rc < 0) {
        error_code = ERROR_INTERNAL;
        goto out;
    }

    filenames_json = file_list_to_json (fsm->filenames);
    tmp_files_json = file_list_to_json (fsm->files);

    char *ret_json = NULL;
    char *task_id = NULL;
    rc = seaf_repo_manager_post_multi_files (seaf->repo_mgr,
                                             fsm->repo_id,
                                             new_parent_dir,
                                             filenames_json,
                                             tmp_files_json,
                                             fsm->user,
                                             replace,
                                             mtime,
                                             &ret_json,
                                             fsm->need_idx_progress ? &task_id : NULL,
                                             &error);
    g_free (filenames_json);
    g_free (tmp_files_json);
    if (rc < 0) {
        error_code = ERROR_INTERNAL;
        if (error) {
            if (error->code == POST_FILE_ERR_FILENAME) {
                error_code = ERROR_FILENAME;
            } else if (error->code == SEAF_ERR_FILES_WITH_SAME_NAME) {
                error_code = -1;
                send_error_reply (req, EVHTP_RES_BADREQ, "Too many files with same name.\n");
            } else if (error->code == SEAF_ERR_GC_CONFLICT) {
                error_code = -1;
                send_error_reply (req, EVHTP_RES_CONFLICT, "GC Conflict.\n");
            }
            g_clear_error (&error);
        }
        goto out;
    }

    if (task_id) {
        evbuffer_add (req->buffer_out, task_id, strlen(task_id));
        g_free (task_id);
    } else {
        const char *use_json = evhtp_kv_find (req->uri->query, "ret-json");
        if (use_json) {
            evbuffer_add (req->buffer_out, ret_json, strlen(ret_json));
        } else {
            char *new_ids = file_id_list_from_json (ret_json);
            if (new_ids)
                evbuffer_add (req->buffer_out, new_ids, strlen(new_ids));
            g_free (new_ids);
        }
    }
    g_free (ret_json);

    send_success_reply (req);

    char *oper = "web-file-upload";
    if (g_strcmp0(fsm->token_type, "upload-link") == 0)
        oper = "link-file-upload";
    send_statistic_msg(fsm->repo_id, fsm->user, oper, (guint64)content_len);

out:
    g_free(new_parent_dir);
    send_reply_by_error_code (req, error_code);

    return;
}


static void
upload_raw_blks_api_cb(evhtp_request_t *req, void *arg)
{
    RecvFSM *fsm = arg;
    GError *error = NULL;
    int error_code = -1;
    char *blockids_json, *tmp_files_json;

    /* After upload_headers_cb() returns an error, libevhtp may still
     * receive data from the web browser and call into this cb.
     * In this case fsm will be NULL.
     */
    if (!fsm || fsm->state == RECV_ERROR)
        return;

    if (!check_tmp_file_list (fsm->files, &error_code))
        goto out;

    blockids_json = file_list_to_json (fsm->filenames);
    tmp_files_json = file_list_to_json (fsm->files);

    int rc = seaf_repo_manager_post_blocks (seaf->repo_mgr,
                                            fsm->repo_id,
                                            blockids_json,
                                            tmp_files_json,
                                            fsm->user,
                                            &error);
    g_free (blockids_json);
    g_free (tmp_files_json);
    if (rc < 0) {
        error_code = ERROR_INTERNAL;
        if (error) {
            if (error->code == POST_FILE_ERR_FILENAME) {
                error_code = ERROR_FILENAME;
            }
            g_clear_error (&error);
        }
        goto out;
    }
    guint64 content_len = (guint64)get_content_length(req);
    send_statistic_msg(fsm->repo_id, fsm->user, "web-file-upload", content_len);

    evbuffer_add (req->buffer_out, "\"OK\"", 4);
    send_success_reply (req);

out:
    send_reply_by_error_code (req, error_code);

    return;
}

static void
upload_blks_api_cb(evhtp_request_t *req, void *arg)
{
    RecvFSM *fsm = arg;
    const char *parent_dir, *file_name, *size_str, *replace_str, *commitonly_str;
    char *last_modify = NULL;
    gint64 mtime = 0;
    GError *error = NULL;
    int error_code = -1;
    char *blockids_json;
    gint64 file_size = -1;
    int replace = 0;

    /* After upload_headers_cb() returns an error, libevhtp may still
     * receive data from the web browser and call into this cb.
     * In this case fsm will be NULL.
     */
    if (!fsm || fsm->state == RECV_ERROR)
        return;

    replace_str = g_hash_table_lookup (fsm->form_kvs, "replace");
    if (replace_str) {
        replace = atoi(replace_str);
        if (replace != 0 && replace != 1) {
            seaf_debug ("[Upload-blks] Invalid argument replace: %s.\n", replace_str);
            send_error_reply (req, EVHTP_RES_BADREQ, "Invalid argument replace.\n");
            return;
        }
    }
    parent_dir = g_hash_table_lookup (fsm->form_kvs, "parent_dir");
    file_name = g_hash_table_lookup (fsm->form_kvs, "file_name");
    size_str = g_hash_table_lookup (fsm->form_kvs, "file_size");
    if (size_str)
        file_size = atoll(size_str);
    commitonly_str = evhtp_kv_find (req->uri->query, "commitonly");

    last_modify = g_hash_table_lookup (fsm->form_kvs, "last_modify");
    if (last_modify) {
        mtime = rfc3339_to_timestamp (last_modify);
    }

    if (!file_name || !parent_dir || !size_str || file_size < 0) {
        seaf_debug ("[upload-blks] No parent dir or file name given.\n");
        send_error_reply (req, EVHTP_RES_BADREQ, "No parent dir or file name.\n");
        return;
    }
    if (!commitonly_str) {
        send_error_reply (req, EVHTP_RES_BADREQ, "Only commit suppported.\n");
        return;
    }

    if (!check_parent_dir (req, fsm->repo_id, parent_dir))
        return;

    char *new_file_id = NULL;
    int rc = 0;
    /* if (!commitonly_str) { */
    /*     gint64 content_len = get_content_length (req); */
    /*     if (seaf_quota_manager_check_quota_with_delta (seaf->quota_mgr, */
    /*                                                    fsm->repo_id, */
    /*                                                    content_len) != 0) { */
    /*         error_code = ERROR_QUOTA; */
    /*         goto error; */
    /*     } */

    /*     if (!check_tmp_file_list (fsm->files, &error_code)) */
    /*         goto error; */
    /*     blockids_json = file_list_to_json (fsm->filenames); */
    /*     tmp_files_json = file_list_to_json (fsm->files); */

    /*     rc = seaf_repo_manager_post_file_blocks (seaf->repo_mgr, */
    /*                                              fsm->repo_id, */
    /*                                              parent_dir, */
    /*                                              file_name, */
    /*                                              blockids_json, */
    /*                                              tmp_files_json, */
    /*                                              fsm->user, */
    /*                                              file_size, */
    /*                                              replace, */
    /*                                              &new_file_id, */
    /*                                              &error); */
    /*     g_free (blockids_json); */
    /*     g_free (tmp_files_json); */
    /* } else { */

    blockids_json = g_hash_table_lookup (fsm->form_kvs, "blockids");
    if (blockids_json == NULL) {
        seaf_debug ("[upload-blks] No blockids given.\n");
        send_error_reply (req, EVHTP_RES_BADREQ, "No blockids.\n");
        return;
    }
    rc = seaf_repo_manager_commit_file_blocks (seaf->repo_mgr,
                                               fsm->repo_id,
                                               parent_dir,
                                               file_name,
                                               blockids_json,
                                               fsm->user,
                                               file_size,
                                               replace,
                                               mtime,
                                               &new_file_id,
                                               &error);
    if (rc < 0) {
        error_code = ERROR_INTERNAL;
        if (error) {
            if (error->code == POST_FILE_ERR_FILENAME) {
                error_code = ERROR_FILENAME;
            } else if (error->code == POST_FILE_ERR_BLOCK_MISSING) {
                error_code = ERROR_BLOCK_MISSING;
            } else if (error->code == POST_FILE_ERR_QUOTA_FULL) {
                error_code = ERROR_QUOTA;
            } else if (error->code == SEAF_ERR_GC_CONFLICT) {
                error_code = -1;
                send_error_reply (req, EVHTP_RES_CONFLICT, "GC Conflict.\n");
            }
            g_clear_error (&error);
        }
        goto out;
    }

    const char *use_json = evhtp_kv_find (req->uri->query, "ret-json");
    if (use_json) {
        json_t *json = json_object ();
        json_object_set_string_member(json, "id", new_file_id);
        char *json_data = json_dumps (json, 0);
        evbuffer_add (req->buffer_out, json_data, strlen(json_data));
        json_decref (json);
        free (json_data);
    } else {
        evbuffer_add (req->buffer_out, "\"", 1);
        evbuffer_add (req->buffer_out, new_file_id, strlen(new_file_id));
        evbuffer_add (req->buffer_out, "\"", 1);
    }
    send_success_reply (req);

out:
    g_free (new_file_id);
    send_reply_by_error_code (req, error_code);

    return;
}

/* static void */
/* upload_blks_ajax_cb(evhtp_request_t *req, void *arg) */
/* { */
/*     RecvFSM *fsm = arg; */
/*     char *parent_dir, *file_name, *size_str; */
/*     GError *error = NULL; */
/*     int error_code = ERROR_INTERNAL; */
/*     char *blockids_json, *tmp_files_json; */
/*     gint64 file_size = -1; */

/*     evhtp_headers_add_header (req->headers_out, */
/*                               evhtp_header_new("Access-Control-Allow-Headers", */
/*                                                "x-requested-with, content-type, accept, origin, authorization", 1, 1)); */
/*     evhtp_headers_add_header (req->headers_out, */
/*                               evhtp_header_new("Access-Control-Allow-Methods", */
/*                                                "GET, POST, PUT, PATCH, DELETE, OPTIONS", 1, 1)); */
/*     evhtp_headers_add_header (req->headers_out, */
/*                               evhtp_header_new("Access-Control-Allow-Origin", */
/*                                                "*", 1, 1)); */
/*     evhtp_headers_add_header (req->headers_out, */
/*                               evhtp_header_new("Access-Control-Max-Age", */
/*                                                "86400", 1, 1)); */

/*     if (evhtp_request_get_method(req) == htp_method_OPTIONS) { */
/*         /\* If CORS preflight header, then create an empty body response (200 OK) */
/*          * and return it. */
/*          *\/ */
/*         send_success_reply (req); */
/*         return; */
/*     } */

/*     /\* After upload_headers_cb() returns an error, libevhtp may still */
/*      * receive data from the web browser and call into this cb. */
/*      * In this case fsm will be NULL. */
/*      *\/ */
/*     if (!fsm || fsm->state == RECV_ERROR) */
/*         return; */

/*     parent_dir = g_hash_table_lookup (fsm->form_kvs, "parent_dir"); */
/*     file_name = g_hash_table_lookup (fsm->form_kvs, "file_name"); */
/*     size_str = g_hash_table_lookup (fsm->form_kvs, "file_size"); */
/*     if (size_str) */
/*         file_size = atoll(size_str); */
/*     if (!file_name || !parent_dir || !size_str || file_size < 0) { */
/*         seaf_debug ("[upload-blks] No parent dir or file name given.\n"); */
/*         send_error_reply (req, EVHTP_RES_BADREQ, "Invalid URL.\n"); */
/*         return; */
/*     } */

/*     if (!check_parent_dir (req, fsm->repo_id, parent_dir)) */
/*         return; */

/*     if (!check_tmp_file_list (fsm->files, &error_code)) */
/*         goto error; */

/*     gint64 content_len = get_content_length (req); */
/*     if (seaf_quota_manager_check_quota_with_delta (seaf->quota_mgr, */
/*                                                    fsm->repo_id, */
/*                                                    content_len) != 0) { */
/*         error_code = ERROR_QUOTA; */
/*         goto error; */
/*     } */

/*     blockids_json = file_list_to_json (fsm->filenames); */
/*     tmp_files_json = file_list_to_json (fsm->files); */

/*     int rc = seaf_repo_manager_post_file_blocks (seaf->repo_mgr, */
/*                                                  fsm->repo_id, */
/*                                                  parent_dir, */
/*                                                  file_name, */
/*                                                  blockids_json, */
/*                                                  tmp_files_json, */
/*                                                  fsm->user, */
/*                                                  file_size, */
/*                                                  0, */
/*                                                  NULL, */
/*                                                  &error); */
/*     g_free (blockids_json); */
/*     g_free (tmp_files_json); */
/*     if (rc < 0) { */
/*         if (error) { */
/*             if (error->code == POST_FILE_ERR_FILENAME) { */
/*                 error_code = ERROR_FILENAME; */
/*             } */
/*             g_clear_error (&error); */
/*         } */
/*         goto error; */
/*     } */

/*     send_success_reply (req); */
/*     return; */

/* error: */
/*     switch (error_code) { */
/*     case ERROR_FILENAME: */
/*         send_error_reply (req, SEAF_HTTP_RES_BADFILENAME, "Invalid filename."); */
/*         break; */
/*     case ERROR_EXISTS: */
/*         send_error_reply (req, SEAF_HTTP_RES_EXISTS, "File already exists."); */
/*         break; */
/*     case ERROR_SIZE: */
/*         send_error_reply (req, SEAF_HTTP_RES_TOOLARGE, "File size is too large."); */
/*         break; */
/*     case ERROR_QUOTA: */
/*         send_error_reply (req, SEAF_HTTP_RES_NOQUOTA, "Out of quota."); */
/*         break; */
/*     case ERROR_RECV: */
/*     case ERROR_INTERNAL: */
/*         send_error_reply (req, EVHTP_RES_SERVERR, "Internal error.\n"); */
/*         break; */
/*     } */
/* } */

static int
copy_block_to_tmp_file (int blk_fd, int tmp_fd, gint64 offset)
{
    if (lseek(blk_fd, 0, SEEK_SET) < 0) {
        seaf_warning ("Failed to rewind block temp file position to start: %s\n",
                      strerror(errno));
        return -1;
    }

    if (lseek(tmp_fd, offset, SEEK_SET) <0) {
        seaf_warning ("Failed to rewind web upload temp file write position: %s\n",
                      strerror(errno));
        return -1;
    }

    char buf[8192];
    int buf_len = sizeof(buf);
    ssize_t len;

    while (TRUE) {
        len = readn (blk_fd, buf, buf_len);
        if (len < 0) {
            seaf_warning ("Failed to read content from block temp file: %s.\n",
                          strerror(errno));
            return -1;
        } else if (len == 0) {
            return 0;
        }

        if (writen (tmp_fd, buf, len) != len) {
            seaf_warning ("Failed to write content to temp file: %s.\n",
                          strerror(errno));
            return -1;
        }
    }
}

static int
write_block_data_to_tmp_file (RecvFSM *fsm, const char *parent_dir,
                              const char *file_name)
{
    char *abs_path;
    char *temp_file = NULL;
    GError *error = NULL;
    int tmp_fd = -1;
    int ret = 0;
    HttpServerStruct *htp_server = seaf->http_server;
    int cluster_shared_temp_file_mode = htp_server->cluster_shared_temp_file_mode;

    abs_path = g_build_path ("/", parent_dir, file_name, NULL);

    temp_file = seaf_repo_manager_get_upload_tmp_file (seaf->repo_mgr,
                                                       fsm->repo_id,
                                                       abs_path, &error);
    if (error) {
        seaf_warning ("%s\n", error->message);
        g_clear_error (&error);
        ret = -1;
        goto out;
    }

    if (!temp_file) {
        temp_file = g_strdup_printf ("%s/cluster-shared/%sXXXXXX",
                                     seaf->http_server->http_temp_dir,
                                     file_name);
        tmp_fd = g_mkstemp_full (temp_file, O_RDWR, cluster_shared_temp_file_mode);
        if (tmp_fd < 0) {
            seaf_warning ("Failed to create upload temp file: %s.\n", strerror(errno));
            ret = -1;
            goto out;
        }

        if (seaf_repo_manager_add_upload_tmp_file (seaf->repo_mgr,
                                                   fsm->repo_id,
                                                   abs_path, temp_file,
                                                   &error) < 0) {
            seaf_warning ("%s\n", error->message);
            g_clear_error (&error);
            close (tmp_fd);
            g_unlink (temp_file);
            tmp_fd = -1;
            ret = -1;
            goto out;
        }
    } else {
        tmp_fd = g_open (temp_file, O_WRONLY);
        if (tmp_fd < 0) {
            seaf_warning ("Failed to open upload temp file: %s.\n", strerror(errno));
            if (errno == ENOENT) {
                seaf_message ("Upload temp file %s doesn't exist, remove record from db.\n",
                              temp_file);
                seaf_repo_manager_del_upload_tmp_file (seaf->repo_mgr, fsm->repo_id,
                                                       abs_path, &error);
            }
            ret = -1;
            goto out;
        }
    }

    if (copy_block_to_tmp_file (fsm->fd, tmp_fd, fsm->rstart) < 0) {
        ret = -1;
        goto out;
    }

    if (fsm->rend == fsm->fsize - 1) {
        // For the last block, record tmp_files for upload to seafile and remove
        fsm->files = g_list_prepend (fsm->files, g_strdup(temp_file)); // for virus checking, indexing...
    }

out:
    g_free (abs_path);
    if (tmp_fd >= 0) {
        close (tmp_fd);
    }
    g_free (temp_file);
    close (fsm->fd);
    g_unlink (fsm->tmp_file);
    g_free (fsm->tmp_file);
    fsm->tmp_file = NULL;

    return ret;
}
/*
  Handle AJAX file upload.
  @return an array of json data, e.g. [{"name": "foo.txt"}]
 */
static void
upload_ajax_cb(evhtp_request_t *req, void *arg)
{
    RecvFSM *fsm = arg;
    char *parent_dir = NULL, *relative_path = NULL, *new_parent_dir = NULL;
    char *last_modify = NULL;
    gint64 mtime = 0;
    GError *error = NULL;
    int error_code = -1;
    char *filenames_json, *tmp_files_json;
    int rc;

    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Access-Control-Allow-Headers",
                                               "x-requested-with, content-type, content-range, content-disposition, accept, origin, authorization", 1, 1));
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Access-Control-Allow-Methods",
                                               "GET, POST, PUT, PATCH, DELETE, OPTIONS", 1, 1));
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Access-Control-Allow-Origin",
                                               "*", 1, 1));
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Access-Control-Max-Age",
                                               "86400", 1, 1));

    if (evhtp_request_get_method(req) == htp_method_OPTIONS) {
        /* If CORS preflight header, then create an empty body response (200 OK)
         * and return it.
         */
        send_success_reply (req);
        return;
    }

    /* After upload_headers_cb() returns an error, libevhtp may still
     * receive data from the web browser and call into this cb.
     * In this case fsm will be NULL.
     */
    if (!fsm || fsm->state == RECV_ERROR)
        return;

    parent_dir = g_hash_table_lookup (fsm->form_kvs, "parent_dir");
    if (!parent_dir) {
        seaf_debug ("[upload] No parent dir given.\n");
        send_error_reply (req, EVHTP_RES_BADREQ, "Invalid parent dir.");
        return;
    }

    last_modify = g_hash_table_lookup (fsm->form_kvs, "last_modify");
    if (last_modify) {
        mtime = rfc3339_to_timestamp (last_modify);
    }

    if (!fsm->filenames) {
        seaf_debug ("[upload] No file uploaded.\n");
        send_error_reply (req, EVHTP_RES_BADREQ, "No file uploaded.\n");
        return;
    }

    relative_path = g_hash_table_lookup (fsm->form_kvs, "relative_path");
    if (relative_path != NULL) {
        if (relative_path[0] == '/' || relative_path[0] == '\\') {
            seaf_warning ("Invalid relative path %s.\n", relative_path);
            send_error_reply (req, EVHTP_RES_BADREQ, "Invalid relative path.");
            return;
        }
        char *tmp_p = get_canonical_path(parent_dir);
        char *tmp_r = get_canonical_path(relative_path);
        new_parent_dir = g_build_path("/", tmp_p, tmp_r, NULL);
        g_free(tmp_p);
        g_free(tmp_r);
    } else {
        new_parent_dir = get_canonical_path(parent_dir);
    }

    if (fsm->rstart >= 0) {
        if (fsm->filenames->next) {
            seaf_debug ("[upload] Breakpoint transfer only support one file in one request.\n");
            send_error_reply (req, EVHTP_RES_BADREQ, "More files in one request.\n");
            goto out;
        }

        if (parent_dir[0] != '/') {
            seaf_debug ("[upload] Invalid parent dir, should start with /.\n");
            send_error_reply (req, EVHTP_RES_BADREQ, "Invalid parent dir.\n");
            goto out;
        }

        if (!fsm->resumable_tmp_file)
            fsm->resumable_tmp_file = g_build_path ("/", new_parent_dir, (char *)fsm->filenames->data, NULL);

        if (write_block_data_to_tmp_file (fsm, new_parent_dir,
                                          (char *)fsm->filenames->data) < 0) {
            error_code = ERROR_INTERNAL;
            goto out;
        }
        if (fsm->rend != fsm->fsize - 1) {
            const char *success_str = "{\"success\": true}";
            evbuffer_add (req->buffer_out, success_str, strlen(success_str));
            send_success_reply_ie8_compatible (req, EVHTP_RES_OK);
            goto out;
        }
    }

    if (!fsm->files) {
        seaf_debug ("[upload] No file uploaded.\n");
        send_error_reply (req, EVHTP_RES_BADREQ, "No file uploaded.\n");
        goto out;
    }

    if (!check_parent_dir (req, fsm->repo_id, parent_dir))
        goto out;

    if (!fsm->parent_dir || !is_parent_matched (fsm->parent_dir, parent_dir)){
        error_code = ERROR_FORBIDDEN;
        goto out;
    }

    if (!check_tmp_file_list (fsm->files, &error_code))
        goto out;

    gint64 content_len;
    if (fsm->fsize > 0)
        content_len = fsm->fsize;
    else
        content_len = get_content_length (req);

    if (seaf_quota_manager_check_quota_with_delta (seaf->quota_mgr,
                                                   fsm->repo_id,
                                                   content_len) != 0) {
        error_code = ERROR_QUOTA;
        goto out;
    }

    rc = create_relative_path (fsm, parent_dir, relative_path);
    if (rc < 0) {
        error_code = ERROR_INTERNAL;
        goto out;
    }

    filenames_json = file_list_to_json (fsm->filenames);
    tmp_files_json = file_list_to_json (fsm->files);

    char *ret_json = NULL;
    char *task_id = NULL;
    rc = seaf_repo_manager_post_multi_files (seaf->repo_mgr,
                                             fsm->repo_id,
                                             new_parent_dir,
                                             filenames_json,
                                             tmp_files_json,
                                             fsm->user,
                                             0,
                                             mtime,
                                             &ret_json,
                                             fsm->need_idx_progress ? &task_id : NULL,
                                             &error);
    g_free (filenames_json);
    g_free (tmp_files_json);
    if (rc < 0) {
        error_code = ERROR_INTERNAL;
        if (error) {
            if (error->code == POST_FILE_ERR_FILENAME) {
                error_code = ERROR_FILENAME;
            } else if (error->code == SEAF_ERR_FILES_WITH_SAME_NAME) {
                error_code = -1;
                send_error_reply (req, EVHTP_RES_BADREQ, "Too many files with same name.\n");
            } else if (error->code == SEAF_ERR_GC_CONFLICT) {
                error_code = -1;
                send_error_reply (req, EVHTP_RES_CONFLICT, "GC Conflict.\n");
            }
            g_clear_error (&error);
        }
        goto out;
    }

    if (task_id) {
        evbuffer_add (req->buffer_out, task_id, strlen(task_id));
        g_free (task_id);
    } else {
        evbuffer_add (req->buffer_out, ret_json, strlen(ret_json));
    }
    g_free (ret_json);

    send_success_reply_ie8_compatible (req, EVHTP_RES_OK);

    char *oper = "web-file-upload";
    if (g_strcmp0(fsm->token_type, "upload-link") == 0)
        oper = "link-file-upload";
    send_statistic_msg(fsm->repo_id, fsm->user, oper, (guint64)content_len);

out:
    g_free (new_parent_dir);
    send_reply_by_error_code (req, error_code);

    return;
}

static void
update_api_cb(evhtp_request_t *req, void *arg)
{
    RecvFSM *fsm = arg;
    char *target_file, *parent_dir = NULL, *filename = NULL;
    char *last_modify = NULL;
    gint64 mtime = 0;
    const char *head_id = NULL;
    GError *error = NULL;
    int error_code = -1;
    char *new_file_id = NULL;

    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Access-Control-Allow-Headers",
                                               "x-requested-with, content-type, content-range, content-disposition, accept, origin, authorization", 1, 1));
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Access-Control-Allow-Methods",
                                               "GET, POST, PUT, PATCH, DELETE, OPTIONS", 1, 1));
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Access-Control-Allow-Origin",
                                               "*", 1, 1));
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Access-Control-Max-Age",
                                               "86400", 1, 1));

    if (evhtp_request_get_method(req) == htp_method_OPTIONS) {
        /* If CORS preflight header, then create an empty body response (200 OK)
         * and return it.
         */
        send_success_reply (req);
        return;
    }

    if (!fsm || fsm->state == RECV_ERROR)
        return;

    if (!fsm->filenames) {
        seaf_debug ("[Update] No file uploaded.\n");
        send_error_reply (req, EVHTP_RES_BADREQ, "No file uploaded.\n");
        return;
    }

    target_file = g_hash_table_lookup (fsm->form_kvs, "target_file");
    if (!target_file) {
        seaf_debug ("[Update] No target file given.\n");
        send_error_reply (req, EVHTP_RES_BADREQ, "No target file.\n");
        return;
    }

    last_modify = g_hash_table_lookup (fsm->form_kvs, "last_modify");
    if (last_modify) {
        mtime = rfc3339_to_timestamp (last_modify);
    }

    parent_dir = g_path_get_dirname (target_file);
    filename = g_path_get_basename (target_file);
    if (!filename || filename[0] == '\0') {
        seaf_debug ("[Update] Bad target_file.\n");
        send_error_reply (req, EVHTP_RES_BADREQ, "Invalid targe_file.\n");
        goto out;
    }

    if (fsm->rstart >= 0) {
        if (fsm->filenames->next) {
            seaf_debug ("[Update] Breakpoint transfer only support one file in one request.\n");
            send_error_reply (req, EVHTP_RES_BADREQ, "More than one file in one request.\n");
            goto out;
        }

        if (parent_dir[0] != '/') {
            seaf_debug ("[Update] Invalid parent dir, should start with /.\n");
            send_error_reply (req, EVHTP_RES_BADREQ, "Invalid parent dir.\n");
            goto out;
        }

        if (!fsm->resumable_tmp_file)
            fsm->resumable_tmp_file = g_build_path ("/", parent_dir, filename, NULL);

        if (write_block_data_to_tmp_file (fsm, parent_dir, filename) < 0) {
            send_error_reply (req, EVHTP_RES_SERVERR, "Internal error.\n");
            goto out;
        }

        if (fsm->rend != fsm->fsize - 1) {
            const char *success_str = "{\"success\": true}";
            evbuffer_add (req->buffer_out, success_str, strlen(success_str));
            send_success_reply_ie8_compatible (req, EVHTP_RES_OK);
            goto out;
        }
    }

    if (!fsm->files) {
        seaf_debug ("[Update] No file uploaded.\n");
        send_error_reply (req, EVHTP_RES_BADREQ, "No file uploaded.\n");
        goto out;
    }

    if (!check_parent_dir (req, fsm->repo_id, parent_dir))
        goto out;

    if (!check_tmp_file_list (fsm->files, &error_code))
        goto out;

    head_id = evhtp_kv_find (req->uri->query, "head");

    gint64 content_len;
    if (fsm->fsize > 0)
        content_len = fsm->fsize;
    else
        content_len = get_content_length (req);
    if (seaf_quota_manager_check_quota_with_delta (seaf->quota_mgr,
                                                   fsm->repo_id,
                                                   content_len) != 0) {
        error_code = ERROR_QUOTA;
        goto out;
    }

    int rc = seaf_repo_manager_put_file (seaf->repo_mgr,
                                         fsm->repo_id,
                                         (char *)(fsm->files->data),
                                         parent_dir,
                                         filename,
                                         fsm->user,
                                         head_id,
                                         mtime,
                                         &new_file_id,
                                         &error);
    if (rc < 0) {
        error_code = ERROR_INTERNAL;
        if (error) {
            if (g_strcmp0 (error->message, "file does not exist") == 0) {
                error_code = ERROR_NOT_EXIST;
            }
            g_clear_error (&error);
        }
        goto out;
    }

    /* Send back the new file id, so that the mobile client can update local cache */
    evbuffer_add(req->buffer_out, new_file_id, strlen(new_file_id));
    send_success_reply (req);

out:
    if (fsm->rstart >= 0 && fsm->rend == fsm->fsize - 1) {
        // File upload success, try to remove tmp file from WebUploadTmpFile table
        char *abs_path;

        abs_path = g_build_path ("/", parent_dir, filename, NULL);

        seaf_repo_manager_del_upload_tmp_file (seaf->repo_mgr, fsm->repo_id, abs_path, NULL);
        g_free (abs_path);
    }
    g_free (parent_dir);
    g_free (filename);
    g_free (new_file_id);
    send_reply_by_error_code (req, error_code);

    return;
}

static void
update_blks_api_cb(evhtp_request_t *req, void *arg)
{
    RecvFSM *fsm = arg;
    char *target_file, *parent_dir = NULL, *filename = NULL, *size_str = NULL;
    char *last_modify = NULL;
    gint64 mtime = 0;
    const char *commitonly_str;
    GError *error = NULL;
    int error_code = -1;
    char *new_file_id = NULL;
    char *blockids_json;
    gint64 file_size = -1;

    if (!fsm || fsm->state == RECV_ERROR)
        return;
    target_file = g_hash_table_lookup (fsm->form_kvs, "target_file");
    size_str = g_hash_table_lookup (fsm->form_kvs, "file_size");
    if (size_str)  file_size = atoll(size_str);
    if (!target_file || !size_str || file_size < 0) {
        seaf_debug ("[Update-blks] No target file given.\n");
        send_error_reply (req, EVHTP_RES_BADREQ, "No target file.\n");
        return;
    }
    commitonly_str = evhtp_kv_find (req->uri->query, "commitonly");
    if (!commitonly_str) {
        send_error_reply (req, EVHTP_RES_BADREQ, "Only commit supported.\n");
        return;
    }

    last_modify = g_hash_table_lookup (fsm->form_kvs, "last_modify");
    if (last_modify) {
        mtime = rfc3339_to_timestamp (last_modify);
    }

    parent_dir = g_path_get_dirname (target_file);
    filename = g_path_get_basename (target_file);

    if (!check_parent_dir (req, fsm->repo_id, parent_dir))
        goto out;

    int rc = 0;
    /* if (!commitonly_str) { */
    /*     gint64 content_len = get_content_length(req); */
    /*     if (seaf_quota_manager_check_quota_with_delta (seaf->quota_mgr, */
    /*                                                    fsm->repo_id, */
    /*                                                    content_len) != 0) { */
    /*         error_code = ERROR_QUOTA; */
    /*         goto error; */
    /*     } */

    /*     if (!check_tmp_file_list (fsm->files, &error_code)) */
    /*         goto error; */

    /*     blockids_json = file_list_to_json (fsm->filenames); */
    /*     tmp_files_json = file_list_to_json (fsm->files); */
    /*     rc = seaf_repo_manager_put_file_blocks (seaf->repo_mgr, */
    /*                                             fsm->repo_id, */
    /*                                             parent_dir, */
    /*                                             filename, */
    /*                                             blockids_json, */
    /*                                             tmp_files_json, */
    /*                                             fsm->user, */
    /*                                             head_id, */
    /*                                             file_size, */
    /*                                             &new_file_id, */
    /*                                             &error); */
    /*     g_free (blockids_json); */
    /*     g_free (tmp_files_json); */
    /* } else { */

    blockids_json = g_hash_table_lookup (fsm->form_kvs, "blockids");
    if (blockids_json == NULL) {
        seaf_debug ("[upload-blks] No blockids given.\n");
        send_error_reply (req, EVHTP_RES_BADREQ, "No blockids.\n");
        goto out;
    }
    rc = seaf_repo_manager_commit_file_blocks (seaf->repo_mgr,
                                               fsm->repo_id,
                                               parent_dir,
                                               filename,
                                               blockids_json,
                                               fsm->user,
                                               file_size,
                                               1,
                                               mtime,
                                               &new_file_id,
                                               &error);

    if (rc < 0) {
        error_code = ERROR_INTERNAL;
        if (error) {
            if (g_strcmp0 (error->message, "file does not exist") == 0) {
                error_code = ERROR_NOT_EXIST;
            } else if (error->code == POST_FILE_ERR_QUOTA_FULL) {
                error_code = ERROR_QUOTA;
            } else if (error->code == SEAF_ERR_GC_CONFLICT) {
                error_code = -1;
                send_error_reply (req, EVHTP_RES_CONFLICT, "GC Conflict.\n");
            }
            g_clear_error (&error);
        }
        goto out;
    }

    /* Send back the new file id, so that the mobile client can update local cache */
    evbuffer_add(req->buffer_out, new_file_id, strlen(new_file_id));
    send_success_reply (req);

out:
    g_free (parent_dir);
    g_free (filename);
    g_free (new_file_id);
    send_reply_by_error_code (req, error_code);

    return;
}

/* static void */
/* update_blks_ajax_cb(evhtp_request_t *req, void *arg) */
/* { */
/*     RecvFSM *fsm = arg; */
/*     char *target_file, *parent_dir = NULL, *filename = NULL, *size_str = NULL; */
/*     const char *head_id = NULL; */
/*     GError *error = NULL; */
/*     int error_code = ERROR_INTERNAL; */
/*     char *blockids_json, *tmp_files_json; */
/*     gint64 file_size = -1; */

/*     evhtp_headers_add_header (req->headers_out, */
/*                               evhtp_header_new("Access-Control-Allow-Headers", */
/*                                                "x-requested-with, content-type, accept, origin, authorization", 1, 1)); */
/*     evhtp_headers_add_header (req->headers_out, */
/*                               evhtp_header_new("Access-Control-Allow-Methods", */
/*                                                "GET, POST, PUT, PATCH, DELETE, OPTIONS", 1, 1)); */
/*     evhtp_headers_add_header (req->headers_out, */
/*                               evhtp_header_new("Access-Control-Allow-Origin", */
/*                                                "*", 1, 1)); */
/*     evhtp_headers_add_header (req->headers_out, */
/*                               evhtp_header_new("Access-Control-Max-Age", */
/*                                                "86400", 1, 1)); */

/*     if (evhtp_request_get_method(req) == htp_method_OPTIONS) { */
/*         /\* If CORS preflight header, then create an empty body response (200 OK) */
/*          * and return it. */
/*          *\/ */
/*         send_success_reply (req); */
/*         return; */
/*     } */

/*     if (!fsm || fsm->state == RECV_ERROR) */
/*         return; */
/*     target_file = g_hash_table_lookup (fsm->form_kvs, "target_file"); */
/*     size_str = g_hash_table_lookup (fsm->form_kvs, "file_size"); */
/*     if (size_str)  file_size = atoll(size_str); */
/*     if (!target_file || !size_str || file_size < 0) { */
/*         seaf_debug ("[Update-blks] No target file given.\n"); */
/*         send_error_reply (req, EVHTP_RES_BADREQ, "Invalid URL.\n"); */
/*         return; */
/*     } */

/*     parent_dir = g_path_get_dirname (target_file); */
/*     filename = g_path_get_basename (target_file); */

/*     if (!check_parent_dir (req, fsm->repo_id, parent_dir)) */
/*         return; */

/*     if (!check_tmp_file_list (fsm->files, &error_code)) */
/*         goto error; */

/*     head_id = evhtp_kv_find (req->uri->query, "head"); */

/*     gint64 content_len = get_content_length (req); */
/*     if (seaf_quota_manager_check_quota_with_delta (seaf->quota_mgr, */
/*                                                    fsm->repo_id, */
/*                                                    content_len) != 0) { */
/*         error_code = ERROR_QUOTA; */
/*         goto error; */
/*     } */

/*     blockids_json = file_list_to_json (fsm->filenames); */
/*     tmp_files_json = file_list_to_json (fsm->files); */
/*     int rc = seaf_repo_manager_put_file_blocks (seaf->repo_mgr, */
/*                                                 fsm->repo_id, */
/*                                                 parent_dir, */
/*                                                 filename, */
/*                                                 blockids_json, */
/*                                                 tmp_files_json, */
/*                                                 fsm->user, */
/*                                                 head_id, */
/*                                                 file_size, */
/*                                                 NULL, */
/*                                                 &error); */
/*     g_free (blockids_json); */
/*     g_free (tmp_files_json); */
/*     g_free (parent_dir); */
/*     g_free (filename); */

/*     if (rc < 0) { */
/*         if (error) { */
/*             if (g_strcmp0 (error->message, "file does not exist") == 0) { */
/*                 error_code = ERROR_NOT_EXIST; */
/*             } */
/*             g_clear_error (&error); */
/*         } */
/*         goto error; */
/*     } */

/*     send_success_reply (req); */

/*     return; */

/* error: */
/*     switch (error_code) { */
/*     case ERROR_FILENAME: */
/*         send_error_reply (req, SEAF_HTTP_RES_BADFILENAME, "Invalid filename.\n"); */
/*         break; */
/*     case ERROR_EXISTS: */
/*         send_error_reply (req, SEAF_HTTP_RES_EXISTS, "File already exists.\n"); */
/*         break; */
/*     case ERROR_SIZE: */
/*         send_error_reply (req, SEAF_HTTP_RES_TOOLARGE, "File size is too large.\n"); */
/*         break; */
/*     case ERROR_QUOTA: */
/*         send_error_reply (req, SEAF_HTTP_RES_NOQUOTA, "Out of quota.\n"); */
/*         break; */
/*     case ERROR_NOT_EXIST: */
/*         send_error_reply (req, SEAF_HTTP_RES_NOT_EXISTS, "File does not exist.\n"); */
/*         break; */
/*     case ERROR_RECV: */
/*     case ERROR_INTERNAL: */
/*     default: */
/*         send_error_reply (req, EVHTP_RES_SERVERR, "Internal error.\n"); */
/*         break; */
/*     } */
/* } */

static char *
format_update_json_ret (const char *filename, const char *file_id, gint64 size)
{
    json_t *array, *obj;
    char *json_data;
    char *ret;

    array = json_array ();

    obj = json_object ();
    json_object_set_string_member (obj, "name", filename);
    json_object_set_string_member (obj, "id", file_id);
    json_object_set_int_member (obj, "size", size);
    json_array_append_new (array, obj);

    json_data = json_dumps (array, 0);
    json_decref (array);

    ret = g_strdup (json_data);
    free (json_data);
    return ret;
}

static void
update_ajax_cb(evhtp_request_t *req, void *arg)
{
    RecvFSM *fsm = arg;
    char *target_file, *parent_dir = NULL, *filename = NULL;
    char *last_modify = NULL;
    gint64 mtime = 0;
    const char *head_id = NULL;
    GError *error = NULL;
    int error_code = -1;
    char *new_file_id = NULL;
    gint64 size;

    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Access-Control-Allow-Headers",
                                               "x-requested-with, content-type, accept, origin, authorization", 1, 1));
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Access-Control-Allow-Methods",
                                               "GET, POST, PUT, PATCH, DELETE, OPTIONS", 1, 1));
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Access-Control-Allow-Origin",
                                               "*", 1, 1));
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Access-Control-Max-Age",
                                               "86400", 1, 1));


    if (evhtp_request_get_method(req) == htp_method_OPTIONS) {
        /* If CORS preflight header, then create an empty body response (200 OK)
         * and return it.
         */
        send_success_reply (req);
        return;
    }

    if (!fsm || fsm->state == RECV_ERROR)
        return;

    if (!fsm->files) {
        seaf_debug ("[update] No file uploaded.\n");
        send_error_reply (req, EVHTP_RES_BADREQ, "No file uploaded.\n");
        return;
    }

    target_file = g_hash_table_lookup (fsm->form_kvs, "target_file");
    if (!target_file) {
        seaf_debug ("[Update] No target file given.\n");
        send_error_reply (req, EVHTP_RES_BADREQ, "No target file.");
        return;
    }

    last_modify = g_hash_table_lookup (fsm->form_kvs, "last_modify");
    if (last_modify) {
        mtime = rfc3339_to_timestamp (last_modify);
    }

    parent_dir = g_path_get_dirname (target_file);
    filename = g_path_get_basename (target_file);

    if (!check_parent_dir (req, fsm->repo_id, parent_dir))
        goto out;

    if (!check_tmp_file_list (fsm->files, &error_code))
        goto out;

    SeafStat st;
    char *tmp_file_path = fsm->files->data;
    if (seaf_stat (tmp_file_path, &st) < 0) {
        seaf_warning ("Failed to stat tmp file %s.\n", tmp_file_path);
        error_code = ERROR_INTERNAL;
        goto out;
    }
    size = (gint64)st.st_size;

    head_id = evhtp_kv_find (req->uri->query, "head");

    gint64 content_len = get_content_length (req);
    if (seaf_quota_manager_check_quota_with_delta (seaf->quota_mgr,
                                                   fsm->repo_id,
                                                   content_len) != 0) {
        error_code = ERROR_QUOTA;
        goto out;
    }

    int rc = seaf_repo_manager_put_file (seaf->repo_mgr,
                                         fsm->repo_id,
                                         (char *)(fsm->files->data),
                                         parent_dir,
                                         filename,
                                         fsm->user,
                                         head_id,
                                         mtime,
                                         &new_file_id,
                                         &error);

    if (rc < 0) {
        error_code = ERROR_INTERNAL;
        if (error) {
            if (g_strcmp0 (error->message, "file does not exist") == 0) {
                error_code = ERROR_NOT_EXIST;
            } else if (error->code == SEAF_ERR_GC_CONFLICT) {
                error_code = -1;
                send_error_reply (req, EVHTP_RES_CONFLICT, "GC Conflict.\n");
            }
            g_clear_error (&error);
        }
        goto out;
    }
    send_statistic_msg(fsm->repo_id, fsm->user, "web-file-upload", (guint64)content_len);

    char *json_ret = format_update_json_ret (filename, new_file_id, size);

    evbuffer_add (req->buffer_out, json_ret, strlen(json_ret));
    send_success_reply (req);
    g_free (json_ret);

out:
    g_free (parent_dir);
    g_free (new_file_id);
    g_free (filename);
    send_reply_by_error_code (req, error_code);

    return;
}

/*
static void
upload_link_cb(evhtp_request_t *req, void *arg)
{
    return upload_api_cb (req, arg);
}
*/

static evhtp_res
upload_finish_cb (evhtp_request_t *req, void *arg)
{
    RecvFSM *fsm = arg;
    GList *ptr;

    seaf_metric_manager_in_flight_request_dec (seaf->metric_mgr);

    if (!fsm)
        return EVHTP_RES_OK;

    /* Clean up FSM struct no matter upload succeed or not. */

    g_free (fsm->parent_dir);
    g_free (fsm->user);
    g_free (fsm->boundary);
    g_free (fsm->input_name);
    g_free (fsm->token_type);

    g_hash_table_destroy (fsm->form_kvs);

    g_free (fsm->file_name);
    if (fsm->tmp_file) {
        close (fsm->fd);
        // For resumable upload, in case tmp file not be deleted
        if (fsm->rstart >= 0) {
            g_unlink (fsm->tmp_file);
        }
    }
    g_free (fsm->tmp_file);

    if (fsm->resumable_tmp_file) {
        if (fsm->rstart >= 0 && fsm->rend == fsm->fsize - 1) {
            seaf_repo_manager_del_upload_tmp_file (seaf->repo_mgr, fsm->repo_id, fsm->resumable_tmp_file, NULL);
        }
        g_free (fsm->resumable_tmp_file);
    }

    g_free (fsm->repo_id);

    if (!fsm->need_idx_progress) {
        for (ptr = fsm->files; ptr; ptr = ptr->next)
            g_unlink ((char *)(ptr->data));
    }
    string_list_free (fsm->filenames);
    string_list_free (fsm->files);

    evbuffer_free (fsm->line);

    if (fsm->progress_id) {
        pthread_mutex_lock (&pg_lock);
        g_hash_table_remove (upload_progress, fsm->progress_id);
        pthread_mutex_unlock (&pg_lock);

        /* fsm->progress has been free'd by g_hash_table_remove(). */
        g_free (fsm->progress_id);
    }

    g_free (fsm);

    return EVHTP_RES_OK;
}

static char *
get_mime_header_param_value (const char *param)
{
    char *first_quote, *last_quote;
    char *value;

    // param may not start with double quotes. 
    first_quote = strchr (param, '\"');
    if (!first_quote) {
        return g_strdup (param);
    }
    last_quote = strrchr (param, '\"');
    if (!first_quote || !last_quote || first_quote == last_quote) {
        seaf_debug ("[upload] Invalid mime param %s.\n", param);
        return NULL;
    }

    value = g_strndup (first_quote + 1, last_quote - first_quote - 1);
    return value;
}

static char *
parse_file_name_from_header (evhtp_request_t *req)
{
    const char *dispose = NULL;
    char **p;
    char **params;
    char *dec_file_name = NULL;

    dispose = evhtp_kv_find (req->headers_in, "Content-Disposition");
    if (!dispose)
        return NULL;

    params = g_strsplit (dispose, ";", 2);
    for (p = params; *p != NULL; ++p)
        *p = g_strstrip (*p);

    if (g_strv_length (params) != 2 ||
        strcasecmp (params[0], "attachment") != 0 ||
        strncasecmp (params[1], "filename", strlen("filename")) != 0) {
        seaf_warning ("[upload] Invalid Content-Disposition header.\n");
        g_strfreev (params);
        return NULL;
    }

    char *file_name = get_mime_header_param_value (params[1]);
    if (file_name)
        dec_file_name = g_uri_unescape_string (file_name, NULL);
    g_free (file_name);
    g_strfreev (params);

    return dec_file_name;
}

static int
parse_mime_header (evhtp_request_t *req, char *header, RecvFSM *fsm)
{
    char *colon;
    char **params, **p;

    colon = strchr (header, ':');
    if (!colon) {
        seaf_debug ("[upload] bad mime header format.\n");
        return -1;
    }

    *colon = 0;
    // Content-Disposition is case-insensitive.
    if (strcasecmp (header, "Content-Disposition") == 0) {
        params = g_strsplit (colon + 1, ";", 3);
        for (p = params; *p != NULL; ++p)
            *p = g_strstrip (*p);

        if (g_strv_length (params) < 2) {
            seaf_debug ("[upload] Too little params for mime header.\n");
            g_strfreev (params);
            return -1;
        }
        if (strcasecmp (params[0], "form-data") != 0) {
            seaf_debug ("[upload] Invalid Content-Disposition\n");
            g_strfreev (params);
            return -1;
        }

        for (p = params; *p != NULL; ++p) {
            if (strncasecmp (*p, "name", strlen("name")) == 0) {
                fsm->input_name = get_mime_header_param_value (*p);
                break;
            }
        }
        if (!fsm->input_name) {
            seaf_debug ("[upload] No input-name given.\n");
            g_strfreev (params);
            return -1;
        }

        if (strcmp (fsm->input_name, "file") == 0) {
            char *file_name;
            for (p = params; *p != NULL; ++p) {
                if (strncasecmp (*p, "filename", strlen("filename")) == 0) {
                    if (fsm->rstart >= 0) {
                        file_name = parse_file_name_from_header (req);
                    } else {
                        file_name = get_mime_header_param_value (*p);
                    }
                    if (file_name) {
                        fsm->file_name = normalize_utf8_path (file_name);
                        if (!fsm->file_name)
                            seaf_debug ("File name is not valid utf8 encoding.\n");
                        g_free (file_name);
                    }
                    break;
                }
            }
            if (!fsm->file_name) {
                seaf_debug ("[upload] No filename given.\n");
                g_strfreev (params);
                return -1;
            }
        }
        g_strfreev (params);
    }

    return 0;
}

static int
open_temp_file (RecvFSM *fsm)
{
    GString *temp_file = g_string_new (NULL);
    char *base_name = get_basename(fsm->file_name);

    g_string_printf (temp_file, "%s/%sXXXXXX",
                     seaf->http_server->http_temp_dir, base_name);
    g_free (base_name);

    fsm->fd = g_mkstemp (temp_file->str);
    if (fsm->fd < 0) {
        seaf_warning("[upload] Failed to open temp file: %s.\n", strerror(errno));
        g_string_free (temp_file, TRUE);
        return -1;
    }

    fsm->tmp_file = g_string_free (temp_file, FALSE);
    /* For clean up later. */
    if (fsm->rstart < 0) {
        fsm->files = g_list_prepend (fsm->files, g_strdup(fsm->tmp_file));
    }

    return 0;
}

static evhtp_res
recv_form_field (RecvFSM *fsm, gboolean *no_line)
{
    char *line, *norm_line;
    size_t len;

    *no_line = FALSE;

    line = evbuffer_readln (fsm->line, &len, EVBUFFER_EOL_CRLF_STRICT);
    if (line != NULL) {
        if (strstr (line, fsm->boundary) != NULL) {
            seaf_debug ("[upload] form field ends.\n");

            g_free (fsm->input_name);
            fsm->input_name = NULL;
            fsm->state = RECV_HEADERS;
        } else {
            seaf_debug ("[upload] form field is %s.\n", line);

            norm_line = normalize_utf8_path (line);
            if (norm_line) {
                g_hash_table_insert (fsm->form_kvs,
                                     g_strdup(fsm->input_name),
                                     norm_line);
            }
        }
        free (line);
    } else {
        size_t size = evbuffer_get_length (fsm->line);
        if (size >= strlen(fsm->boundary) + 4) {
            struct evbuffer_ptr search_boundary = evbuffer_search (fsm->line,
                                                                   fsm->boundary,
                                                                   strlen(fsm->boundary),
                                                                   NULL);
            if (search_boundary.pos != -1) {
                seaf_debug ("[upload] form field ends.\n");
                evbuffer_drain (fsm->line, size);
                g_free (fsm->input_name);
                fsm->input_name = NULL;
                fsm->state = RECV_HEADERS;
            }
        }
        *no_line = TRUE;
    }

    return EVHTP_RES_OK;
}

static evhtp_res
add_uploaded_file (RecvFSM *fsm)
{
    if (fsm->rstart < 0) {
        // Non breakpoint transfer, same as original

        /* In case of using NFS, the error may only occur in close(). */
        if (close (fsm->fd) < 0) {
            seaf_warning ("[upload] Failed to close temp file: %s\n", strerror(errno));
            return EVHTP_RES_SERVERR;
        }

        fsm->filenames = g_list_prepend (fsm->filenames,
                                         get_basename(fsm->file_name));

        g_free (fsm->file_name);
        g_free (fsm->tmp_file);
        fsm->file_name = NULL;
        fsm->tmp_file = NULL;
        fsm->recved_crlf = FALSE;
    } else {
        fsm->filenames = g_list_prepend (fsm->filenames,
                                         get_basename(fsm->file_name));
        g_free (fsm->file_name);
        fsm->file_name = NULL;
        fsm->recved_crlf = FALSE;
    }

    return EVHTP_RES_OK;
}

static evhtp_res
recv_file_data (RecvFSM *fsm, gboolean *no_line)
{
    char *line;
    size_t len;

    *no_line = FALSE;

    line = evbuffer_readln (fsm->line, &len, EVBUFFER_EOL_CRLF_STRICT);
    if (!line) {
        // handle boundary
        size_t size = evbuffer_get_length (fsm->line);
        /* If we haven't read an entire line, but the line
         * buffer gets too long, flush the content to file,
         * or we reach the last boundary line (without CRLF at the end).
         * Since the last boundary line starts with "--" and ends with "--"
         * we have to add 4 bytes to the boundary size.
         */
        if (size >= strlen(fsm->boundary) + 4) {
            char *buf = g_new0 (char, size + 1);
            evbuffer_remove (fsm->line, buf, size);
            // strstr need a '\0'
            if (strstr(buf, fsm->boundary) != NULL) {
                seaf_debug ("[upload] file data ends.\n");
                evhtp_res res = add_uploaded_file (fsm);
                if (res != EVHTP_RES_OK) {
                    g_free(buf);
                    return res;
                }
                g_free (fsm->input_name);
                fsm->input_name = NULL;
                fsm->state = RECV_HEADERS;
            } else {
                seaf_debug ("[upload] recv file data %d bytes.\n", size);
                if (fsm->recved_crlf) {
                    if (writen (fsm->fd, "\r\n", 2) < 0) {
                        seaf_warning ("[upload] Failed to write temp file: %s.\n",
                                   strerror(errno));
                        return EVHTP_RES_SERVERR;
                    }
                }
                if (writen (fsm->fd, buf, size) < 0) {
                    seaf_warning ("[upload] Failed to write temp file: %s.\n",
                               strerror(errno));
                    g_free (buf);
                    return EVHTP_RES_SERVERR;
                }
                fsm->recved_crlf = FALSE;
            }
            g_free(buf);
        }
        *no_line = TRUE;
    } else if (strstr (line, fsm->boundary) != NULL) {
        seaf_debug ("[upload] file data ends.\n");

        evhtp_res res = add_uploaded_file (fsm);
        if (res != EVHTP_RES_OK) {
            free (line);
            return res;
        }

        g_free (fsm->input_name);
        fsm->input_name = NULL;
        fsm->state = RECV_HEADERS;
        free (line);
    } else {
        seaf_debug ("[upload] recv file data %d bytes.\n", len + 2);
        if (fsm->recved_crlf) {
            if (writen (fsm->fd, "\r\n", 2) < 0) {
                seaf_warning ("[upload] Failed to write temp file: %s.\n",
                           strerror(errno));
                return EVHTP_RES_SERVERR;
            }
        }
        if (writen (fsm->fd, line, len) < 0) {
            seaf_warning ("[upload] Failed to write temp file: %s.\n",
                       strerror(errno));
            free (line);
            return EVHTP_RES_SERVERR;
        }
        free (line);
        fsm->recved_crlf = TRUE;
    }

    return EVHTP_RES_OK;
}

/*
   Refer to https://www.w3.org/Protocols/rfc1341/7_2_Multipart.html
   and https://tools.ietf.org/html/rfc7578
   Example multipart form-data request content format:

   --AaB03x
   Content-Disposition: form-data; name="submit-name"

   Larry
   --AaB03x
   Content-Disposition: form-data; name="file"; filename="file1.txt"
   Content-Type: text/plain

   ... contents of file1.txt ...
   --AaB03x--
*/
static evhtp_res
upload_read_cb (evhtp_request_t *req, evbuf_t *buf, void *arg)
{
    RecvFSM *fsm = arg;
    char *line;
    size_t len;
    gboolean no_line = FALSE;
    int res = EVHTP_RES_OK;

    if (fsm->state == RECV_ERROR)
        return EVHTP_RES_OK;

    /* Update upload progress. */
    if (fsm->progress) {
        fsm->progress->uploaded += (gint64)evbuffer_get_length(buf);

        seaf_debug ("progress: %lld/%lld\n",
                    fsm->progress->uploaded, fsm->progress->size);
    }

    evbuffer_add_buffer (fsm->line, buf);
    /* Drain the buffer so that evhtp don't copy it to another buffer
     * after this callback returns.
     */
    evbuffer_drain (buf, evbuffer_get_length (buf));

    while (!no_line) {
        switch (fsm->state) {
        case RECV_INIT:
            line = evbuffer_readln (fsm->line, &len, EVBUFFER_EOL_CRLF_STRICT);
            if (line != NULL) {
                seaf_debug ("[upload] boundary line: %s.\n", line);
                if (!strstr (line, fsm->boundary)) {
                    seaf_debug ("[upload] no boundary found in the first line.\n");
                    free (line);
                    res = EVHTP_RES_BADREQ;
                    goto out;
                } else {
                    fsm->state = RECV_HEADERS;
                    free (line);
                }
            } else {
                no_line = TRUE;
            }
            break;
        case RECV_HEADERS:
            line = evbuffer_readln (fsm->line, &len, EVBUFFER_EOL_CRLF_STRICT);
            if (line != NULL) {
                seaf_debug ("[upload] mime header line: %s.\n", line);
                if (len == 0) {
                    /* Read an blank line, headers end. */
                    free (line);
                    // Each part MUST contain a Content-Disposition header field
                    if (!fsm->input_name) {
                        res = EVHTP_RES_BADREQ;
                        goto out;
                    }
                    if (g_strcmp0 (fsm->input_name, "file") == 0) {
                        if (open_temp_file (fsm) < 0) {
                            seaf_warning ("[upload] Failed open temp file, errno:[%d]\n", errno);
                            res = EVHTP_RES_SERVERR;
                            goto out;
                        }
                    }
                    seaf_debug ("[upload] Start to recv %s.\n", fsm->input_name);
                    fsm->state = RECV_CONTENT;
                } else if (parse_mime_header (req, line, fsm) < 0) {
                    free (line);
                    res = EVHTP_RES_BADREQ;
                    goto out;
                } else {
                    free (line);
                }
            } else {
                no_line = TRUE;
            }
            break;
        case RECV_CONTENT:
            if (g_strcmp0 (fsm->input_name, "file") == 0)
                res = recv_file_data (fsm, &no_line);
            else
                res = recv_form_field (fsm, &no_line);

            if (res != EVHTP_RES_OK)
                goto out;

            break;
        }
    }

out:
    if (res != EVHTP_RES_OK) {
        /* Don't receive any data before the connection is closed. */
        //evhtp_request_pause (req);

        /* Set keepalive to 0. This will cause evhtp to close the
         * connection after sending the reply.
         */
        req->keepalive = 0;

        fsm->state = RECV_ERROR;
    }

    if (res == EVHTP_RES_BADREQ) {
        send_error_reply (req, EVHTP_RES_BADREQ, "Bad request.\n");
    } else if (res == EVHTP_RES_SERVERR) {
        send_error_reply (req, EVHTP_RES_SERVERR, "Internal server error\n");
    }
    return EVHTP_RES_OK;
}

static char *
get_http_header_param_value (const char *param)
{
    char *equal;
    char *value;

    equal = strchr (param, '=');
    if (!equal) {
        seaf_debug ("[upload] Invalid http header param %s.\n", param);
        return NULL;
    }

    value = g_strdup (equal + 1);
    return value;
}

static char *
get_boundary (evhtp_headers_t *hdr)
{
    const char *content_type;
    char **params, **p;
    char *boundary = NULL;

    content_type = evhtp_kv_find (hdr, "Content-Type");
    if (!content_type) {
        seaf_debug ("[upload] Missing Content-Type header\n");
        return boundary;
    }

    params = g_strsplit (content_type, ";", 0);
    for (p = params; *p != NULL; ++p)
        *p = g_strstrip (*p);

    if (!params || g_strv_length (params) < 2) {
        seaf_debug ("[upload] Too little params Content-Type header\n");
        g_strfreev (params);
        return boundary;
    }
    if (strcasecmp (params[0], "multipart/form-data") != 0) {
        seaf_debug ("[upload] Invalid Content-Type\n");
        g_strfreev (params);
        return boundary;
    }

    for (p = params; *p != NULL; ++p) {
        if (strncasecmp (*p, "boundary", strlen("boundary")) == 0) {
            boundary = get_http_header_param_value (*p);
            break;
        }
    }
    g_strfreev (params);
    if (!boundary) {
        seaf_debug ("[upload] boundary not given\n");
    }

    return boundary;
}

static int
check_access_token (const char *token,
                    const char *url_op,
                    char **repo_id,
                    char **parent_dir,
                    char **user,
                    char **token_type,
                    char **err_msg)
{
    SeafileWebAccess *webaccess;
    const char *op;
    const char *_repo_id;
    const char *_obj_id;
    const char *_parent_dir;
    json_t *parent_dir_json;

    webaccess = (SeafileWebAccess *)
        seaf_web_at_manager_query_access_token (seaf->web_at_mgr, token);
    if (!webaccess) {
        *err_msg = "Access token not found.";
        return -1;
    }

    _repo_id = seafile_web_access_get_repo_id (webaccess);
    int status = seaf_repo_manager_get_repo_status(seaf->repo_mgr, _repo_id);
    if (status != REPO_STATUS_NORMAL && status != -1) {
        *err_msg = "Repo status not writable.";
        g_object_unref (webaccess);
        return -1;
    }

    /* token with op = "upload" can only be used for "upload-*" operations;
     * token with op = "update" can only be used for "update-*" operations.
     */
    op = seafile_web_access_get_op (webaccess);
    if (token_type)
        *token_type = g_strdup (op);

    if (g_strcmp0(op, "upload-link") == 0)
        op = "upload";

    if (strncmp (url_op, op, strlen(op)) != 0) {
        *err_msg = "Operation does not match access token.";
        g_object_unref (webaccess);
        return -1;
    }

    *repo_id = g_strdup (_repo_id);
    *user = g_strdup (seafile_web_access_get_username (webaccess));

    _obj_id  = seafile_web_access_get_obj_id (webaccess);
    parent_dir_json = json_loadb (_obj_id, strlen (_obj_id), 0, NULL);
    if (parent_dir_json) {
        _parent_dir = json_object_get_string_member (parent_dir_json, "parent_dir");
        
        if (_parent_dir){
            *parent_dir = g_strdup(_parent_dir);
        }
        json_decref (parent_dir_json);
    }

    g_object_unref (webaccess);

    return 0;
}

static gboolean
parse_range_val (evhtp_headers_t *hdr, gint64 *rstart,
                 gint64 *rend, gint64 *rfsize)
{
    const char *tmp = evhtp_kv_find (hdr, "Content-Range");
    if (!tmp)
        return TRUE;

    char *next = NULL;
    gint64 start;
    gint64 end;
    gint64 fsize;

    if (strstr (tmp, "bytes") != tmp) {
        return FALSE;
    }

    tmp += strlen("bytes");
    while (tmp && *tmp == ' ') {
        tmp++;
    }

    start = strtoll (tmp, &next, 10);
    if ((start == 0 && next == tmp) || *next != '-') {
        return FALSE;
    }

    tmp = next + 1;
    end = strtoll (tmp, &next, 10);
    if ((end == 0 && next == tmp) || *next != '/') {
        return FALSE;
    }

    tmp = next + 1;
    fsize = strtoll (tmp, &next, 10);
    if ((fsize == 0 && next == tmp) || *next != '\0') {
        return FALSE;
    }

    if (start > end || end >= fsize) {
        return FALSE;
    }

    *rstart = start;
    *rend = end;
    *rfsize = fsize;

    return TRUE;
}

static int
get_progress_info (evhtp_request_t *req,
                   evhtp_headers_t *hdr,
                   gint64 *content_len,
                   char **progress_id)
{
    const char *content_len_str;
    const char *uuid;

    uuid = evhtp_kv_find (req->uri->query, "X-Progress-ID");
    /* If progress id is not given, we don't need content-length either. */
    if (!uuid)
        return 0;
    *progress_id = g_strdup(uuid);

    content_len_str = evhtp_kv_find (hdr, "Content-Length");
    if (!content_len_str) {
        seaf_debug ("[upload] Content-Length not found.\n");
        return -1;
    }
    *content_len = strtoll (content_len_str, NULL, 10);

    return 0;
}

static evhtp_res
upload_headers_cb (evhtp_request_t *req, evhtp_headers_t *hdr, void *arg)
{
    char **parts = NULL;
    char *token, *repo_id = NULL, *user = NULL;
    char *parent_dir = NULL;
    char *boundary = NULL;
    gint64 content_len;
    char *progress_id = NULL;
    char *err_msg = NULL;
    char *token_type = NULL;
    RecvFSM *fsm = NULL;
    Progress *progress = NULL;
    int error_code = EVHTP_RES_BADREQ;

    if (evhtp_request_get_method(req) == htp_method_OPTIONS) {
         return EVHTP_RES_OK;
    }

    /* URL format: http://host:port/[upload|update]/<token>?X-Progress-ID=<uuid> */
    token = req->uri->path->file;
    if (!token) {
        seaf_debug ("[upload] No token in url.\n");
        err_msg = "No token in url";
        goto err;
    }

    parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    if (!parts || g_strv_length (parts) < 2) {
        err_msg = "Invalid URL";
        goto err;
    }
    char *url_op = parts[0];

    if (check_access_token (token, url_op, &repo_id, &parent_dir, &user, &token_type, &err_msg) < 0) {
        error_code = EVHTP_RES_FORBIDDEN;
        goto err;
    }

    boundary = get_boundary (hdr);
    if (!boundary) {
        err_msg = "Wrong boundary in url";
        goto err;
    }

    if (get_progress_info (req, hdr, &content_len, &progress_id) < 0) {
        err_msg = "No progress info";
        goto err;
    }

    if (progress_id != NULL) {
        pthread_mutex_lock (&pg_lock);
        if (g_hash_table_lookup (upload_progress, progress_id)) {
            pthread_mutex_unlock (&pg_lock);
            err_msg = "Duplicate progress id.\n";
            goto err;
        }
        pthread_mutex_unlock (&pg_lock);
    }

    gint64 rstart = -1;
    gint64 rend = -1;
    gint64 fsize = -1;
    if (!parse_range_val (hdr, &rstart, &rend, &fsize)) {
        seaf_warning ("Invalid Seafile-Content-Range value.\n");
        err_msg = "Invalid Seafile-Content-Range";
        goto err;
    }

    fsm = g_new0 (RecvFSM, 1);
    fsm->boundary = boundary;
    fsm->repo_id = repo_id;
    fsm->parent_dir = parent_dir;
    fsm->user = user;
    fsm->token_type = token_type;
    fsm->rstart = rstart;
    fsm->rend = rend;
    fsm->fsize = fsize;
    fsm->line = evbuffer_new ();
    fsm->form_kvs = g_hash_table_new_full (g_str_hash, g_str_equal,
                                           g_free, g_free);
    /* const char *need_idx_progress = evhtp_kv_find (req->uri->query, "need_idx_progress"); */
    /* if (g_strcmp0(need_idx_progress, "true") == 0) */
    /*     fsm->need_idx_progress = TRUE; */
    fsm->need_idx_progress = FALSE;

    if (progress_id != NULL) {
        progress = g_new0 (Progress, 1);
        progress->size = content_len;
        fsm->progress_id = progress_id;
        fsm->progress = progress;

        pthread_mutex_lock (&pg_lock);
        g_hash_table_insert (upload_progress, g_strdup(progress_id), progress);
        pthread_mutex_unlock (&pg_lock);
    }

    seaf_metric_manager_in_flight_request_inc (seaf->metric_mgr);

    /* Set up per-request hooks, so that we can read file data piece by piece. */
    evhtp_set_hook (&req->hooks, evhtp_hook_on_read, upload_read_cb, fsm);
    evhtp_set_hook (&req->hooks, evhtp_hook_on_request_fini, upload_finish_cb, fsm);
    /* Set arg for upload_cb or update_cb. */
    req->cbarg = fsm;

    g_strfreev (parts);

    return EVHTP_RES_OK;

err:
    /* Don't receive any data before the connection is closed. */
    //evhtp_request_pause (req);

    /* Set keepalive to 0. This will cause evhtp to close the
     * connection after sending the reply.
     */
    req->keepalive = 0;
    send_error_reply (req, error_code, err_msg);

    g_free (repo_id);
    g_free (user);
    g_free (boundary);
    g_free (token_type);
    g_free (progress_id);
    g_strfreev (parts);
    return EVHTP_RES_OK;
}

/*
static evhtp_res
upload_link_headers_cb (evhtp_request_t *req, evhtp_headers_t *hdr, void *arg)
{
    char **parts = NULL;
    char *token = NULL;
    const char *repo_id = NULL, *parent_dir = NULL;
    char *r_parent_dir = NULL;
    char *norm_parent_dir = NULL;
    char *user = NULL;
    char *boundary = NULL;
    gint64 content_len;
    char *progress_id = NULL;
    char *err_msg = NULL;
    RecvFSM *fsm = NULL;
    Progress *progress = NULL;
    int error_code = EVHTP_RES_BADREQ;
    SeafileShareLinkInfo *info = NULL;

    if (!seaf->seahub_pk) {
        seaf_warning ("No seahub private key is configured.\n");
        return EVHTP_RES_NOTFOUND;
    }

    if (evhtp_request_get_method(req) == htp_method_OPTIONS) {
         return EVHTP_RES_OK;
    }

    token = req->uri->path->file;
    if (!token) {
        seaf_debug ("[upload] No token in url.\n");
        err_msg = "No token in url";
        goto err;
    }

    parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    if (!parts || g_strv_length (parts) < 2) {
        err_msg = "Invalid URL";
        goto err;
    }

    info = http_tx_manager_query_access_token (token, "upload");
    if (!info) {
        err_msg = "Access token not found\n";
        error_code = EVHTP_RES_FORBIDDEN;
        goto err;
    }
    repo_id = seafile_share_link_info_get_repo_id (info);
    parent_dir = seafile_share_link_info_get_parent_dir (info);
    if (!parent_dir) {
        err_msg = "No parent_dir\n";
        goto err;
    }
    norm_parent_dir = normalize_utf8_path (parent_dir); 
    r_parent_dir = format_dir_path (norm_parent_dir);

    user = seaf_repo_manager_get_repo_owner (seaf->repo_mgr, repo_id);

    boundary = get_boundary (hdr);
    if (!boundary) {
        err_msg = "Wrong boundary in url";
        goto err;
    }

    if (get_progress_info (req, hdr, &content_len, &progress_id) < 0) {
        err_msg = "No progress info";
        goto err;
    }

    if (progress_id != NULL) {
        pthread_mutex_lock (&pg_lock);
        if (g_hash_table_lookup (upload_progress, progress_id)) {
            pthread_mutex_unlock (&pg_lock);
            err_msg = "Duplicate progress id.\n";
            goto err;
        }
        pthread_mutex_unlock (&pg_lock);
    }

    gint64 rstart = -1;
    gint64 rend = -1;
    gint64 fsize = -1;
    if (!parse_range_val (hdr, &rstart, &rend, &fsize)) {
        seaf_warning ("Invalid Seafile-Content-Range value.\n");
        err_msg = "Invalid Seafile-Content-Range";
        goto err;
    }

    fsm = g_new0 (RecvFSM, 1);
    fsm->boundary = boundary;
    fsm->repo_id = g_strdup (repo_id);
    fsm->parent_dir = r_parent_dir;
    fsm->user = user;
    fsm->token_type = "upload-link";
    fsm->rstart = rstart;
    fsm->rend = rend;
    fsm->fsize = fsize;
    fsm->line = evbuffer_new ();
    fsm->form_kvs = g_hash_table_new_full (g_str_hash, g_str_equal,
                                           g_free, g_free);
    // const char *need_idx_progress = evhtp_kv_find (req->uri->query, "need_idx_progress");
    // if (g_strcmp0(need_idx_progress, "true") == 0) 
    //     fsm->need_idx_progress = TRUE; 
    fsm->need_idx_progress = FALSE;

    if (progress_id != NULL) {
        progress = g_new0 (Progress, 1);
        progress->size = content_len;
        fsm->progress_id = progress_id;
        fsm->progress = progress;

        pthread_mutex_lock (&pg_lock);
        g_hash_table_insert (upload_progress, g_strdup(progress_id), progress);
        pthread_mutex_unlock (&pg_lock);
    }

    // Set up per-request hooks, so that we can read file data piece by piece.
    evhtp_set_hook (&req->hooks, evhtp_hook_on_read, upload_read_cb, fsm);
    evhtp_set_hook (&req->hooks, evhtp_hook_on_request_fini, upload_finish_cb, fsm);
    // Set arg for upload_cb or update_cb.
    req->cbarg = fsm;

    g_free (norm_parent_dir);
    g_strfreev (parts);
    g_object_unref (info);

    return EVHTP_RES_OK;

err:
    // Don't receive any data before the connection is closed.
    // evhtp_request_pause (req);

    // Set keepalive to 0. This will cause evhtp to close the
    // connection after sending the reply.
    req->keepalive = 0;
    send_error_reply (req, error_code, err_msg);

    g_free (norm_parent_dir);
    g_free (r_parent_dir);
    g_free (user);
    g_free (boundary);
    g_free (progress_id);
    g_strfreev (parts);
    if (info)
        g_object_unref (info);
    return EVHTP_RES_OK;
}
*/

static void
idx_progress_cb(evhtp_request_t *req, void *arg)
{
    const char *progress_id;

    progress_id = evhtp_kv_find (req->uri->query, "task_id");
    if (!progress_id) {
        seaf_debug ("[get pg] Index task id not found in url.\n");
        send_error_reply (req, EVHTP_RES_BADREQ, "task id not found");
        return;
    }
    char *progress_info = index_blocks_mgr_query_progress (seaf->index_blocks_mgr,
                                                           progress_id, NULL);
    if (!progress_info) {
        send_error_reply (req, EVHTP_RES_NOTFOUND, "Failed to get index progress");
        return;
    }
    evbuffer_add (req->buffer_out, progress_info, strlen(progress_info));
    send_success_reply (req);

    g_free (progress_info);
}

static void
upload_progress_cb(evhtp_request_t *req, void *arg)
{
    const char *progress_id;
    const char *callback;
    Progress *progress;
    GString *buf;

    progress_id = evhtp_kv_find (req->uri->query, "X-Progress-ID");
    if (!progress_id) {
        seaf_debug ("[get pg] Progress id not found in url.\n");
        send_error_reply (req, EVHTP_RES_BADREQ, "Progress id not found");
        return;
    }

    callback = evhtp_kv_find (req->uri->query, "callback");
    if (!callback) {
        seaf_debug ("[get pg] callback not found in url.\n");
        send_error_reply (req, EVHTP_RES_BADREQ, "Callback not found");
        return;
    }

    pthread_mutex_lock (&pg_lock);
    progress = g_hash_table_lookup (upload_progress, progress_id);
    pthread_mutex_unlock (&pg_lock);

    if (!progress) {
        /* seaf_warning ("[get pg] No progress found for %s.\n", progress_id); */
        send_error_reply (req, EVHTP_RES_BADREQ, "No progress found.\n");
        return;
    }

    /* Return JSONP formated data. */
    buf = g_string_new (NULL);
    g_string_append_printf (buf,
                            "%s({\"uploaded\": %"G_GINT64_FORMAT", \"length\": %"G_GINT64_FORMAT"});",
                            callback, progress->uploaded, progress->size);
    evbuffer_add (req->buffer_out, buf->str, buf->len);

    seaf_debug ("JSONP: %s\n", buf->str);

    send_success_reply (req);
    g_string_free (buf, TRUE);
}

int
upload_file_init (evhtp_t *htp, const char *http_temp_dir)
{
    evhtp_callback_t *cb;

    if (g_mkdir_with_parents (http_temp_dir, 0777) < 0) {
        seaf_warning ("Failed to create temp file dir %s.\n",
                      http_temp_dir);
        return -1;
    }

    char *cluster_shared_dir = g_strdup_printf ("%s/cluster-shared", http_temp_dir);
    if (g_mkdir_with_parents (cluster_shared_dir, 0777) < 0) {
        seaf_warning ("Failed to create cluster shared dir %s.\n",
                cluster_shared_dir);
        g_free (cluster_shared_dir);
        return -1;
    }
    g_free (cluster_shared_dir);

    cb = evhtp_set_regex_cb (htp, "^/upload-api/.*", upload_api_cb, NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, upload_headers_cb, NULL);

    cb = evhtp_set_regex_cb (htp, "^/upload-raw-blks-api/.*",
                             upload_raw_blks_api_cb, NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, upload_headers_cb, NULL);

    cb = evhtp_set_regex_cb (htp, "^/upload-blks-api/.*", upload_blks_api_cb, NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, upload_headers_cb, NULL);

    /* cb = evhtp_set_regex_cb (htp, "^/upload-blks-aj/.*", upload_blks_ajax_cb, NULL); */
    /* evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, upload_headers_cb, NULL); */

    cb = evhtp_set_regex_cb (htp, "^/upload-aj/.*", upload_ajax_cb, NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, upload_headers_cb, NULL);

    cb = evhtp_set_regex_cb (htp, "^/update-api/.*", update_api_cb, NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, upload_headers_cb, NULL);

    cb = evhtp_set_regex_cb (htp, "^/update-blks-api/.*", update_blks_api_cb, NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, upload_headers_cb, NULL);

    /* cb = evhtp_set_regex_cb (htp, "^/update-blks-aj/.*", update_blks_ajax_cb, NULL); */
    /* evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, upload_headers_cb, NULL); */

    cb = evhtp_set_regex_cb (htp, "^/update-aj/.*", update_ajax_cb, NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, upload_headers_cb, NULL);

    // upload links
    // cb = evhtp_set_regex_cb (htp, "^/u/.*", upload_link_cb, NULL);
    //evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, upload_link_headers_cb, NULL);

    evhtp_set_regex_cb (htp, "^/upload_progress.*", upload_progress_cb, NULL);

    evhtp_set_regex_cb (htp, "^/idx_progress.*", idx_progress_cb, NULL);

    upload_progress = g_hash_table_new_full (g_str_hash, g_str_equal,
                                             g_free, g_free);
    pthread_mutex_init (&pg_lock, NULL);

    return 0;
}
#endif
