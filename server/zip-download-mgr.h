#ifndef ZIP_DOWNLOAD_MGR_H
#define ZIP_DOWNLOAD_MGR_H

#ifdef HAVE_EVHTP

#include "seafile-object.h"

#define MULTI_DOWNLOAD_FILE_PREFIX "documents-export-"

struct ZipDownloadMgrPriv;

typedef struct ZipDownloadMgr {
    struct ZipDownloadMgrPriv *priv;
} ZipDownloadMgr;

ZipDownloadMgr *
zip_download_mgr_new ();

int
zip_download_mgr_start_zip_task (ZipDownloadMgr *mgr,
                                 const char *token,
                                 SeafileWebAccess *info,
                                 GError **error);

char *
zip_download_mgr_start_zip_task_v2 (ZipDownloadMgr *mgr,
                                    const char *repo_id,
                                    const char *operation,
                                    const char *user,
                                    GList *dirent_list);

char *
zip_download_mgr_query_zip_progress (ZipDownloadMgr *mgr,
                                     const char *token, GError **error);

char *
zip_download_mgr_get_zip_file_path (ZipDownloadMgr *mgr,
                                    const char *token);

char *
zip_download_mgr_get_zip_file_name (ZipDownloadMgr *mgr,
                                    const char *token);

void
zip_download_mgr_del_zip_progress (ZipDownloadMgr *mgr,
                                   const char *token);

int
zip_download_mgr_cancel_zip_task (ZipDownloadMgr *mgr,
                                  const char *token);
#endif

#endif
