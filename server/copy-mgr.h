#ifndef COPY_MGR_H
#define COPY_MGR_H

#include <glib.h>

#define COPY_ERR_INTERNAL  "Internal error when copy or move"
#define COPY_ERR_BAD_ARG  "Invalid arguments"
#define COPY_ERR_TOO_MANY_FILES "Too many files"
#define COPY_ERR_SIZE_TOO_LARGE "Folder or file size is too large"
#define COPY_ERR_QUOTA_IS_FULL  "Quota is full"

struct _SeafileSession;
struct _SeafCopyManagerPriv;
struct _SeafileCopyTask;

struct _SeafCopyManager {
    struct _SeafileSession *session;
    struct _SeafCopyManagerPriv *priv;
};
typedef struct _SeafCopyManager SeafCopyManager;
typedef struct _SeafCopyManagerPriv SeafCopyManagerPriv;

struct CopyTask {
    char task_id[37];
    gint64 done;
    gint64 total;
    gint canceled;
    gboolean failed;
    char *failed_reason;
    gboolean successful;
};
typedef struct CopyTask CopyTask;

SeafCopyManager *
seaf_copy_manager_new (struct _SeafileSession *session);

int
seaf_copy_manager_start (SeafCopyManager *mgr);

typedef int (*CopyTaskFunc) (const char *, const char *, const char *,
                             const char *, const char *, const char *,
                             int, const char *, CopyTask *);

char *
seaf_copy_manager_add_task (SeafCopyManager *mgr,
                            const char *src_repo_id,
                            const char *src_path,
                            const char *src_filename,
                            const char *dst_repo_id,
                            const char *dst_path,
                            const char *dst_filename,
                            int replace,
                            const char *modifier,
                            CopyTaskFunc function,
                            gboolean need_progress);

struct _SeafileCopyTask *
seaf_copy_manager_get_task (SeafCopyManager *mgr,
                            const char * id);

int
seaf_copy_manager_cancel_task (SeafCopyManager *mgr, const char *task_id);

#endif
