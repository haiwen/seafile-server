#ifndef SEAF_FSCK_H
#define SEAF_FSCK_H

typedef struct FsckOptions {
    int max_thread_num;
    gboolean check_integrity;
    gboolean check_file_size;
    gboolean repair;
} FsckOptions;

int
seaf_fsck (GList *repo_id_list, FsckOptions *options);

void export_file (GList *repo_id_list, const char *seafile_dir, char *export_path);

#endif
