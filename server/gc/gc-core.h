#ifndef GC_CORE_H
#define GC_CORE_H

int gc_core_run (GList *repo_id_list, const char *id_prefix,
                 int dry_run, int verbose, int thread_num, int rm_fs);

void
delete_garbaged_repos (int dry_run, int thread_num);

#endif
