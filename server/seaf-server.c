/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <event2/event.h>
#else
#include <event.h>
#endif

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>

#include <glib.h>
#include <glib-object.h>

#include <searpc-server.h>
#include <searpc-client.h>

#include "seafile-session.h"
#include "seafile-rpc.h"
#include "log.h"
#include "utils.h"

#include "cdc/cdc.h"

SeafileSession *seaf;

char *pidfile = NULL;

static const char *short_options = "hvc:d:l:fP:D:F:p:tr:";
static struct option long_options[] = {
    { "help", no_argument, NULL, 'h', },
    { "version", no_argument, NULL, 'v', },
    { "config-file", required_argument, NULL, 'c' },
    { "central-config-dir", required_argument, NULL, 'F' },
    { "seafdir", required_argument, NULL, 'd' },
    { "log", required_argument, NULL, 'l' },
    { "debug", required_argument, NULL, 'D' },
    { "foreground", no_argument, NULL, 'f' },
    { "pidfile", required_argument, NULL, 'P' },
    { "rpc-pipe-path", required_argument, NULL, 'p' },
    { "test-config", no_argument, NULL, 't' },
    { "repair-repo", required_argument, NULL, 'r' },
    { NULL, 0, NULL, 0, },
};

static void usage ()
{
    fprintf (stderr, "usage: seaf-server [-c config_dir] [-d seafile_dir]\n");
}

#include <searpc.h>
#include "searpc-signature.h"
#include "searpc-marshal.h"
#include <searpc-named-pipe-transport.h>

#define SEAFILE_RPC_PIPE_NAME "seafile.sock"

#define NAMED_PIPE_SERVER_THREAD_POOL_SIZE 50

static void start_rpc_service (const char *seafile_dir,
                               const char *rpc_pipe_path)
{
    SearpcNamedPipeServer *rpc_server = NULL;
    char *pipe_path = NULL;

    searpc_server_init (register_marshals);

    searpc_create_service ("seafserv-threaded-rpcserver");

    /* threaded services */

    /* repo manipulation */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_repos_by_id_prefix,
                                     "seafile_get_repos_by_id_prefix",
                                     searpc_signature_objlist__string_int_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_repo,
                                     "seafile_get_repo",
                                     searpc_signature_object__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_destroy_repo,
                                     "seafile_destroy_repo",
                                     searpc_signature_int__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_repo_list,
                                     "seafile_get_repo_list",
                                     searpc_signature_objlist__int_int_string_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_count_repos,
                                     "seafile_count_repos",
                                     searpc_signature_int64__void());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_repo_owner,
                                     "seafile_set_repo_owner",
                                     searpc_signature_int__string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_repo_owner,
                                     "seafile_get_repo_owner",
                                     searpc_signature_string__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_orphan_repo_list,
                                     "seafile_get_orphan_repo_list",
                                     searpc_signature_objlist__void());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_edit_repo,
                                     "seafile_edit_repo",
                                     searpc_signature_int__string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_change_repo_passwd,
                                     "seafile_change_repo_passwd",
                                     searpc_signature_int__string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_upgrade_repo_pwd_hash_algorithm,
                                     "seafile_upgrade_repo_pwd_hash_algorithm",
                                     searpc_signature_int__string_string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_is_repo_owner,
                                     "seafile_is_repo_owner",
                                     searpc_signature_int__string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_owned_repos,
                                     "seafile_list_owned_repos",
                                     searpc_signature_objlist__string_int_int_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_search_repos_by_name,
                                     "seafile_search_repos_by_name",
                                     searpc_signature_objlist__string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_server_repo_size,
                                     "seafile_server_repo_size",
                                     searpc_signature_int64__string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_repo_set_access_property,
                                     "seafile_repo_set_access_property",
                                     searpc_signature_int__string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_repo_query_access_property,
                                     "seafile_repo_query_access_property",
                                     searpc_signature_string__string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_revert_on_server,
                                     "seafile_revert_on_server",
                                     searpc_signature_int__string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_diff,
                                     "seafile_diff",
                                     searpc_signature_objlist__string_string_string_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_post_file,
                                     "seafile_post_file",
                    searpc_signature_int__string_string_string_string_string());

    /* searpc_server_register_function ("seafserv-threaded-rpcserver", */
    /*                                  seafile_post_file_blocks, */
    /*                                  "seafile_post_file_blocks", */
    /*                 searpc_signature_string__string_string_string_string_string_string_int64_int()); */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_post_multi_files,
                                     "seafile_post_multi_files",
                    searpc_signature_string__string_string_string_string_string_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_put_file,
                                     "seafile_put_file",
                    searpc_signature_string__string_string_string_string_string_string());
    /* searpc_server_register_function ("seafserv-threaded-rpcserver", */
    /*                                  seafile_put_file_blocks, */
    /*                                  "seafile_put_file_blocks", */
    /*                 searpc_signature_string__string_string_string_string_string_string_string_int64()); */

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_post_empty_file,
                                     "seafile_post_empty_file",
                        searpc_signature_int__string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_post_dir,
                                     "seafile_post_dir",
                        searpc_signature_int__string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_mkdir_with_parents,
                                     "seafile_mkdir_with_parents",
                        searpc_signature_int__string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_del_file,
                                     "seafile_del_file",
                        searpc_signature_int__string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_batch_del_files,
                                     "seafile_batch_del_files",
                        searpc_signature_int__string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_copy_file,
                                     "seafile_copy_file",
       searpc_signature_object__string_string_string_string_string_string_string_int_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_move_file,
                                     "seafile_move_file",
       searpc_signature_object__string_string_string_string_string_string_int_string_int_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_rename_file,
                                     "seafile_rename_file",
                    searpc_signature_int__string_string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_is_valid_filename,
                                     "seafile_is_valid_filename",
                                     searpc_signature_int__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_create_repo,
                                     "seafile_create_repo",
                                     searpc_signature_string__string_string_string_string_int_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_create_enc_repo,
                                     "seafile_create_enc_repo",
                                     searpc_signature_string__string_string_string_string_string_string_string_int_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_commit,
                                     "seafile_get_commit",
                                     searpc_signature_object__string_int_string());
    
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_dir,
                                     "seafile_list_dir",
                                     searpc_signature_objlist__string_string_int_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_dir_with_perm,
                                     "list_dir_with_perm",
                                     searpc_signature_objlist__string_string_string_string_int_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_file_blocks,
                                     "seafile_list_file_blocks",
                                     searpc_signature_string__string_string_int_int());
    
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_file_size,
                                     "seafile_get_file_size",
                                     searpc_signature_int64__string_int_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_dir_size,
                                     "seafile_get_dir_size",
                                     searpc_signature_int64__string_int_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_dir_by_path,
                                     "seafile_list_dir_by_path",
                                     searpc_signature_objlist__string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_dir_id_by_commit_and_path,
                                     "seafile_get_dir_id_by_commit_and_path",
                                     searpc_signature_string__string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_file_id_by_path,
                                     "seafile_get_file_id_by_path",
                                     searpc_signature_string__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_dir_id_by_path,
                                     "seafile_get_dir_id_by_path",
                                     searpc_signature_string__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_dirent_by_path,
                                     "seafile_get_dirent_by_path",
                                     searpc_signature_object__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_file_revisions,
                                     "seafile_list_file_revisions",
                                     searpc_signature_objlist__string_string_string_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_calc_files_last_modified,
                                     "seafile_calc_files_last_modified",
                                     searpc_signature_objlist__string_string_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_revert_file,
                                     "seafile_revert_file",
                                     searpc_signature_int__string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_revert_dir,
                                     "seafile_revert_dir",
                                     searpc_signature_int__string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_check_repo_blocks_missing,
                                     "seafile_check_repo_blocks_missing",
                                     searpc_signature_string__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_deleted,
                                     "get_deleted",
                                     searpc_signature_objlist__string_int_string_string_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_total_file_number,
                                     "get_total_file_number",
                                     searpc_signature_int64__void());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_total_storage,
                                     "get_total_storage",
                                     searpc_signature_int64__void());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_file_count_info_by_path,
                                     "get_file_count_info_by_path",
                                     searpc_signature_object__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_trash_repo_owner,
                                     "get_trash_repo_owner",
                                     searpc_signature_string__string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_convert_repo_path,
                                     "convert_repo_path",
                                     searpc_signature_string__string_string_string_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_search_files,
                                     "search_files",
                                     searpc_signature_objlist__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_search_files_by_path,
                                     "search_files_by_path",
                                     searpc_signature_objlist__string_string_string());

    /* share repo to user */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_add_share,
                                     "seafile_add_share",
                                     searpc_signature_int__string_string_string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_share_repos,
                                     "seafile_list_share_repos",
                                     searpc_signature_objlist__string_string_int_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_repo_shared_to,
                                     "seafile_list_repo_shared_to",
                                     searpc_signature_objlist__string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_remove_share,
                                     "seafile_remove_share",
                                     searpc_signature_int__string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_share_permission,
                                     "set_share_permission",
                                     searpc_signature_int__string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_share_subdir_to_user,
                                     "share_subdir_to_user",
                                     searpc_signature_string__string_string_string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_unshare_subdir_for_user,
                                     "unshare_subdir_for_user",
                                     searpc_signature_int__string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_update_share_subdir_perm_for_user,
                                     "update_share_subdir_perm_for_user",
                                     searpc_signature_int__string_string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_shared_repo_by_path,
                                     "get_shared_repo_by_path",
                                     searpc_signature_object__string_string_string_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_shared_users_by_repo,
                                     "get_shared_users_by_repo",
                                     searpc_signature_objlist__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_org_get_shared_users_by_repo,
                                     "org_get_shared_users_by_repo",
                                     searpc_signature_objlist__int_string());

    /* share repo to group */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_group_share_repo,
                                     "seafile_group_share_repo",
                                     searpc_signature_int__string_int_string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_group_unshare_repo,
                                     "seafile_group_unshare_repo",
                                     searpc_signature_int__string_int_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_shared_groups_by_repo,
                                     "seafile_get_shared_groups_by_repo",
                                     searpc_signature_string__string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_share_subdir_to_group,
                                     "share_subdir_to_group",
                                     searpc_signature_string__string_string_string_int_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_unshare_subdir_for_group,
                                     "unshare_subdir_for_group",
                                     searpc_signature_int__string_string_string_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_update_share_subdir_perm_for_group,
                                     "update_share_subdir_perm_for_group",
                                     searpc_signature_int__string_string_string_int_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_group_repoids,
                                     "seafile_get_group_repoids",
                                     searpc_signature_string__int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_repo_shared_group,
                                     "seafile_list_repo_shared_group",
                                     searpc_signature_objlist__string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_group_shared_repo_by_path,
                                     "get_group_shared_repo_by_path",
                                     searpc_signature_object__string_string_int_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_group_repos_by_user,
                                     "get_group_repos_by_user",
                                     searpc_signature_objlist__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_org_group_repos_by_user,
                                     "get_org_group_repos_by_user",
                                     searpc_signature_objlist__string_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_repos_by_group,
                                     "seafile_get_repos_by_group",
                                     searpc_signature_objlist__int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_group_repos_by_owner,
                                     "get_group_repos_by_owner",
                                     searpc_signature_objlist__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_group_repo_owner,
                                     "get_group_repo_owner",
                                     searpc_signature_string__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_remove_repo_group,
                                     "seafile_remove_repo_group",
                                     searpc_signature_int__int_string());    

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_group_repo_permission,
                                     "set_group_repo_permission",
                                     searpc_signature_int__int_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_shared_users_for_subdir,
                                     "seafile_get_shared_users_for_subdir",
                                     searpc_signature_objlist__string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_shared_groups_for_subdir,
                                     "seafile_get_shared_groups_for_subdir",
                                     searpc_signature_objlist__string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_repo_has_been_shared,
                                     "repo_has_been_shared",
                                     searpc_signature_int__string_int());

    /* branch and commit */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_branch_gets,
                                     "seafile_branch_gets",
                                     searpc_signature_objlist__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_commit_list,
                                     "seafile_get_commit_list",
                                     searpc_signature_objlist__string_int_int());

    /* token */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_generate_repo_token,
                                     "seafile_generate_repo_token",
                                     searpc_signature_string__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_delete_repo_token,
                                     "seafile_delete_repo_token",
                                     searpc_signature_int__string_string_string());
    
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_repo_tokens,
                                     "seafile_list_repo_tokens",
                                     searpc_signature_objlist__string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_repo_tokens_by_email,
                                     "seafile_list_repo_tokens_by_email",
                                     searpc_signature_objlist__string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_delete_repo_tokens_by_peer_id,
                                     "seafile_delete_repo_tokens_by_peer_id",
                                     searpc_signature_int__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_delete_repo_tokens_by_email,
                                     "delete_repo_tokens_by_email",
                                     searpc_signature_int__string());
    
    /* quota */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_user_quota_usage,
                                     "seafile_get_user_quota_usage",
                                     searpc_signature_int64__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_user_share_usage,
                                     "seafile_get_user_share_usage",
                                     searpc_signature_int64__string());

    /* virtual repo */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_create_virtual_repo,
                                     "create_virtual_repo",
                                     searpc_signature_string__string_string_string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_virtual_repos_by_owner,
                                     "get_virtual_repos_by_owner",
                                     searpc_signature_objlist__string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_virtual_repo,
                                     "get_virtual_repo",
                                     searpc_signature_object__string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_upload_tmp_file_offset,
                                     "seafile_get_upload_tmp_file_offset",
                                     searpc_signature_int64__string_string());

    /* Clean trash */

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_clean_up_repo_history,
                                     "clean_up_repo_history",
                                     searpc_signature_int__string_int());

    /* -------- rpc services -------- */
    /* token for web access to repo */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_web_get_access_token,
                                     "seafile_web_get_access_token",
                                     searpc_signature_string__string_string_string_string_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_web_query_access_token,
                                     "seafile_web_query_access_token",
                                     searpc_signature_object__string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_query_zip_progress,
                                     "seafile_query_zip_progress",
                                     searpc_signature_string__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_cancel_zip_task,
                                     "cancel_zip_task",
                                     searpc_signature_int__string());

    /* Copy task related. */

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_copy_task,
                                     "get_copy_task",
                                     searpc_signature_object__string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_cancel_copy_task,
                                     "cancel_copy_task",
                                     searpc_signature_int__string());

    /* password management */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_check_passwd,
                                     "seafile_check_passwd",
                                     searpc_signature_int__string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_passwd,
                                     "seafile_set_passwd",
                                     searpc_signature_int__string_string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_unset_passwd,
                                     "seafile_unset_passwd",
                                     searpc_signature_int__string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_is_passwd_set,
                                     "seafile_is_passwd_set",
                                     searpc_signature_int__string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_decrypt_key,
                                     "seafile_get_decrypt_key",
                                     searpc_signature_object__string_string());

    /* quota management */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_user_quota,
                                     "set_user_quota",
                                     searpc_signature_int__string_int64());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_user_quota,
                                     "get_user_quota",
                                     searpc_signature_int64__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_check_quota,
                                     "check_quota",
                                     searpc_signature_int__string_int64());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_user_quota_usage,
                                     "list_user_quota_usage",
                                     searpc_signature_objlist__void());

    /* repo permission */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_check_permission,
                                     "check_permission",
                                     searpc_signature_string__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_repo_status,
                                     "set_repo_status",
                                     searpc_signature_int__string_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_repo_status,
                                     "get_repo_status",
                                     searpc_signature_int__string());

    /* folder permission */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_check_permission_by_path,
                                     "check_permission_by_path",
                                     searpc_signature_string__string_string_string());
    
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_file_id_by_commit_and_path,
                                     "seafile_get_file_id_by_commit_and_path",
                                     searpc_signature_string__string_string_string());

    /* event */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_publish_event,
                                     "publish_event",
                                     searpc_signature_int__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_pop_event,
                                     "pop_event",
                                     searpc_signature_json__string());

                                     
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_inner_pub_repo,
                                     "set_inner_pub_repo",
                                     searpc_signature_int__string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_unset_inner_pub_repo,
                                     "unset_inner_pub_repo",
                                     searpc_signature_int__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_is_inner_pub_repo,
                                     "is_inner_pub_repo",
                                     searpc_signature_int__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_inner_pub_repos,
                                     "list_inner_pub_repos",
                                     searpc_signature_objlist__void());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_count_inner_pub_repos,
                                     "count_inner_pub_repos",
                                     searpc_signature_int64__void());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_inner_pub_repos_by_owner,
                                     "list_inner_pub_repos_by_owner",
                                     searpc_signature_objlist__string());

    /* History */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_repo_history_limit,
                                     "set_repo_history_limit",
                                     searpc_signature_int__string_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_repo_history_limit,
                                     "get_repo_history_limit",
                                     searpc_signature_int__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_repo_valid_since,
                                     "set_repo_valid_since",
                                     searpc_signature_int__string_int64());

    /* System default library */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_system_default_repo_id,
                                     "get_system_default_repo_id",
                                     searpc_signature_string__void());

    /* Trashed repos. */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_trash_repo_list,
                                     "get_trash_repo_list",
                                     searpc_signature_objlist__int_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_del_repo_from_trash,
                                     "del_repo_from_trash",
                                     searpc_signature_int__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_restore_repo_from_trash,
                                     "restore_repo_from_trash",
                                     searpc_signature_int__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_trash_repos_by_owner,
                                     "get_trash_repos_by_owner",
                                     searpc_signature_objlist__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_empty_repo_trash,
                                     "empty_repo_trash",
                                     searpc_signature_int__void());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_empty_repo_trash_by_owner,
                                     "empty_repo_trash_by_owner",
                                     searpc_signature_int__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_generate_magic_and_random_key,
                                     "generate_magic_and_random_key",
                                     searpc_signature_object__int_string_string());

    /* Config */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_server_config_int,
                                     "get_server_config_int",
                                     searpc_signature_int__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_server_config_int,
                                     "set_server_config_int",
                                     searpc_signature_int__string_string_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_server_config_int64,
                                     "get_server_config_int64",
                                     searpc_signature_int64__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_server_config_int64,
                                     "set_server_config_int64",
                                     searpc_signature_int__string_string_int64());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_server_config_string,
                                     "get_server_config_string",
                                     searpc_signature_string__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_server_config_string,
                                     "set_server_config_string",
                                     searpc_signature_int__string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_server_config_boolean,
                                     "get_server_config_boolean",
                                     searpc_signature_int__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_server_config_boolean,
                                     "set_server_config_boolean",
                                     searpc_signature_int__string_string_int());

    /*user management*/
   searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_add_emailuser,
                                     "add_emailuser",
                                     searpc_signature_int__string_string_int_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_remove_emailuser,
                                     "remove_emailuser",
                                     searpc_signature_int__string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_validate_emailuser,
                                     "validate_emailuser",
                                     searpc_signature_int__string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_emailuser,
                                     "get_emailuser",
                                     searpc_signature_object__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_emailuser_with_import,
                                     "get_emailuser_with_import",
                                     searpc_signature_object__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_emailuser_by_id,
                                     "get_emailuser_by_id",
                                     searpc_signature_object__int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_emailusers,
                                     "get_emailusers",
                                     searpc_signature_objlist__string_int_int_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_search_emailusers,
                                     "search_emailusers",
                                     searpc_signature_objlist__string_string_int_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_search_ldapusers,
                                     "search_ldapusers",
                                     searpc_signature_objlist__string_int_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_count_emailusers,
                                     "count_emailusers",
                                     searpc_signature_int64__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_count_inactive_emailusers,
                                     "count_inactive_emailusers",
                                     searpc_signature_int64__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_update_emailuser,
                                     "update_emailuser",
                                     searpc_signature_int__string_int_string_int_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_update_role_emailuser,
                                     "update_role_emailuser",
                                     searpc_signature_int__string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_superusers,
                                     "get_superusers",
                                     searpc_signature_objlist__void());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_emailusers_in_list,
                                     "get_emailusers_in_list",
                                     searpc_signature_objlist__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_update_emailuser_id,
                                     "update_emailuser_id",
                                     searpc_signature_int__string_string());

    /*group management*/
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_create_group,
                                     "create_group",
                                     searpc_signature_int__string_string_string_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_create_org_group,
                                     "create_org_group",
                                 searpc_signature_int__int_string_string_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_remove_group,
                                     "remove_group",
                                     searpc_signature_int__int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_group_add_member,
                                     "group_add_member",
                                     searpc_signature_int__int_string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_group_remove_member,
                                     "group_remove_member",
                                     searpc_signature_int__int_string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_group_set_admin,
                                     "group_set_admin",
                                     searpc_signature_int__int_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_group_unset_admin,
                                     "group_unset_admin",
                                     searpc_signature_int__int_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_set_group_name,
                                     "set_group_name",
                                     searpc_signature_int__int_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_quit_group,
                                     "quit_group",
                                     searpc_signature_int__int_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_groups,
                                     "get_groups",
                                     searpc_signature_objlist__string_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                      ccnet_rpc_list_all_departments,
                                     "list_all_departments",
                                     searpc_signature_objlist__void());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_all_groups,
                                     "get_all_groups",
                                     searpc_signature_objlist__int_int_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_ancestor_groups,
                                     "get_ancestor_groups",
                                     searpc_signature_objlist__int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_group,
                                     "get_group",
                                     searpc_signature_object__int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_group_members,
                                     "get_group_members",
                                     searpc_signature_objlist__int_int_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_members_with_prefix,
                                     "get_members_with_prefix",
                                     searpc_signature_objlist__int_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_check_group_staff,
                                     "check_group_staff",
                                     searpc_signature_int__int_string_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_remove_group_user,
                                     "remove_group_user",
                                     searpc_signature_int__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_is_group_user,
                                     "is_group_user",
                                     searpc_signature_int__int_string_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_set_group_creator,
                                     "set_group_creator",
                                     searpc_signature_int__int_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_search_groups,
                                     "search_groups",
                                     searpc_signature_objlist__string_int_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_search_group_members,
                                     "search_group_members",
                                     searpc_signature_objlist__int_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_top_groups,
                                     "get_top_groups",
                                     searpc_signature_objlist__int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_child_groups,
                                     "get_child_groups",
                                     searpc_signature_objlist__int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_descendants_groups,
                                     "get_descendants_groups",
                                     searpc_signature_objlist__int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_groups_members,
                                     "get_groups_members",
                                     searpc_signature_objlist__string());
    /*org management*/
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_create_org,
                                     "create_org",
                                     searpc_signature_int__string_string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_remove_org,
                                     "remove_org",
                                     searpc_signature_int__int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_all_orgs,
                                     "get_all_orgs",
                                     searpc_signature_objlist__int_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_count_orgs,
                                     "count_orgs",
                                     searpc_signature_int64__void());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_org_by_url_prefix,
                                     "get_org_by_url_prefix",
                                     searpc_signature_object__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_org_by_id,
                                     "get_org_by_id",
                                     searpc_signature_object__int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_add_org_user,
                                     "add_org_user",
                                     searpc_signature_int__int_string_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_remove_org_user,
                                     "remove_org_user",
                                     searpc_signature_int__int_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_orgs_by_user,
                                     "get_orgs_by_user",
                                     searpc_signature_objlist__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_org_emailusers,
                                     "get_org_emailusers",
                                     searpc_signature_objlist__string_int_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_add_org_group,
                                     "add_org_group",
                                     searpc_signature_int__int_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_remove_org_group,
                                     "remove_org_group",
                                     searpc_signature_int__int_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_is_org_group,
                                     "is_org_group",
                                     searpc_signature_int__int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_org_id_by_group,
                                     "get_org_id_by_group",
                                     searpc_signature_int__int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_org_groups,
                                     "get_org_groups",
                                     searpc_signature_objlist__int_int_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_org_groups_by_user,
                                     "get_org_groups_by_user",
                                     searpc_signature_objlist__string_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_org_top_groups,
                                     "get_org_top_groups",
                                     searpc_signature_objlist__int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_org_user_exists,
                                     "org_user_exists",
                                     searpc_signature_int__int_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_is_org_staff,
                                     "is_org_staff",
                                     searpc_signature_int__int_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_set_org_staff,
                                     "set_org_staff",
                                     searpc_signature_int__int_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_unset_org_staff,
                                     "unset_org_staff",
                                     searpc_signature_int__int_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_set_org_name,
                                     "set_org_name",
                                     searpc_signature_int__int_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_set_reference_id,
                                     "set_reference_id",
                                     searpc_signature_int__string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     ccnet_rpc_get_primary_id,
                                     "get_primary_id",
                                     searpc_signature_string__string());

    if (rpc_pipe_path) {
        pipe_path = g_build_path ("/", rpc_pipe_path, SEAFILE_RPC_PIPE_NAME, NULL);
    } else {
        pipe_path = g_build_path ("/", seafile_dir, SEAFILE_RPC_PIPE_NAME, NULL);
    }
    rpc_server = searpc_create_named_pipe_server_with_threadpool (pipe_path, NAMED_PIPE_SERVER_THREAD_POOL_SIZE);

    g_free(pipe_path);
    if (!rpc_server) {
        seaf_warning ("Failed to create rpc server.\n");
        exit (1);
    }

    rpc_server->use_epoll = TRUE;

    if (searpc_named_pipe_server_start(rpc_server) < 0) {
        seaf_warning ("Failed to start rpc server.\n");
        exit (1);
    }
}

static struct event sigusr1;

static void sigusr1Handler (int fd, short event, void *user_data)
{
    seafile_log_reopen ();
}

static void
set_signal_handlers (SeafileSession *session)
{
#ifndef WIN32
    signal (SIGPIPE, SIG_IGN);

    /* design as reopen log */
    event_set(&sigusr1, SIGUSR1, EV_SIGNAL | EV_PERSIST, sigusr1Handler, NULL);
    event_add(&sigusr1, NULL);
#endif
}

static void
remove_pidfile (const char *pidfile)
{
    if (pidfile) {
        g_unlink (pidfile);
    }
}

static int
write_pidfile (const char *pidfile_path)
{
    if (!pidfile_path)
        return -1;

    pid_t pid = getpid();

    FILE *pidfile = g_fopen(pidfile_path, "w");
    if (!pidfile) {
        seaf_warning ("Failed to fopen() pidfile %s: %s\n",
                      pidfile_path, strerror(errno));
        return -1;
    }

    char buf[32];
    snprintf (buf, sizeof(buf), "%d\n", pid);
    if (fputs(buf, pidfile) < 0) {
        seaf_warning ("Failed to write pidfile %s: %s\n",
                      pidfile_path, strerror(errno));
        fclose (pidfile);
        return -1;
    }

    fflush (pidfile);
    fclose (pidfile);
    return 0;
}

static void
on_seaf_server_exit(void)
{
    if (pidfile)
        remove_pidfile (pidfile);
}

#ifdef WIN32
/* Get the commandline arguments in unicode, then convert them to utf8  */
static char **
get_argv_utf8 (int *argc)
{
    int i = 0;
    char **argv = NULL;
    const wchar_t *cmdline = NULL;
    wchar_t **argv_w = NULL;

    cmdline = GetCommandLineW();
    argv_w = CommandLineToArgvW (cmdline, argc);
    if (!argv_w) {
        printf("failed to CommandLineToArgvW(), GLE=%lu\n", GetLastError());
        return NULL;
    }

    argv = (char **)malloc (sizeof(char*) * (*argc));
    for (i = 0; i < *argc; i++) {
        argv[i] = wchar_to_utf8 (argv_w[i]);
    }

    return argv;
}
#endif

int
test_seafile_config(const char *central_config_dir, const char *config_dir, const char *seafile_dir)
{
#if !GLIB_CHECK_VERSION(2, 36, 0)
    g_type_init ();
#endif

    config_dir = ccnet_expand_path (config_dir);
    if (central_config_dir) {
        central_config_dir = ccnet_expand_path (central_config_dir);
    }

    seafile_log_init ("-", "debug", "debug", "seaf-server");

    srand (time(NULL));

    event_init ();

    seaf = seafile_session_new (central_config_dir, seafile_dir, config_dir);
    if (!seaf) {
        seaf_error ("Error: failed to create ccnet session\n");
        return -1;
    }

    if (seafile_session_init (seaf) < 0)
        return -1;

    return 0;
}

int
main (int argc, char **argv)
{
    int c;
    char *ccnet_dir = DEFAULT_CONFIG_DIR;
    char *seafile_dir = NULL;
    char *central_config_dir = NULL;
    char *logfile = NULL;
    char *rpc_pipe_path = NULL;
    const char *debug_str = NULL;
    int daemon_mode = 1;
    gboolean test_config = FALSE;
    char *repo_id = NULL;

#ifdef WIN32
    argv = get_argv_utf8 (&argc);
#endif

    while ((c = getopt_long (argc, argv, short_options, 
                             long_options, NULL)) != EOF)
    {
        switch (c) {
        case 'h':
            exit (1);
            break;
        case 'v':
            exit (1);
            break;
        case 'c':
            ccnet_dir = optarg;
            break;
        case 'd':
            seafile_dir = g_strdup(optarg);
            break;
        case 'F':
            central_config_dir = g_strdup(optarg);
            break;
        case 'f':
            daemon_mode = 0;
            break;
        case 'l':
            logfile = g_strdup(optarg);
            break;
        case 'D':
            debug_str = optarg;
            break;
        case 'P':
            pidfile = optarg;
            break;
        case 'p':
            rpc_pipe_path = g_strdup (optarg);
            break;
        case 't':
            test_config = TRUE;
            break;
        case 'r':
            repo_id = g_strdup (optarg);
            break;
        default:
            usage ();
            exit (1);
        }
    }

    argc -= optind;
    argv += optind;

    if (test_config) {
        return test_seafile_config (central_config_dir, ccnet_dir, seafile_dir);
    }

    const char *log_to_stdout_env = g_getenv("SEAFILE_LOG_TO_STDOUT");
    if (g_strcmp0 (log_to_stdout_env, "true") == 0) {
        daemon_mode = 0;
    }

#ifndef WIN32
    if (daemon_mode) {
#ifndef __APPLE__
        daemon (1, 0);
#else   /* __APPLE */
        /* daemon is deprecated under APPLE
         * use fork() instead
         * */
        switch (fork ()) {
          case -1:
              seaf_warning ("Failed to daemonize");
              exit (-1);
              break;
          case 0:
              /* all good*/
              break;
          default:
              /* kill origin process */
              exit (0);
        }
#endif  /* __APPLE */
    }
#endif /* !WIN32 */

    cdc_init ();

#if !GLIB_CHECK_VERSION(2, 35, 0)
    g_type_init();
#endif
#if !GLIB_CHECK_VERSION(2,32,0)
    g_thread_init (NULL);
#endif

    if (!debug_str)
        debug_str = g_getenv("SEAFILE_DEBUG");
    seafile_debug_set_flags_string (debug_str);

    if (seafile_dir == NULL)
        seafile_dir = g_build_filename (ccnet_dir, "seafile", NULL);
    if (logfile == NULL)
        logfile = g_build_filename (seafile_dir, "seafile.log", NULL);

    if (seafile_log_init (logfile, "info", "debug", "seaf-server") < 0) {
        seaf_warning ("Failed to init log.\n");
        exit (1);
    }

    event_init ();

    if (repo_id) {
        seaf = seafile_repair_session_new (central_config_dir, seafile_dir, ccnet_dir);
        if (!seaf) {
            seaf_warning ("Failed to create repair seafile session.\n");
            exit (1);
        }
        seaf_repo_manager_repair_virtual_repo (repo_id);
        exit (0);
    }

    seaf = seafile_session_new (central_config_dir, seafile_dir, ccnet_dir);
    if (!seaf) {
        seaf_warning ("Failed to create seafile session.\n");
        exit (1);
    }


#ifndef WIN32
    set_syslog_config (seaf->config);
#endif

    set_signal_handlers (seaf);

    /* Create pid file before connecting to database.
     * Connecting to database and creating tables may take long if the db
     * is on a remote host. This may make controller think seaf-server fails
     * to start and restart it.
     */
    if (pidfile) {
        if (write_pidfile (pidfile) < 0) {
            ccnet_message ("Failed to write pidfile\n");
            return -1;
        }
    }

    /* init seaf */
    if (seafile_session_init (seaf) < 0)
        exit (1);

    if (seafile_session_start (seaf) < 0)
        exit (1);

    start_rpc_service (seafile_dir, rpc_pipe_path);
    g_free (seafile_dir);
    g_free (logfile);
    g_free (rpc_pipe_path);

    atexit (on_seaf_server_exit);

    /* Create a system default repo to contain the tutorial file. */
    schedule_create_system_default_repo (seaf);

    event_dispatch ();

    return 0;
}
