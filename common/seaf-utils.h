#ifndef SEAF_UTILS_H
#define SEAF_UTILS_H

#include <searpc-client.h>

#ifndef DEFAULT_MAX_CONNECTIONS
#define DEFAULT_MAX_CONNECTIONS 100
#endif

struct _SeafileSession;

char *
seafile_session_get_tmp_file_path (struct _SeafileSession *session,
                                   const char *basename,
                                   char path[]);

int
load_database_config (struct _SeafileSession *session);

int
load_ccnet_database_config (struct _SeafileSession *session);

SearpcClient *
create_ccnet_rpc_client ();

void
release_ccnet_rpc_client (SearpcClient *client);

#endif
