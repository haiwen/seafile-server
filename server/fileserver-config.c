#include "common.h"

#include <glib.h>

#include "seafile-session.h"

const char *OLD_GROUP_NAME = "httpserver";
const char *GROUP_NAME = "fileserver";

static const char *
get_group_name(GKeyFile *config)
{
    return g_key_file_has_group (config, GROUP_NAME) ? GROUP_NAME : OLD_GROUP_NAME;
}

int
fileserver_config_get_integer(SeafCfgManager *mgr, GKeyFile *config, char *key)
{
    const char *group = get_group_name(config);
    return seaf_cfg_manager_get_config_int (mgr, group, key);
}

char *
fileserver_config_get_string(SeafCfgManager *mgr, GKeyFile *config, char *key)
{
    const char *group = get_group_name(config);
    return seaf_cfg_manager_get_config_string (mgr, group, key);
}

gboolean
fileserver_config_get_boolean(SeafCfgManager *mgr, GKeyFile *config, char *key)
{
    const char *group = get_group_name(config);
    return seaf_cfg_manager_get_config_boolean (mgr, group, key);
}
