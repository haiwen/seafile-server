#ifndef SEAFILE_FILESERVER_CONFIG_H
#define SEAFILE_FILESERVER_CONFIG_H

struct GKeyFile;

int
fileserver_config_get_integer(SeafCfgManager *mgr, GKeyFile *config, char *key);

char *
fileserver_config_get_string(SeafCfgManager *mgr, GKeyFile *config, char *key);

gboolean
fileserver_config_get_boolean(SeafCfgManager *mgr, GKeyFile *config, char *key);

#endif // SEAFILE_FILESERVER_CONFIG_H
