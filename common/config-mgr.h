#ifndef SEAF_CONFIG_MGR_H
#define SEAF_CONFIG_MGR_H

typedef struct _SeafCfgManager SeafCfgManager;
typedef struct _SeafCfgManagerPriv SeafCfgManagerPriv;
#include "seafile-session.h"

struct _SeafCfgManager {
    struct _SeafCfgManagerPriv *priv;
};

typedef struct _SeafileSession SeafileSession;

SeafCfgManager *
seaf_cfg_manager_new (SeafileSession *seaf);

int
seaf_cfg_manager_set_config (SeafCfgManager *mgr, const char *group, const char *key, const char *value);

char *
seaf_cfg_manager_get_config (SeafCfgManager *mgr, const char *group, const char *key);

int
seaf_cfg_manager_set_config_int (SeafCfgManager *mgr, const char *group, const char *key, int value);

int
seaf_cfg_manager_get_config_int (SeafCfgManager *mgr, const char *group, const char *key);

int
seaf_cfg_manager_set_config_int64 (SeafCfgManager *mgr, const char *group, const char *key, gint64 value);

gint64
seaf_cfg_manager_get_config_int64 (SeafCfgManager *mgr, const char *group, const char *key);

int
seaf_cfg_manager_set_config_string (SeafCfgManager *mgr, const char *group, const char *key, const char *value);

char *
seaf_cfg_manager_get_config_string (SeafCfgManager *mgr, const char *group, const char *key);

int
seaf_cfg_manager_set_config_boolean (SeafCfgManager *mgr, const char *group, const char *key, gboolean value);

gboolean
seaf_cfg_manager_get_config_boolean (SeafCfgManager *mgr, const char *group, const char *key);

int
seaf_cfg_manager_init (SeafCfgManager *mgr);

#endif /* SEAF_CONFIG_MGR_H */
