#include "common.h"
#include "config-mgr.h"
#include "seaf-db.h"
#include "log.h"

int
seaf_cfg_manager_init (SeafCfgManager *mgr)
{
    char *sql;
    int db_type = seaf_db_type(mgr->db);

    if (db_type == SEAF_DB_TYPE_MYSQL)
        sql = "CREATE TABLE IF NOT EXISTS SeafileConf ("
              "id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, cfg_group VARCHAR(255) NOT NULL,"
              "cfg_key VARCHAR(255) NOT NULL, value VARCHAR(255), property INTEGER) ENGINE=INNODB";
    else
        sql = "CREATE TABLE IF NOT EXISTS SeafileConf (cfg_group VARCHAR(255) NOT NULL,"
              "cfg_key VARCHAR(255) NOT NULL, value VARCHAR(255), property INTEGER)";

    if (seaf_db_query (mgr->db, sql) < 0)
        return -1;

    return 0;
}

SeafCfgManager *
seaf_cfg_manager_new (SeafileSession *session)
{
    SeafCfgManager *mgr = g_new0 (SeafCfgManager, 1);
    if (!mgr)
        return NULL;

    mgr->config = session->config;
    mgr->db = session->db;

    return mgr;
}

int
seaf_cfg_manager_set_config_int (SeafCfgManager *mgr,
                                 const char *group,
                                 const char *key,
                                 int value)
{
    char value_str[256];

    snprintf (value_str, sizeof(value_str), "%d", value);

    return seaf_cfg_manager_set_config (mgr, group, key, value_str);
}

int
seaf_cfg_manager_set_config_int64 (SeafCfgManager *mgr,
                                   const char *group,
                                   const char *key,
                                   gint64 value)
{
    char value_str[256];

    snprintf (value_str, sizeof(value_str), "%"G_GINT64_FORMAT"", value);

    return seaf_cfg_manager_set_config (mgr, group, key, value_str);
}

int
seaf_cfg_manager_set_config_string (SeafCfgManager *mgr,
                                    const char *group,
                                    const char *key,
                                    const char *value)
{
    char value_str[256];

    snprintf (value_str, sizeof(value_str), "%s", value);

    return seaf_cfg_manager_set_config (mgr, group, key, value_str);
}

int
seaf_cfg_manager_set_config_boolean (SeafCfgManager *mgr,
                                     const char *group,
                                     const char *key,
                                     gboolean value)
{
    char value_str[256];

    if (value)
        snprintf (value_str, sizeof(value_str), "true");
    else
        snprintf (value_str, sizeof(value_str), "false");

    return seaf_cfg_manager_set_config (mgr, group, key, value_str);
}

int
seaf_cfg_manager_set_config (SeafCfgManager *mgr, const char *group, const char *key, const char *value)
{
    gboolean exists, err = FALSE;

    char *sql = "SELECT 1 FROM SeafileConf WHERE cfg_group=? AND cfg_key=?";
    exists = seaf_db_statement_exists(mgr->db, sql, &err,
                                      2, "string", group,
                                      "string", key);
    if (err) {
        seaf_warning ("[db error]Failed to set config [%s:%s] to db.\n", group, key);
        return -1;
    }
    if (exists)
        sql = "UPDATE SeafileConf SET value=? WHERE cfg_group=? AND cfg_key=?";
    else
        sql = "INSERT INTO SeafileConf (value, cfg_group, cfg_key, property) VALUES "
              "(?,?,?,0)";
    if (seaf_db_statement_query (mgr->db, sql, 3,
                                 "string", value, "string",
                                 group, "string", key) < 0) {
        seaf_warning ("Failed to set config [%s:%s] to db.\n", group, key);
        return -1;
    }

    return 0;
}

int
seaf_cfg_manager_get_config_int (SeafCfgManager *mgr, const char *group, const char *key)
{
    int ret;
    char *invalid = NULL;

    char *value = seaf_cfg_manager_get_config (mgr, group, key);
    if (!value)
        ret = -1;
    else {
        ret = strtol (value, &invalid, 10);
        if (*invalid != '\0') {
            ret = -1;
            seaf_warning ("Value of config [%s:%s] is invalid: [%s]\n", group, key, value);
        }
        g_free (value);
    }

    return ret;
}

gint64
seaf_cfg_manager_get_config_int64 (SeafCfgManager *mgr, const char *group, const char *key)
{
    gint64 ret;
    char *invalid = NULL;

    char *value = seaf_cfg_manager_get_config (mgr, group, key);
    if (!value)
        ret = -1;
    else {
        ret = strtoll (value, &invalid, 10);
        if (*invalid != '\0') {
            seaf_warning ("Value of config [%s:%s] is invalid: [%s]\n", group, key, value);
            ret = -1;
        }
        g_free (value);
    }

    return ret;
}

gboolean
seaf_cfg_manager_get_config_boolean (SeafCfgManager *mgr, const char *group, const char *key)
{
    gboolean ret;

    char *value = seaf_cfg_manager_get_config (mgr, group, key);
    if (!value) {
        seaf_warning ("Config [%s:%s] not set, default is false.\n", group, key);
        ret = FALSE;
    } else {
        if (strcmp ("true", value) == 0)
            ret = TRUE;
        else
            ret = FALSE;
        g_free (value);
    }

    return ret;
}

char *
seaf_cfg_manager_get_config_string (SeafCfgManager *mgr, const char *group, const char *key)
{
    char *ret = NULL;

    char *value = seaf_cfg_manager_get_config (mgr, group, key);
    if (!value)
        ret = NULL;
    else {
        ret = value;
    }

    return ret;
}

char *
seaf_cfg_manager_get_config (SeafCfgManager *mgr, const char *group, const char *key)
{
    char *sql = "SELECT value FROM SeafileConf WHERE cfg_group=? AND cfg_key=?";
    char *value = seaf_db_statement_get_string(mgr->db, sql, 
                                               2, "string", group, "string", key);
    if (!value) {
        value = g_key_file_get_string (mgr->config, group, key, NULL);
    }

    return value;
}
