#include "common.h"
#include "config-mgr.h"
#include "seaf-db.h"
#include "log.h"
#include "utils.h"

/* These configure options in this table are displayed as */
/* "group:option:default_value:property" format .*/
const static char *config_table [] = {
    "quota:default:-2:0",
    "history:keep_days:-1:0",
    "fileserver:max_upload_size:-1:0",
    "fileserver:max_download_dir_size:100:0",
    "fileserver:host:0.0.0.0:1",
    "fileserver:port:8082:1",
    "fileserver:worker_threads:10:1",
    "fileserver:fixed_block_size:8:1",
    "fileserver:web_token_expire_time:8:1",
    "fileserver:max_index_processing_threads:3:1",
    "fileserver:cluster_shared_temp_file_mode:0600:1",
    "library_trash:expire_days:30:0",
    "library_trash:scan_days:1:1",
    "web_copy:max_files:0:1",
    "web_copy:max-size:none:1",
    "scheduler:size_sched_thread_num:1:1",
    "zip:windows_encoding:none:1",
    "general:enable_syslog:false:1",
    "fuse:excluded_users:none:1",
    NULL
};

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

static void load_config_option (SeafCfgManager *mgr, char **option_item)
{
     char *group = NULL, *key = NULL,
          *property = NULL, *default_value = NULL,
          *cache_key = NULL, *cache_value = NULL,
          *sql = NULL, *value = NULL;

     group = option_item[0];
     key = option_item[1];
     default_value = option_item[2];
     property = option_item[2];

     sql = "SELECT value FROM SeafileConf WHERE cfg_group=? AND cfg_key=?";
     value = seaf_db_statement_get_string(mgr->db, sql,
                                          2, "string", group, "string", key);
     if (value) {
         value = g_strstrip(value);
     } else {

         value = seaf_key_file_get_string (seaf->config, group, key, NULL);
         if (!value)
             value = g_strdup (default_value);
     }
     cache_key = g_strdup_printf ("%s,%s" ,group, key);
     cache_value = g_strdup_printf ("%s,%s", value, property);
     g_free (value);

     g_hash_table_insert (mgr->config_cache, cache_key, cache_value);
}

static void load_config_cache (SeafCfgManager *mgr)
{
     int index = 0;
     char **option_item = NULL;

     while (config_table[index]) {
         option_item = g_strsplit (config_table[index], ":", -1);
         load_config_option (mgr, option_item);
         g_strfreev (option_item);
         index++;
     }
}

SeafCfgManager *
seaf_cfg_manager_new (SeafileSession *session)
{
    SeafCfgManager *mgr = g_new0 (SeafCfgManager, 1);
    if (!mgr)
        return NULL;

    mgr->config = session->config;
    mgr->db = session->db;
    mgr->config_cache = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    load_config_cache (mgr);

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
    char *cache_key = NULL, *cache_value = NULL, *property = NULL;

    cache_key = g_strdup_printf ("%s,%s" ,group, key);
    property = g_hash_table_lookup (mgr->config_cache, cache_key);
    if (g_strcmp0 (property, "1") == 0) {
        char *sql = "SELECT 1 FROM SeafileConf WHERE cfg_group=? AND cfg_key=?";
        exists = seaf_db_statement_exists(mgr->db, sql, &err,
                                          2, "string", group,
                                          "string", key);
        if (err) {
            seaf_warning ("[db error]Failed to set config [%s:%s] to db.\n", group, key);
            g_free (cache_key);
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
            g_free (cache_key);
            return -1;
        }
    } else {
        cache_value = g_strdup_printf ("%s,%s" ,value, property);
        g_hash_table_insert (mgr->config_cache, cache_key, cache_value);
    }

    g_free (cache_key);
    return 0;
}

int
seaf_cfg_manager_get_config_int (SeafCfgManager *mgr, const char *group, const char *key)
{
    int ret;
    char *invalid = NULL;

    char *value = seaf_cfg_manager_get_config (mgr, group, key);
    if (!value) {
        seaf_warning ("Config [%s:%s] not set, default is -1.\n", group, key);
        ret = -1;
    } else {
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
    if (!value) {
        seaf_warning ("Config [%s:%s] not set, default is -1.\n", group, key);
        ret = -1;
    } else {
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
    char *value = seaf_cfg_manager_get_config (mgr, group, key);

    if (!value)
        seaf_warning ("Config [%s:%s] not set, default is NULL.\n", group, key);

    return value;
}

char *
seaf_cfg_manager_get_config (SeafCfgManager *mgr, const char *group, const char *key)
{
    char *ret = NULL;
    char *cache_key = g_strdup_printf ("%s,%s", group, key);
    char *cache_value = g_hash_table_lookup (mgr->config_cache, cache_key);
    char **option_item = g_strsplit(cache_value, ",", -1);
    char *option_value = option_item[0];

    if (strcmp (option_value, "none") == 0)
        ret = NULL;
    else
        ret = g_strdup (option_value);

    g_free (cache_key);
    g_strfreev (option_item);

    return ret;
}
