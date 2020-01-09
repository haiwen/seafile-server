#include "common.h"
#include "config-mgr.h"
#include "seaf-db.h"
#include "log.h"
#include "utils.h"

enum {
    QUOTA_DEFALUT,
    HISTORY_KEEPDAYS,
    FILESERVER_MAX_UPLOAD_SIZE,
    FILESERVER_MAX_DOWNLOAD_DIR_SIZE,
    FILESERVER_HOST,
    FILESERVER_PORT,
    FILESERVER_WORKER_THREADS,
    FILESERVER_FIXED_BLOCK_SIZE,
    FILESERVER_WEB_TOKEN_EXPIRE_TIME,
    FILESERVER_MAX_INDEXING_THREADS,
    FILESERVER_MAX_INDEX_PROCESSING_THREADS,
    FILESERVER_CLUSTER_SHARED_TEMP_FILE_MODE,
    HTTPSERVER_MAX_UPLOAD_SIZE,
    HTTPSERVER_MAX_DOWNLOAD_DIR_SIZE,
    HTTPSERVER_HOST,
    HTTPSERVER_PORT,
    HTTPSERVER_WORKER_THREADS,
    HTTPSERVER_FIXED_BLOCK_SIZE,
    HTTPSERVER_WEB_TOKEN_EXPIRE_TIME,
    HTTPSERVER_MAX_INDEXING_THREADS,
    HTTPSERVER_MAX_INDEX_PROCESSING_THREADS,
    HTTPSERVER_CLUSTER_SHARED_TEMP_FILE_MODE,
    LIBRARY_TRASH_EXPIRE_DAYS,
    LIBRARY_TRASH_SCAN_DAYS,
    WEB_COPY_MAX_FILES,
    WEB_COPY_MAX_SIZE,
    SHCEDULER_SIZE_SCHED_THREAD_NUM,
    ZIP_WINDOWS_ENCODING,
    GENERAL_CLOUD_MODE,
    GENERAL_ENABLE_SYSLOG,
    FUSE_EXCLUEDE_USERS,
};

/* These configurations in this table are displayed as */
/* "group:option:default_value:property" format . */
const static char *config_table [] = {
    "quota:default:none:0",
    "history:keep_days:-1:0",
    "fileserver:max_upload_size:-1:0",
    "fileserver:max_download_dir_size:100:0",
    "fileserver:host:0.0.0.0:1",
    "fileserver:port:8082:1",
    "fileserver:worker_threads:10:1",
    "fileserver:fixed_block_size:8:1",
    "fileserver:web_token_expire_time:8:1",
    "fileserver:max_indexing_threads:1:1",
    "fileserver:max_index_processing_threads:3:1",
    "fileserver:cluster_shared_temp_file_mode:0600:1",
    "httpserver:max_upload_size:-1:0",
    "httpserver:max_download_dir_size:100:0",
    "httpserver:host:0.0.0.0:1",
    "httpserver:port:8082:1",
    "httpserver:worker_threads:10:1",
    "httpserver:fixed_block_size:8:1",
    "httpserver:web_token_expire_time:8:1",
    "httpserver:max_indexing_threads:1:1",
    "httpserver:max_index_processing_threads:3:1",
    "httpserver:cluster_shared_temp_file_mode:0600:1",
    "library_trash:expire_days:30:0",
    "library_trash:scan_days:1:1",
    "web_copy:max_files:0:1",
    "web_copy:max_size:0:1",
    "scheduler:size_sched_thread_num:1:1",
    "zip:windows_encoding:none:1",
    "general:cloud_mode:false:1",
    "general:enable_syslog:false:1",
    "fuse:excluded_users:none:1",
    "t_group:t_key:0:0",
    NULL
};

struct _SeafCfgManagerPriv {
    GKeyFile *config;
    SeafDB *db;
    GHashTable *config_cache;
};

typedef struct {
    char *value;
    char *property;
} OptionCacheValue;

gboolean is_option_valid (int option_index, char *value)
{
    char *invalid = NULL;
    int value_int;
    gint64 value_int64;
    gboolean ret = TRUE;

    switch (option_index) {
        case HISTORY_KEEPDAYS:
            value_int = strtol (value, &invalid, 10);
            if (value_int < 0 || *invalid != '\0')
                ret = FALSE;
            break;
        case FILESERVER_MAX_UPLOAD_SIZE:
        case FILESERVER_MAX_DOWNLOAD_DIR_SIZE:
            value_int64 = strtoll (value, &invalid, 10);
            if (value_int64 <= 0 || *invalid != '\0')
                ret = FALSE;
            break;
        case FILESERVER_WORKER_THREADS:
        case FILESERVER_FIXED_BLOCK_SIZE:
        case FILESERVER_WEB_TOKEN_EXPIRE_TIME:
        case FILESERVER_MAX_INDEXING_THREADS:
        case FILESERVER_MAX_INDEX_PROCESSING_THREADS:
        case LIBRARY_TRASH_EXPIRE_DAYS:
        case LIBRARY_TRASH_SCAN_DAYS:
        case SHCEDULER_SIZE_SCHED_THREAD_NUM:
            value_int = strtol (value, &invalid, 10);
            if (value_int <= 0 || *invalid != '\0')
                ret = FALSE;
            break;
        case FILESERVER_CLUSTER_SHARED_TEMP_FILE_MODE:
            value_int = strtol(value, NULL, 8);
            if (value_int < 0001 ||
                value_int > 0777)
                ret = FALSE;
            break;
        default:
            break;
    }

    if (!ret)
        g_free (value);

    return ret;
}

static void load_config_option (SeafCfgManager *mgr, char **option_item, int index)
{
     char *group = NULL, *key = NULL,
          *property = NULL, *default_value = NULL,
          *cache_key = NULL, *value = NULL;
     OptionCacheValue *cache_value = NULL;

     group = option_item[0];
     key = option_item[1];
     default_value = option_item[2];
     property = option_item[3];

     cache_key = g_strdup_printf ("%s/%s", group, key);

     value = seaf_key_file_get_string (mgr->priv->config, group, key, NULL);
     if (!value || !is_option_valid (index, value))
         value = g_strdup (default_value);

     cache_value = g_new0 (OptionCacheValue, 1);
     cache_value->value = value;
     cache_value->property = g_strdup (property);

     g_hash_table_insert (mgr->priv->config_cache, cache_key, cache_value);
}

static void load_config_cache (SeafCfgManager *mgr)
{
     int index = 0;
     char **option_item = NULL;

     while (config_table[index]) {
         option_item = g_strsplit (config_table[index], ":", -1);
         load_config_option (mgr, option_item, index);
         g_strfreev (option_item);
         index++;
     }
}

int
seaf_cfg_manager_init (SeafCfgManager *mgr)
{
    char *sql;
    int db_type;

    if (seaf->create_tables || seaf_db_type(seaf->db) == SEAF_DB_TYPE_PGSQL) {
        db_type = seaf_db_type(mgr->priv->db);
        if (db_type == SEAF_DB_TYPE_MYSQL)
            sql = "CREATE TABLE IF NOT EXISTS SeafileConf ("
                  "id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, cfg_group VARCHAR(255) NOT NULL,"
                  "cfg_key VARCHAR(255) NOT NULL, value VARCHAR(255), property INTEGER) ENGINE=INNODB";
        else
            sql = "CREATE TABLE IF NOT EXISTS SeafileConf (cfg_group VARCHAR(255) NOT NULL,"
                  "cfg_key VARCHAR(255) NOT NULL, value VARCHAR(255), property INTEGER)";

        if (seaf_db_query (mgr->priv->db, sql) < 0) {
            seaf_warning ("[cfg mgr] Failed to create table.\n");
            return -1;
        }
    }

    load_config_cache (mgr);

    return 0;
}

static void
cache_value_free (gpointer data)

{
    OptionCacheValue *cache_value = (OptionCacheValue *)data;

    g_free (cache_value->value);
    g_free (cache_value->property);
    g_free (cache_value);
}

SeafCfgManager *
seaf_cfg_manager_new (SeafileSession *session)
{
    SeafCfgManager *mgr = g_new0 (SeafCfgManager, 1);
    if (!mgr)
        return NULL;

    mgr->priv = g_new0 (SeafCfgManagerPriv, 1);
    if (!mgr->priv) {
        g_free (mgr);
        return NULL;
    }

    mgr->priv->config = session->config;
    mgr->priv->db = session->db;
    mgr->priv->config_cache = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, cache_value_free);

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
#if 0
    gboolean exists, err = FALSE;
    char *cache_key = NULL, *property = NULL;
    OptionCacheValue *prev_cache_value = NULL, *new_cache_value = NULL;
    int ret = 0;

    cache_key = g_strdup_printf ("%s/%s" ,group, key);
    prev_cache_value = g_hash_table_lookup (mgr->priv->config_cache, cache_key);
    property = prev_cache_value->property;

    if (strcmp (property, "0") == 0) {
        new_cache_value = g_new0 (OptionCacheValue, 1);
        new_cache_value->value = g_strdup (value);
        new_cache_value->property = property;
        g_hash_table_insert (mgr->priv->config_cache, cache_key, new_cache_value);
    }

    char *sql = "SELECT 1 FROM SeafileConf WHERE cfg_group=? AND cfg_key=?";
    exists = seaf_db_statement_exists(mgr->priv->db, sql, &err,
                                      2, "string", group,
                                      "string", key);
    if (err) {
        seaf_warning ("[db error]Failed to set config [%s:%s] to db.\n", group, key);
        ret = -1;
    }
    if (exists)
        sql = "UPDATE SeafileConf SET value=? WHERE cfg_group=? AND cfg_key=?";
    else
        sql = "INSERT INTO SeafileConf (value, cfg_group, cfg_key, property) VALUES "
              "(?,?,?,0)";
    if (seaf_db_statement_query (mgr->priv->db, sql, 3,
                                 "string", value, "string",
                                 group, "string", key) < 0) {
        seaf_warning ("Failed to set config [%s:%s] to db.\n", group, key);
        ret = -1;
    }

    return ret;
#endif

    return 0;
}

int
seaf_cfg_manager_get_config_int (SeafCfgManager *mgr, const char *group, const char *key)
{
    int ret;

    char *value = seaf_cfg_manager_get_config (mgr, group, key);
    if (!value) {
        seaf_warning ("Config [%s:%s] not set, default is -1.\n", group, key);
        ret = -1;
    } else {
        ret = strtol (value, NULL, 10);
        g_free (value);
    }

    return ret;
}

gint64
seaf_cfg_manager_get_config_int64 (SeafCfgManager *mgr, const char *group, const char *key)
{
    gint64 ret;

    char *value = seaf_cfg_manager_get_config (mgr, group, key);
    if (!value) {
        seaf_warning ("Config [%s:%s] not set, default is -1.\n", group, key);
        ret = -1;
    } else {
        ret = strtoll (value, NULL, 10);
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
    char *ret = NULL, *cache_key = NULL,
         *value = NULL;
    OptionCacheValue *cache_value = NULL;

    cache_key = g_strdup_printf ("%s/%s", group, key);
    cache_value = g_hash_table_lookup (mgr->priv->config_cache, cache_key);
    value = cache_value->value;

    if (strcmp (value, "none") == 0)
        ret = NULL;
    else
        ret = g_strdup (value);

    g_free (cache_key);

    return ret;
}
