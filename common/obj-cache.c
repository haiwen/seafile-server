/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_OTHER
#include "log.h"
#include "redis-cache.h"
#include "obj-cache.h"

#define DEFAULT_MEMCACHED_EXPIRY 24 * 3600
#define DEFAULT_MAX_CONNECTIONS 100

typedef struct CacheOption {
    char *cache_provider;
    char *redis_host;
    char *redis_passwd;
    int redis_port;
    int redis_max_connections;
    int redis_expiry;
} CacheOption;

static void
cache_option_free (CacheOption *option)
{
    if (!option)
        return;
    g_free (option->cache_provider);
    g_free (option->redis_host);
    g_free (option->redis_passwd);
    g_free (option);
}

static void
load_cache_option_from_env (CacheOption *option)
{
    const char *cache_provider, *redis_host, *redis_port, *redis_passwd, *redis_max_conn, *redis_expiry;

    cache_provider = g_getenv("CACHE_PROVIDER");
    redis_host = g_getenv("REDIS_HOST");
    redis_port = g_getenv("REDIS_PORT");
    redis_passwd = g_getenv("REDIS_PASSWORD");
    redis_max_conn = g_getenv("REDIS_MAX_CONNECTIONS");
    redis_expiry = g_getenv("REDIS_EXPIRY");

    if (!cache_provider || g_strcmp0 (cache_provider, "") == 0) {
        return;
    }

    if (cache_provider) {
        g_free (option->cache_provider);
        option->cache_provider = g_strdup (cache_provider);
    }
    if (redis_host && g_strcmp0(redis_host, "") != 0) {
        g_free (option->redis_host);
        option->redis_host = g_strdup (redis_host);
    }
    if (redis_port && g_strcmp0(redis_port, "") != 0) {
        option->redis_port = atoi (redis_port);
    }
    if (redis_passwd && g_strcmp0 (redis_passwd, "") != 0) {
        g_free (option->redis_passwd);
        option->redis_passwd = g_strdup (redis_passwd);
    }
    if (redis_max_conn && g_strcmp0 (redis_max_conn, "") != 0) {
        option->redis_max_connections = atoi (redis_max_conn);
    }
    if (redis_expiry && g_strcmp0 (redis_expiry, "") != 0) {
        option->redis_expiry = atoi (redis_expiry);
    }
}

ObjCache *
objcache_new (GKeyFile *config)
{
    ObjCache *cache = NULL;
    GError *error = NULL;
    CacheOption *option = g_new0 (CacheOption, 1);
    int redis_port;
    int redis_expiry;
    int redis_max_connections;

    redis_expiry = DEFAULT_MEMCACHED_EXPIRY;
    redis_port = 6379;
    redis_max_connections = DEFAULT_MAX_CONNECTIONS;

    option->redis_port = redis_port;
    option->redis_max_connections = redis_max_connections;
    option->redis_expiry = redis_expiry;

    load_cache_option_from_env (option);

    if (g_strcmp0 (option->cache_provider, "redis") == 0) {
        cache = redis_cache_new (option->redis_host, option->redis_passwd, option->redis_port, option->redis_expiry, option->redis_max_connections);
    } else if (option->cache_provider){
        seaf_warning ("Unsupported cache provider: %s\n", option->cache_provider);
    }

    cache_option_free (option);

    return cache;
}

void *
objcache_get_object (ObjCache *cache, const char *obj_id, size_t *len)
{
    return cache->get_object (cache, obj_id, len);
}

int
objcache_set_object (ObjCache *cache,
                    const char *obj_id,
                    const void *object,
                    int len,
                    int expiry)
{
    return cache->set_object (cache, obj_id, object, len, expiry);
}

gboolean
objcache_test_object (ObjCache *cache, const char *obj_id)
{
    return cache->test_object (cache, obj_id);
}

int
objcache_delete_object (ObjCache *cache, const char *obj_id)
{
    return cache->delete_object (cache, obj_id);
}

int
objcache_set_object_existence (ObjCache *cache, const char *obj_id, int val, int expiry, const char *existence_prefix)
{
    char *key;
    char buf[8];
    int n;
    int ret;

    key = g_strdup_printf ("%s%s", existence_prefix, obj_id);
    n = snprintf (buf, sizeof(buf), "%d", val);

    ret = cache->set_object (cache, key, buf, n+1, expiry);

    g_free (key);
    return ret;
}

int
objcache_get_object_existence (ObjCache *cache, const char *obj_id, int *val_out, const char *existence_prefix)
{
    char *key;
    size_t len;
    char *val;
    int ret = 0;

    key = g_strdup_printf ("%s%s", existence_prefix, obj_id);

    val = cache->get_object (cache, key, &len);
    if (!val)
        ret = -1;
    else 
        *val_out = atoi(val);

    g_free (key);
    g_free (val);
    return ret;
}

int
objcache_delete_object_existence (ObjCache *cache, const char *obj_id, const char *existence_prefix)
{
    char *key;
    int ret;

    key = g_strdup_printf ("%s%s", existence_prefix, obj_id);

    ret = cache->delete_object (cache, key);

    g_free (key);
    return ret;
}

int
objcache_publish (ObjCache *cache, const char *channel, const char *msg)
{
    int ret;
    ret = cache->publish (cache, channel, msg);
    return ret;
}

int
objcache_push (ObjCache *cache, const char *list, const char *msg)
{
    int ret;
    ret = cache->push (cache, list, msg);
    return ret;
}
