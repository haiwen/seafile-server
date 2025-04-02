/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <hiredis.h>
#include "redis-cache.h"

#define DEBUG_FLAG SEAFILE_DEBUG_OTHER
#include "log.h"

struct _RedisConnectionPool {
    char *host;
    int port;
    GPtrArray *connections;
    pthread_mutex_t lock;
    int max_connections;
};
typedef struct _RedisConnectionPool RedisConnectionPool;

struct _RedisConnection {
    gboolean is_available;
    redisContext *ac;
    gint64 ctime;               /* Used to clean up unused connection. */
    gboolean release;           /* If TRUE, the connection will be released. */
};
typedef struct _RedisConnection RedisConnection;

typedef struct RedisPriv {
    RedisConnectionPool *redis_pool;
    char *passwd;
} RedisPriv;

static int
redis_auth (RedisConnection *conn, const char *passwd)
{
    redisReply *reply;
    int ret = 0;

    if (!passwd) {
        return 0;
    }

    reply = redisCommand(conn->ac, "AUTH %s", passwd);
    if (!reply) {
        seaf_warning ("Failed to auth redis server.\n");
        ret = -1;
        goto out;
    }

    if (reply->type != REDIS_REPLY_STATUS ||
        g_strcmp0 (reply->str, "OK") != 0) {
        if (reply->type == REDIS_REPLY_ERROR) {
            seaf_warning ("Failed to auth redis: %s.\n", reply->str);
        }
        ret = -1;
        goto out;
    }

out:
    freeReplyObject (reply);
    return ret;
}


static RedisConnection *
redis_connection_new (const char *host, const char *passwd, int port)
{
    RedisConnection *conn = g_new0 (RedisConnection, 1);

    conn->ac = redisConnect(host, port);
    if (!conn->ac || conn->ac->err) {
        if (conn->ac) {
            seaf_warning ("Failed to connect to redis : %s\n", conn->ac->errstr);
            redisFree (conn->ac);
        } else {
            seaf_warning ("Can't allocate redis context\n");
        }
        g_free (conn);
        return NULL;
    }

    if (redis_auth (conn, passwd) < 0) {
        redisFree (conn->ac);
        g_free (conn);
        return NULL;
    }
    conn->ctime = (gint64)time(NULL);

    return conn;
}

static void
redis_connection_free (RedisConnection *conn)
{
    if (!conn)
        return;

    if (conn->ac)
        redisFree(conn->ac);

    g_free (conn);
}

static RedisConnectionPool *
redis_connection_pool_new (const char *host, int port, int max_connections)
{
    RedisConnectionPool *pool = g_new0 (RedisConnectionPool, 1);
    pool->host = g_strdup(host);
    pool->port = port;
    pool->connections = g_ptr_array_sized_new (max_connections);
    pool->max_connections = max_connections;
    pthread_mutex_init (&pool->lock, NULL);
    return pool;
}

static RedisConnection *
redis_connection_pool_get_connection (RedisConnectionPool *pool, const char *passwd)
{
    RedisConnection *conn = NULL;

    if (pool->max_connections == 0) {
        conn = redis_connection_new (pool->host, passwd, pool->port);
        return conn;
    }

    pthread_mutex_lock (&pool->lock);

    guint i, size = pool->connections->len;
    for (i = 0; i < size; ++i) {
        conn = g_ptr_array_index (pool->connections, i);
        if (!conn->is_available) {
            continue;
        }
        conn->is_available = FALSE;
        goto out;
    }
    conn = NULL;
    if (size < pool->max_connections) {
        conn = redis_connection_new (pool->host, passwd, pool->port);
        if (conn) {
            conn->is_available = FALSE;
            g_ptr_array_add (pool->connections, conn);
        }
    } else {
        seaf_warning ("The number of redis connections exceeds the limit. The maximum connections is %d.\n", pool->max_connections);
    }

out:
    pthread_mutex_unlock (&pool->lock);
    return conn;
}

static void
redis_connection_pool_return_connection (RedisConnectionPool *pool, RedisConnection *conn)
{
    if (!conn)
        return;

    if (pool->max_connections == 0) {
        redis_connection_free (conn);
        return;
    }

    if (conn->release) {
        pthread_mutex_lock (&pool->lock);
        g_ptr_array_remove (pool->connections, conn);
        pthread_mutex_unlock (&pool->lock);
        redis_connection_free (conn);
        return;
    }

    pthread_mutex_lock (&pool->lock);
    conn->is_available = TRUE;
    pthread_mutex_unlock (&pool->lock);
}

void *
redis_cache_get_object (ObjCache *cache, const char *obj_id, size_t *len)
{
    RedisConnection *conn;
    char *object = NULL;
    redisReply *reply;
    RedisPriv *priv = cache->priv;
    RedisConnectionPool *pool = priv->redis_pool;

    conn = redis_connection_pool_get_connection (pool, priv->passwd);
    if (!conn) {
        seaf_warning ("Failed to get redis connection to host %s.\n", cache->host);
        return NULL;
    }

    reply = redisCommand(conn->ac, "GET %s", obj_id);
    if (!reply) {
        seaf_warning ("Failed to get object %s from redis cache.\n", obj_id);
        conn->release = TRUE;
        goto out;
    }
    if (reply->type != REDIS_REPLY_STRING) {
        if (reply->type == REDIS_REPLY_ERROR) {
            conn->release = TRUE;
            seaf_warning ("Failed to get %s from redis cache: %s.\n",
                      obj_id, reply->str);
        }
        goto out;
    }

    *len = reply->len;
    object = g_memdup (reply->str, reply->len);

out:
    freeReplyObject(reply);
    redis_connection_pool_return_connection (pool, conn);

    return object;
}

int
redis_cache_set_object (ObjCache *cache,
                        const char *obj_id,
                        const void *object,
                        int len,
                        int expiry)
{
    RedisConnection *conn;
    redisReply *reply;
    int ret = 0;
    RedisPriv *priv = cache->priv;
    RedisConnectionPool *pool = priv->redis_pool;

    conn = redis_connection_pool_get_connection (pool, priv->passwd);
    if (!conn) {
        seaf_warning ("Failed to get redis connection to host %s.\n", cache->host);
        return -1;
    }

    if (expiry <= 0)
        expiry = cache->mc_expiry;
    reply = redisCommand(conn->ac, "SET %s %b EX %d", obj_id, object, len, expiry);
    if (!reply) {
        seaf_warning ("Failed to set object %s to redis cache.\n", obj_id);
        ret = -1;
        conn->release = TRUE;
        goto out;
    }
    if (reply->type != REDIS_REPLY_STATUS ||
        g_strcmp0 (reply->str, "OK") != 0) {
        if (reply->type == REDIS_REPLY_ERROR) {
            conn->release = TRUE;
            seaf_warning ("Failed to set %s to redis: %s.\n",
                          obj_id, reply->str);
        }
        ret = -1;
    }

out:
    freeReplyObject(reply);
    redis_connection_pool_return_connection (pool, conn);

    return ret;
}

gboolean
redis_cache_test_object (ObjCache *cache, const char *obj_id)
{
    RedisConnection *conn;
    redisReply *reply;
    gboolean ret = FALSE;
    RedisPriv *priv = cache->priv;
    RedisConnectionPool *pool = priv->redis_pool;

    conn = redis_connection_pool_get_connection (pool, priv->passwd);
    if (!conn) {
        seaf_warning ("Failed to get redis connection to host %s.\n", cache->host);
        return ret;
    }

    reply = redisCommand(conn->ac, "EXISTS %s", obj_id);
    if (!reply) {
        seaf_warning ("Failed to test object %s from redis cache.\n", obj_id);
        conn->release = TRUE;
        goto out;
    }
    if (reply->type != REDIS_REPLY_INTEGER ||
        reply->integer != 1) {
        if (reply->type == REDIS_REPLY_ERROR) {
            conn->release = TRUE;
            seaf_warning ("Failed to test %s from redis: %s.\n",
                          obj_id, reply->str);
        }
        goto out;
    }

    ret = TRUE;

out:
    freeReplyObject(reply);
    redis_connection_pool_return_connection (pool, conn);

    return ret;
}

int
redis_cache_delete_object (ObjCache *cache, const char *obj_id)
{
    RedisConnection *conn;
    redisReply *reply;
    int ret = 0;
    RedisPriv *priv = cache->priv;
    RedisConnectionPool *pool = priv->redis_pool;

    conn = redis_connection_pool_get_connection (pool, priv->passwd);
    if (!conn) {
        seaf_warning ("Failed to get redis connection to host %s.\n", cache->host);
        return -1;
    }

    reply = redisCommand(conn->ac, "DEL %s", obj_id);
    if (!reply) {
        seaf_warning ("Failed to delete object %s from redis cache.\n", obj_id);
        ret = -1;
        conn->release = TRUE;
        goto out;
    }
    if (reply->type != REDIS_REPLY_INTEGER ||
        reply->integer != 1) {
        if (reply->type == REDIS_REPLY_ERROR) {
            conn->release = TRUE;
            seaf_warning ("Failed to del %s from redis: %s.\n",
                          obj_id, reply->str);
        }
        ret = -1;
    }

out:
    freeReplyObject(reply);
    redis_connection_pool_return_connection (pool, conn);

    return ret;
}

int
redis_cache_publish (ObjCache *cache, const char *channel, const char *msg)
{
    RedisConnection *conn;
    redisReply *reply;
    int ret = 0;
    RedisPriv *priv = cache->priv;
    RedisConnectionPool *pool = priv->redis_pool;

    conn = redis_connection_pool_get_connection (pool, priv->passwd);
    if (!conn) {
        seaf_warning ("Failed to get redis connection to host %s.\n", cache->host);
        return -1;
    }

    reply = redisCommand(conn->ac, "PUBLISH %s %s", channel, msg);
    if (!reply) {
        seaf_warning ("Failed to publish message to redis channel %s.\n", channel);
        ret = -1;
        conn->release = TRUE;
        goto out;
    }
    if (reply->type != REDIS_REPLY_INTEGER ||
        reply->integer < 0) {
        if (reply->type == REDIS_REPLY_ERROR) {
            conn->release = TRUE;
            seaf_warning ("Failed to publish message to redis channel %s.\n", channel);
        }
        ret = -1;
    }

out:
    freeReplyObject(reply);
    redis_connection_pool_return_connection (pool, conn);

    return ret;
}

int
redis_cache_push (ObjCache *cache, const char *list, const char *msg)
{
    RedisConnection *conn;
    redisReply *reply;
    int ret = 0;
    RedisPriv *priv = cache->priv;
    RedisConnectionPool *pool = priv->redis_pool;

    conn = redis_connection_pool_get_connection (pool, priv->passwd);
    if (!conn) {
        seaf_warning ("Failed to get redis connection to host %s.\n", cache->host);
        return -1;
    }

    reply = redisCommand(conn->ac, "LPUSH %s %s", list, msg);
    if (!reply) {
        seaf_warning ("Failed to push message to redis list %s.\n", list);
        ret = -1;
        conn->release = TRUE;
        goto out;
    }
    if (reply->type != REDIS_REPLY_INTEGER ||
        reply->integer < 0) {
        if (reply->type == REDIS_REPLY_ERROR) {
            conn->release = TRUE;
            seaf_warning ("Failed to push message to redis list %s.\n", list);
        }
        ret = -1;
    }

out:
    freeReplyObject(reply);
    redis_connection_pool_return_connection (pool, conn);

    return ret;
}

ObjCache *
redis_cache_new (const char *host, const char *passwd,
                 int port, int redis_expiry,
                 int max_connections)
{
    ObjCache *cache = g_new0 (ObjCache, 1);
    RedisPriv *priv = g_new0 (RedisPriv, 1);

    priv->redis_pool = redis_connection_pool_new (host, port, max_connections);

    cache->priv = priv;

    cache->host = g_strdup (host);
    priv->passwd = g_strdup (passwd);
    cache->port = port;
    cache->mc_expiry = redis_expiry;
    cache->cache_type = TYPE_REDIS;

    cache->get_object = redis_cache_get_object;
    cache->set_object = redis_cache_set_object;
    cache->test_object = redis_cache_test_object;
    cache->delete_object = redis_cache_delete_object;
    cache->publish = redis_cache_publish;
    cache->push = redis_cache_push;

    return cache;
}
