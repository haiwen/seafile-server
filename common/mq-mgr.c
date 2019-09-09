#include "common.h"
#include "log.h"
#include "utils.h"
#include "mq-mgr.h"

typedef struct SeafMqManagerPriv {
    // chan <-> async_queue
    GHashTable *chans;
} SeafMqManagerPriv;

SeafMqManager *
seaf_mq_manager_new ()
{
    SeafMqManager *mgr = g_new0 (SeafMqManager, 1);
    mgr->priv = g_new0 (SeafMqManagerPriv, 1);
    mgr->priv->chans = g_hash_table_new_full (g_str_hash, g_str_equal,
                                              (GDestroyNotify)g_free,
                                              (GDestroyNotify)g_async_queue_unref);

    return mgr;
}

static GAsyncQueue *
seaf_mq_manager_channel_new (SeafMqManager *mgr, const char *channel)
{
    GAsyncQueue *async_queue = NULL;
    async_queue = g_async_queue_new_full ((GDestroyNotify)json_decref);

    g_hash_table_replace (mgr->priv->chans, g_strdup (channel), async_queue);

    return async_queue;
}

int
seaf_mq_manager_publish_event (SeafMqManager *mgr, const char *channel, const char *content)
{
    int ret = 0;

    if (!channel || !content) {
        seaf_warning ("type and content should not be NULL.\n");
        return -1;
    }

    GAsyncQueue *async_queue = g_hash_table_lookup (mgr->priv->chans, channel);
    if (!async_queue) {
        async_queue = seaf_mq_manager_channel_new(mgr, channel);
    }

    if (!async_queue) {
        seaf_warning("%s channel creation failed.\n", channel);
        return -1;
    }

    json_t *msg = json_object();
    json_object_set_new (msg, "content", json_string(content));
    json_object_set_new (msg, "ctime", json_integer(time(NULL)));
    g_async_queue_push (async_queue, msg);

    return ret;
}

json_t *
seaf_mq_manager_pop_event (SeafMqManager *mgr, const char *channel)
{
    GAsyncQueue *async_queue = g_hash_table_lookup (mgr->priv->chans, channel);
    if (!async_queue)
        return NULL;

    return g_async_queue_try_pop (async_queue);
}
