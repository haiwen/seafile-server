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
    async_queue = g_async_queue_new_full ((GDestroyNotify)g_free);

    g_hash_table_replace (mgr->priv->chans, g_strdup (channel), async_queue);

    return async_queue;
}

int
publish_event (SeafMqManager *mgr, const char *channel, const char *content)
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

    g_async_queue_push (async_queue, g_strdup (content));

    return ret;
}

char *
pop_event (SeafMqManager *mgr, const char *channel)
{
    GAsyncQueue *async_queue = g_hash_table_lookup (mgr->priv->chans, channel);
    if (!async_queue) {
        seaf_warning ("Unkonwn message channel %s.\n", channel);
        return NULL;
    }

    return g_async_queue_try_pop (async_queue);
}
