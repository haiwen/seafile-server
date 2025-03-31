/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "utils.h"
#include "log.h"

#include <string.h>
#include <jansson.h>

#include "seafile-session.h"
#include "metric-mgr.h"
#include "obj-cache.h"

#define PUBLISH_INTERVAL 30 /* 30 seconds*/
#define REDIS_CHANNEL "metric_channel"
#define COMPONENT_NAME "fileserver"

struct _SeafMetricManagerPriv {
    int in_flight_request_count;

    struct ObjCache *cache;
};

SeafMetricManager* 
seaf_metric_manager_new (struct _SeafileSession *seaf)
{
    SeafMetricManager *mgr = g_new0 (SeafMetricManager, 1);

    mgr->priv = g_new0 (SeafMetricManagerPriv, 1);
    mgr->seaf = seaf;

    // redis cache
    mgr->priv->cache = seaf->obj_cache;

    return mgr;
}

static void *
publish_metrics (void *data);

int
seaf_metric_manager_start (SeafMetricManager *mgr)
{
    pthread_t tid;
    int rc;

    rc = pthread_create (&tid, NULL, publish_metrics, mgr);
    if (rc != 0) {
        seaf_warning ("Failed to create publish metrics worker thread: %s.\n",
                      strerror(rc));
        return -1;
    }

    return 0;
}

void
seaf_metric_manager_in_flight_request_inc (SeafMetricManager *mgr)
{
    SeafMetricManagerPriv *priv = mgr->priv;

    g_atomic_int_inc (&priv->in_flight_request_count);
}

void
seaf_metric_manager_in_flight_request_dec (SeafMetricManager *mgr)
{
    SeafMetricManagerPriv *priv = mgr->priv;
    g_atomic_int_dec_and_test (&priv->in_flight_request_count);
}

static int
publish_redis_msg (SeafMetricManager *mgr, const char *msg)
{
    SeafMetricManagerPriv *priv = mgr->priv;

    if (!priv->cache) {
        return 0;
    }

    int ret = objcache_publish (priv->cache, REDIS_CHANNEL, msg); 

    return ret;
}

static int
publish_in_flight_request (SeafMetricManager *mgr)
{
    int ret = 0;
    json_t *obj = NULL;
    char *msg = NULL;
    SeafMetricManagerPriv *priv = mgr->priv;

    obj = json_object ();

    json_object_set_new (obj, "metric_name", json_string("in_flight_request_total"));
    json_object_set_new (obj, "metric_value", json_integer (priv->in_flight_request_count));
    json_object_set_new (obj, "metric_type", json_string("gauge"));
    json_object_set_new (obj, "component_name", json_string(COMPONENT_NAME));
    json_object_set_new (obj, "metric_help", json_string("The number of currently running http requests."));

    msg = json_dumps (obj, JSON_COMPACT);

    ret = publish_redis_msg (mgr, msg);

    json_decref (obj);
    g_free (msg);
    return ret;
}

static void
do_publish_metrics (SeafMetricManager *mgr)
{
    int rc;

    // Don't publish metrics when use go fileserver.
    if (seaf->go_fileserver) {
        return;
    }

    rc = publish_in_flight_request (mgr);
    if (rc < 0) {
        seaf_warning ("Failed to publish in flight request\n");
        return;
    }
}

static void *
publish_metrics (void *data)
{
    SeafMetricManager *mgr = data;

    while (1) {
        do_publish_metrics (mgr);
        sleep(PUBLISH_INTERVAL);
    }

    return NULL;
}
