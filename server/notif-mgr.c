#include "common.h"

#include <pthread.h>
#include <jansson.h>

#include <timer.h>

#include "seafile-session.h"
#include "http-tx-mgr.h"
#include "notif-mgr.h"

#include "utils.h"
#include "seafile-error.h"

#include "log.h"

#define NOTIF_TIMEOUT_SEC 1

struct _NotifPriv {
    char *notif_url;
    char *notif_token;

    ConnectionPool *connection_pool;
};
typedef struct _NotifPriv NotifPriv;

typedef struct Event {
    NotifPriv *priv;
    char *msg;
} Event;

NotifManager *
seaf_notif_manager_new (struct _SeafileSession *seaf, char *url, char *token)
{
    NotifManager *mgr = g_new0 (NotifManager, 1);
    mgr->seaf = seaf;

    NotifPriv *priv = g_new0 (NotifPriv, 1);

    priv->connection_pool = connection_pool_new ();
    if (!priv->connection_pool) {
        g_free (priv);
        g_free (mgr);
        return NULL;
    }

    priv->notif_url = url;
    priv->notif_token = token;
    mgr->priv = priv;

    return mgr;
}

static void*
send_event (void *data)
{
    Event *event= data;
    NotifPriv *priv = event->priv;
    Connection *conn = NULL;
    int rsp_status;
    char *req_url = NULL;

    conn = connection_pool_get_connection (priv->connection_pool);
    if (!conn) {
        seaf_warning ("Failed to get connection: out of memory.\n");
        return event;
    }

    req_url = g_strdup_printf ("%s/events", priv->notif_url);

    int ret;

    ret = http_post (conn, req_url, priv->notif_token, event->msg, strlen (event->msg),
                     &rsp_status, NULL, NULL, TRUE, NOTIF_TIMEOUT_SEC);
    if (ret < 0) {
        goto out;
    }

    if (rsp_status != HTTP_OK) {
        seaf_warning ("Failed to send event to notification server %s: %d.\n",
                      priv->notif_url, rsp_status);
    }

out:
    g_free (req_url);
    connection_pool_return_connection (priv->connection_pool, conn);

    return event;
}

static void
free_send_event(void *data)
{
    if (!data)
        return;

    Event *event= data;

    if (event->msg)
        g_free (event->msg);

    g_free (event);
}

void
seaf_notif_manager_send_event (NotifManager *mgr, const char *msg)
{
    Event *event = g_new0 (Event, 1);
    event->priv = mgr->priv;
    event->msg = g_strdup (msg);

    ccnet_job_manager_schedule_job (seaf->job_mgr,
                                    send_event,
                                    free_send_event,
                                    event);

}
