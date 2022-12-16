#ifndef HTTP_NOTIFICATION_MGR_H
#define HTTP_NOTIFICATION_MGR_H

struct _NotifManager {
    struct _SeafileSession   *seaf;

    struct _NotifPriv *priv;
};

typedef struct _NotifManager NotifManager;

NotifManager *
seaf_notif_manager_new (struct _SeafileSession *seaf, char *url, char *token);

void
seaf_notif_manager_send_event (NotifManager *mgr,
                               const char *msg);

#endif
