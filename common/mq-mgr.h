#ifndef SEAF_MQ_MANAGER_H
#define SEAF_MQ_MANAGER_H

#define SEAFILE_SERVER_CHANNEL_EVENT "seaf_server.event"
#define SEAFILE_SERVER_CHANNEL_STATS "seaf_server.stats"

struct SeafMqManagerPriv;

typedef struct SeafMqManager {
    struct SeafMqManagerPriv *priv;
} SeafMqManager;

SeafMqManager *
seaf_mq_manager_new ();

int
seaf_mq_manager_publish_event (SeafMqManager *mgr, const char *channel, const char *content);

char *
seaf_mq_manager_pop_event (SeafMqManager *mgr, const char *channel);

#endif
