/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAF_METRIC_MGR_H
#define SEAF_METRIC_MGR_H

struct _SeafMetricManager;

typedef struct _SeafMetricManager SeafMetricManager;

typedef struct _SeafMetricManagerPriv SeafMetricManagerPriv;

struct _SeafMetricManager {
    struct _SeafileSession *seaf;

    SeafMetricManagerPriv *priv;
};

SeafMetricManager* 
seaf_metric_manager_new (struct _SeafileSession *seaf);

int
seaf_metric_manager_start (SeafMetricManager *mgr);

void
seaf_metric_manager_in_flight_request_inc (SeafMetricManager *mgr);

void
seaf_metric_manager_in_flight_request_dec (SeafMetricManager *mgr);

#endif
