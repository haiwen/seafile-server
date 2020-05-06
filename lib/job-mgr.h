/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/**
 * Job Manager manages long term jobs. These jobs are run in their
 * own threads.
 */

#ifndef JOB_MGR_H
#define JOB_MGR_H

#include <glib.h>

struct _CcnetSession;

typedef struct _CcnetJob CcnetJob;
typedef struct _CcnetJobManager CcnetJobManager;

/*
  The thread func should return the result back by
     return (void *)result;
  The result will be passed to JobDoneCallback.
 */
typedef void* (*JobThreadFunc)(void *data);
typedef void (*JobDoneCallback)(void *result);


struct _CcnetJobManager {
    GHashTable      *jobs;

    GThreadPool     *thread_pool;

    int              next_job_id;
};

void
ccnet_job_cancel (CcnetJob *job);

CcnetJobManager *
ccnet_job_manager_new (int max_threads);

void
ccnet_job_manager_free (CcnetJobManager *mgr);

int
ccnet_job_manager_schedule_job (CcnetJobManager *mgr,
                                JobThreadFunc func,
                                JobDoneCallback done_func,
                                void *data);

/** 
 * Wait a specific job to be done.
 */
void
ccnet_job_manager_wait_job (CcnetJobManager *mgr, int job_id);


#endif
