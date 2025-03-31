/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef REDIS_CACHE_H
#define REDIS_CACHE_H

#include "obj-cache.h"

ObjCache *
redis_cache_new (const char *host, const char *passwd,
                 int port, int mc_expiry,
                 int max_connections);


#endif
