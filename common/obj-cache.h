/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef OBJ_CACHE_H
#define OBJ_CACHE_H

#define DEFAULT_MEMCACHED_EXPIRY 24 * 3600

#define TYPE_REDIS 0x02

typedef struct ObjCache ObjCache;

struct ObjCache {
    void*       (*get_object) (ObjCache *cache,
                               const char *obj_id,
                               size_t *len);

    int         (*set_object) (ObjCache *cache,
                               const char *obj_id,
                               const void *object,
                               int len,
                               int expiry);

    gboolean    (*test_object) (ObjCache *cache,
                                const char *obj_id);

    int         (*delete_object) (ObjCache *cache,
                                  const char *obj_id);

    int         (*publish) (ObjCache *cache,
                            const char *channel,
                            const char *msg);

    int         (*push) (ObjCache *cache,
                            const char *list,
                            const char *msg);

    int mc_expiry;
    char *host;
    int port;
    char cache_type;

    void *priv;
};

ObjCache *
objcache_new ();

void *
objcache_get_object (struct ObjCache *cache, const char *obj_id, size_t *len);

int
objcache_set_object (struct ObjCache *cache,
                    const char *obj_id,
                    const void *object,
                    int len,
                    int expiry);

gboolean
objcache_test_object (struct ObjCache *cache, const char *obj_id);

int
objcache_delete_object (struct ObjCache *cache, const char *obj_id);

int
objcache_set_object_existence (struct ObjCache *cache, const char *obj_id, int val, int expiry, const char *existence_prefix);

int
objcache_get_object_existence (struct ObjCache *cache, const char *obj_id, int *val_out, const char *existence_prefix);

int
objcache_delete_object_existence (struct ObjCache *cache, const char *obj_id, const char *existence_prefix);

int
objcache_publish (ObjCache *cache, const char *channel, const char *msg);

int
objcache_push (ObjCache *cache, const char *list, const char *msg);

#endif
