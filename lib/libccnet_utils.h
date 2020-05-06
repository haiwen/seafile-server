/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef LIBCCNET_UTILS_H
#define LIBCCNET_UTILS_H

/**
 * All the helper function names are prefixed with ccnet_util_XXX to avoid
 * name conflict.
 */

#include <sys/time.h>
#include <stdint.h>
#include <unistd.h>
#include <stdarg.h>
#include <glib.h>
#include <glib-object.h>
#include <stdlib.h>

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <event2/util.h>
#else
#include <evutil.h>
#endif

#ifdef WIN32
    #include <errno.h>
    #include <glib/gstdio.h>

    #ifndef WEXITSTATUS
    #define WEXITSTATUS(status) (((status) & 0xff00) >> 8)
    #endif

    /* Borrowed from libevent */
    #define ccnet_pipe_t intptr_t

    int ccnet_util_pgpipe (ccnet_pipe_t handles[2]);
    #define ccnet_util_pipe(a) ccnet_util_pgpipe((a))
    #define ccnet_util_pipeclose(a) closesocket((a))
#else
    #define ccnet_pipe_t int
    #define ccnet_util_pipe(a) pipe((a))
    #define ccnet_util_pipeclose(a) close((a))
#endif

#define ccnet_util_pipereadn(a,b,c) ccnet_util_recvn((a),(b),(c))
#define ccnet_util_pipewriten(a,b,c) ccnet_util_sendn((a),(b),(c))

#ifndef O_BINARY
#define O_BINARY 0
#endif

struct timeval ccnet_util_timeval_from_msec (uint64_t milliseconds);

char* ccnet_util_gen_uuid ();

/* dir operations */
int ccnet_util_checkdir (const char *dir);
char* ccnet_util_expand_path (const char *src);

/* Read "n" bytes from a socket. */
ssize_t	ccnet_util_recvn(evutil_socket_t fd, void *vptr, size_t n);
ssize_t ccnet_util_sendn(evutil_socket_t fd, const void *vptr, size_t n);

/* string utilities */

char * ccnet_util_strjoin_n (const char *seperator, int argc, char **argv);

void ccnet_util_string_list_free (GList *str_list);
void ccnet_util_string_list_join (GList *str_list, GString *strbuf, const char *seperator);
GList *ccnet_util_string_list_parse_sorted (const char *list_in_str, const char *seperator);

gchar* ccnet_util_key_file_get_string (GKeyFile *keyf,
                                        const char *category,
                                        const char *key);

#define ccnet_util_hex_to_sha1(hex, sha1) \
    ccnet_util_hex_to_rawdata((hex), (sha1), 20)

int
ccnet_util_hex_to_rawdata (const char *hex_str,
                           unsigned char *rawdata,
                           int n_bytes);

#ifdef WIN32
int ccnet_util_inet_pton(int af, const char *src, void *dst);
#else
#define ccnet_util_inet_pton inet_pton
#endif

#endif
