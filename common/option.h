/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_OPTION_H
#define CCNET_OPTION_H

#include <stdio.h>
#include <glib.h>

#ifdef WIN32
static inline char *GetDeafaultDir()
{
    static char buf[128];
    static int inited = 0;

    if (!inited) {
        const char *home = g_get_home_dir();
        inited = 1;
        snprintf(buf, 128, "%s/ccnet", home);
    }
    return buf;
}

  #define DEFAULT_CONFIG_DIR GetDeafaultDir()
  #define CONFIG_FILE_NAME   "ccnet.conf"
  #define PREFS_FILE_NAME    "prefs.conf"
#else
  #define DEFAULT_CONFIG_DIR "~/.ccnet"
  #define CONFIG_FILE_NAME   "ccnet.conf"
  #define PREFS_FILE_NAME    "prefs.conf"
#endif

#define MAX_USERNAME_LEN 20
#define MIN_USERNAME_LEN 2

#define DEFAULT_PORT       10001

#define CHAT_APP      "Chat"
#define PEERMGR_APP   "PeerMgr"
#define GROUPMGR_APP  "GroupMgr"


enum {
    NET_STATUS_DOWN,
    NET_STATUS_INNAT,
    NET_STATUS_FULL
};

#endif
