/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <config.h>

#include "libccnet_utils.h"

#ifdef WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <Rpc.h>
    #include <shlobj.h>
    #include <psapi.h>
#else
    #include <arpa/inet.h>
#endif

#ifndef WIN32
#include <pwd.h>
#include <uuid/uuid.h>
#endif

#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <ctype.h>

#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>


#include <glib.h>
#include <glib/gstdio.h>
#include <searpc-utils.h>

#ifdef WIN32
int
ccnet_util_pgpipe (ccnet_pipe_t handles[2])
{
    SOCKET s;
    struct sockaddr_in serv_addr;
    int len = sizeof( serv_addr );

    handles[0] = handles[1] = INVALID_SOCKET;

    if ( ( s = socket( AF_INET, SOCK_STREAM, 0 ) ) == INVALID_SOCKET )
    {
        g_warning("pgpipe failed to create socket: %d\n", WSAGetLastError());
        return -1;
    }

    memset( &serv_addr, 0, sizeof( serv_addr ) );
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(0);
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (SOCKADDR *) & serv_addr, len) == SOCKET_ERROR)
    {
        g_warning("pgpipe failed to bind: %d\n", WSAGetLastError());
        closesocket(s);
        return -1;
    }
    if (listen(s, 1) == SOCKET_ERROR)
    {
        g_warning("pgpipe failed to listen: %d\n", WSAGetLastError());
        closesocket(s);
        return -1;
    }
    if (getsockname(s, (SOCKADDR *) & serv_addr, &len) == SOCKET_ERROR)
    {
        g_warning("pgpipe failed to getsockname: %d\n", WSAGetLastError());
        closesocket(s);
        return -1;
    }
    if ((handles[1] = socket(PF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
    {
        g_warning("pgpipe failed to create socket 2: %d\n", WSAGetLastError());
        closesocket(s);
        return -1;
    }

    if (connect(handles[1], (SOCKADDR *) & serv_addr, len) == SOCKET_ERROR)
    {
        g_warning("pgpipe failed to connect socket: %d\n", WSAGetLastError());
        closesocket(s);
        return -1;
    }
    if ((handles[0] = accept(s, (SOCKADDR *) & serv_addr, &len)) == INVALID_SOCKET)
    {
        g_warning("pgpipe failed to accept socket: %d\n", WSAGetLastError());
        closesocket(handles[1]);
        handles[1] = INVALID_SOCKET;
        closesocket(s);
        return -1;
    }
    closesocket(s);
    return 0;
}
#endif

struct timeval
ccnet_util_timeval_from_msec (uint64_t milliseconds)
{
    struct timeval ret;
    const uint64_t microseconds = milliseconds * 1000;
    ret.tv_sec  = microseconds / 1000000;
    ret.tv_usec = microseconds % 1000000;
    return ret;
}

int
ccnet_util_checkdir (const char *dir)
{
    struct stat st;

#ifdef WIN32
    /* remove trailing '\\' */
    char *path = g_strdup(dir);
    char *p = (char *)path + strlen(path) - 1;
    while (*p == '\\' || *p == '/') *p-- = '\0';
    if ((g_stat(dir, &st) < 0) || !S_ISDIR(st.st_mode)) {
        g_free (path);
        return -1;
    }
    g_free (path);
    return 0;
#else
    if ((g_stat(dir, &st) < 0) || !S_ISDIR(st.st_mode))
        return -1;
    return 0;
#endif
}

int
ccnet_util_checkdir_with_mkdir (const char *dir)
{
#ifdef WIN32
    int ret;
    char *path = g_strdup(dir);
    char *p = (char *)path + strlen(path) - 1;
    while (*p == '\\' || *p == '/') *p-- = '\0';
    ret = g_mkdir_with_parents(path, 0755);
    g_free (path);
    return ret;
#else
    return g_mkdir_with_parents(dir, 0755);
#endif
}


ssize_t						/* Read "n" bytes from a descriptor. */
ccnet_util_recvn(evutil_socket_t fd, void *vptr, size_t n)
{
	size_t	nleft;
	ssize_t	nread;
	char	*ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
#ifndef WIN32
        if ( (nread = read(fd, ptr, nleft)) < 0)
#else
        if ( (nread = recv(fd, ptr, nleft, 0)) < 0)
#endif
        {
			if (errno == EINTR)
				nread = 0;		/* and call read() again */
			else
				return(-1);
		} else if (nread == 0)
			break;				/* EOF */

		nleft -= nread;
		ptr   += nread;
	}
	return(n - nleft);		/* return >= 0 */
}

ssize_t						/* Write "n" bytes to a descriptor. */
ccnet_util_sendn (evutil_socket_t fd, const void *vptr, size_t n)
{
	size_t		nleft;
	ssize_t		nwritten;
	const char	*ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
#ifndef WIN32
        if ( (nwritten = write(fd, ptr, nleft)) <= 0)
#else
        if ( (nwritten = send(fd, ptr, nleft, 0)) <= 0)
#endif
        {
			if (nwritten < 0 && errno == EINTR)
				nwritten = 0;		/* and call write() again */
			else
				return(-1);			/* error */
		}

		nleft -= nwritten;
		ptr   += nwritten;
	}
	return(n);
}

char*
ccnet_util_expand_path (const char *src)
{
#ifdef WIN32
    char new_path[PATH_MAX + 1];
    char *p = new_path;
    const char *q = src;

    memset(new_path, 0, sizeof(new_path));
    if (*src == '~') {
        const char *home = g_get_home_dir();
        memcpy(new_path, home, strlen(home));
        p += strlen(new_path);
        q++;
    }
    memcpy(p, q, strlen(q));

    /* delete the charactor '\' or '/' at the end of the path
     * because the function stat faied to deal with directory names
     * with '\' or '/' in the end */
    p = new_path + strlen(new_path) - 1;
    while(*p == '\\' || *p == '/') *p-- = '\0';

    return strdup (new_path);
#else
    const char *next_in, *ntoken;
    char new_path[PATH_MAX + 1];
    char *next_out;
    int len;

   /* special cases */
    if (!src || *src == '\0')
        return NULL;
    if (strlen(src) > PATH_MAX)
        return NULL;

    next_in = src;
    next_out = new_path;
    *next_out = '\0';

    if (*src == '~') {
        /* handle src start with '~' or '~<user>' like '~plt' */
        struct passwd *pw = NULL;

        for ( ; *next_in != '/' && *next_in != '\0'; next_in++) ;

        len = next_in - src;
        if (len == 1) {
            pw = getpwuid (geteuid());
        } else {
            /* copy '~<user>' to new_path */
            memcpy (new_path, src, len);
            new_path[len] = '\0';
            pw = getpwnam (new_path + 1);
        }
        if (pw == NULL)
            return NULL;

        len = strlen (pw->pw_dir);
        memcpy (new_path, pw->pw_dir, len);
        next_out = new_path + len;
        *next_out = '\0';

        if (*next_in == '\0')
            return strdup (new_path);
    } else if (*src != '/') {
        getcwd (new_path, PATH_MAX);
        for ( ; *next_out; next_out++) ; /* to '\0' */
    }

    while (*next_in != '\0') {
        /* move ntoken to the next not '/' char  */
        for (ntoken = next_in; *ntoken == '/'; ntoken++) ;

        for (next_in = ntoken; *next_in != '/'
                 && *next_in != '\0'; next_in++) ;

        len = next_in - ntoken;

        if (len == 0) {
            /* the path ends with '/', keep it */
            *next_out++ = '/';
            *next_out = '\0';
            break;
        }

        if (len == 2 && ntoken[0] == '.' && ntoken[1] == '.')
        {
            /* '..' */
            for (; next_out > new_path && *next_out != '/'; next_out--)
                ;
            *next_out = '\0';
        } else if (ntoken[0] != '.' || len != 1) {
            /* not '.' */
            *next_out++ = '/';
            memcpy (next_out, ntoken, len);
            next_out += len;
            *next_out = '\0';
        }
    }

    /* the final special case */
    if (new_path[0] == '\0') {
        new_path[0] = '/';
        new_path[1] = '\0';
    }
    return strdup (new_path);
#endif
}

#ifndef WIN32
char* ccnet_util_gen_uuid ()
{
    char *uuid_str = g_malloc (37);
    uuid_t uuid;

    uuid_generate (uuid);
    uuid_unparse_lower (uuid, uuid_str);

    return uuid_str;
}

#else
char* ccnet_util_gen_uuid ()
{
    char *uuid_str = g_malloc (37);
    unsigned char *str = NULL;
    UUID uuid;

    UuidCreate(&uuid);
    UuidToString(&uuid, &str);
    memcpy(uuid_str, str, 37);
    RpcStringFree(&str);
    return uuid_str;
}
#endif

char* ccnet_util_strjoin_n (const char *seperator, int argc, char **argv)
{
    GString *buf;
    int i;
    char *str;

    if (argc == 0)
        return NULL;

    buf = g_string_new (argv[0]);
    for (i = 1; i < argc; ++i) {
        g_string_append (buf, seperator);
        g_string_append (buf, argv[i]);
    }

    str = buf->str;
    g_string_free (buf, FALSE);
    return str;
}

/**
 * handle the empty string problem.
 */
gchar*
ccnet_util_key_file_get_string (GKeyFile *keyf,
                                const char *category,
                                const char *key)
{
    gchar *v;

    if (!g_key_file_has_key (keyf, category, key, NULL))
        return NULL;

    v = g_key_file_get_string (keyf, category, key, NULL);
    if (v != NULL && v[0] == '\0') {
        g_free(v);
        return NULL;
    }

    return g_strchomp(v);
}

void
ccnet_util_string_list_free (GList *str_list)
{
    GList *ptr = str_list;

    while (ptr) {
        g_free (ptr->data);
        ptr = ptr->next;
    }

    g_list_free (str_list);
}

void
ccnet_util_string_list_join (GList *str_list, GString *str, const char *seperator)
{
    GList *ptr;
    if (!str_list)
        return;

    ptr = str_list;
    g_string_append (str, ptr->data);

    for (ptr = ptr->next; ptr; ptr = ptr->next) {
        g_string_append (str, seperator);
        g_string_append (str, (char *)ptr->data);
    }
}

static GList *
string_list_parse (const char *list_in_str, const char *seperator)
{
    if (!list_in_str)
        return NULL;

    GList *list = NULL;
    char **array = g_strsplit (list_in_str, seperator, 0);
    char **ptr;

    for (ptr = array; *ptr; ptr++) {
        list = g_list_prepend (list, g_strdup(*ptr));
    }
    list = g_list_reverse (list);

    g_strfreev (array);
    return list;
}

GList *
ccnet_util_string_list_parse_sorted (const char *list_in_str, const char *seperator)
{
    GList *list = string_list_parse (list_in_str, seperator);

    return g_list_sort (list, (GCompareFunc)g_strcmp0);
}

static unsigned hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return ~0;
}

int
ccnet_util_hex_to_rawdata (const char *hex_str,
                           unsigned char *rawdata,
                           int n_bytes)
{
    int i;
    for (i = 0; i < n_bytes; i++) {
        unsigned int val = (hexval(hex_str[0]) << 4) | hexval(hex_str[1]);
        if (val & ~0xff)
            return -1;
        *rawdata++ = val;
        hex_str += 2;
    }
    return 0;
}


#ifdef WIN32

#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT            WSAEAFNOSUPPORT
#endif

#ifndef IN6ADDRSZ
#define IN6ADDRSZ       16
#endif

#ifndef INT16SZ
#define INT16SZ         2
#endif

#ifndef INADDRSZ
#define INADDRSZ        4
#endif

#ifndef inet_ntop
static const char *
inet_ntop4 (const u_char *src, char *dst, size_t size)
{
    static const char fmt[] = "%u.%u.%u.%u";
    char tmp[sizeof("255.255.255.255")];
    int l;
    l = _snprintf(tmp, size, fmt, src[0], src[1], src[2], src[3]);
    if (l <= 0 || l >= size) {
        return (NULL);
    }
    strncpy(dst, tmp, size);
    return (dst);
}

static const char *
inet_ntop6 (const u_char *src, char *dst, size_t size)
{
    char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"];
    char *tp, *ep;
    struct
    {
        int base, len;
    } best, cur;
    u_int words[IN6ADDRSZ / INT16SZ];
    int i;
    int advance;
    memset(words, '\0', sizeof(words));
    for (i = 0; i < IN6ADDRSZ; i++)
        words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
    best.base = -1;
    cur.base = -1;
    best.len = -1;
    cur.len = -1;
    for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
        if (words[i] == 0) {
            if (cur.base == -1)
                cur.base = i, cur.len = 1;
            else
                cur.len++;
        }
        else {
            if (cur.base != -1) {
                if (best.base == -1 || cur.len > best.len)
                    best = cur;
                cur.base = -1;
            }
        }
    }
    if (cur.base != -1) {
        if (best.base == -1 || cur.len > best.len)
            best = cur;
    }
    if (best.base != -1 && best.len < 2)
        best.base = -1;
    tp = tmp;
    ep = tmp + sizeof(tmp);
    for (i = 0; i < (IN6ADDRSZ / INT16SZ) && tp < ep; i++) {
/** Are we inside the best run of 0x00's? */
        if (best.base != -1 && i >= best.base &&
            i < (best.base + best.len)) {
            if (i == best.base) {
                if (tp + 1 >= ep)
                    return (NULL);
                *tp++ = ':';
            }
            continue;
        }
/** Are we following an initial run of 0x00s or any real hex? */
        if (i != 0) {
            if (tp + 1 >= ep)
                return (NULL);
            *tp++ = ':';
        }
/** Is this address an encapsulated IPv4? */
        if (i == 6 && best.base == 0 &&
            (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
            if (!inet_ntop4(src+12, tp, (size_t)(ep - tp)))
                return (NULL);
            tp += strlen(tp);
            break;
        }
        advance = snprintf(tp, ep - tp, "%x", words[i]);
        if (advance <= 0 || advance >= ep - tp)
            return (NULL);
        tp += advance;
    }
/** Was it a trailing run of 0x00's? */
    if (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ)) {
        if (tp + 1 >= ep)
            return (NULL);
        *tp++ = ':';
    }
    if (tp + 1 >= ep)
        return (NULL);
    *tp++ = '\0';

/**
 * Check for overflow, copy, and we're done.
 */
    if ((size_t)(tp - tmp) > size) {
        errno = ENOSPC;
        return (NULL);
    }
    strncpy(dst, tmp, size);
    dst[size] = '\0';
    return (dst);
}

const char *
ccnet_util_inet_ntop(int af, const void *src, char *dst, size_t size)
{
    switch (af) {
    case AF_INET:
        return (inet_ntop4(src, dst, size));
    case AF_INET6:
        return (inet_ntop6(src, dst, size));
    default:
        return (NULL);
    }
/** NOTREACHED */
}
#endif //inet_ntop

#ifndef inet_aton
int
ccnet_util_inet_aton (const char *string, struct in_addr *addr)
{
    addr->s_addr = inet_addr(string);
    if (addr->s_addr != -1 || strcmp("255.255.255.255", string) == 0)
        return 1;
    return 0;
}
#endif

#ifndef inet_pton
/*
 *  Don't even consider trying to compile this on a system where
 * sizeof(int) < 4.  sizeof(int) > 4 is fine; all the world's not a VAX.
 */

/* int
 * inet_pton4(src, dst, pton)
 *      when last arg is 0: inet_aton(). with hexadecimal, octal and shorthand.
 *      when last arg is 1: inet_pton(). decimal dotted-quad only.
 * return:
 *      1 if `src' is a valid input, else 0.
 * notice:
 *      does not touch `dst' unless it's returning 1.
 * author:
 *      Paul Vixie, 1996.
 */
static int
inet_pton4 (const char *src, u_char *dst, int pton)
{
    u_int val;
    u_int digit;
    int base, n;
    unsigned char c;
    u_int parts[4];
    register u_int *pp = parts;

    c = *src;
    for (;;) {
        /*
         * Collect number up to ``.''.
         * Values are specified as for C:
         * 0x=hex, 0=octal, isdigit=decimal.
         */
        if (!isdigit(c))
            return (0);
        val = 0; base = 10;
        if (c == '0') {
            c = *++src;
            if (c == 'x' || c == 'X')
                base = 16, c = *++src;
            else if (isdigit(c) && c != '9')
                base = 8;
        }
        /* inet_pton() takes decimal only */
        if (pton && base != 10)
            return (0);
        for (;;) {
            if (isdigit(c)) {
                digit = c - '0';
                if (digit >= base)
                    break;
                val = (val * base) + digit;
                c = *++src;
            } else if (base == 16 && isxdigit(c)) {
                digit = c + 10 - (islower(c) ? 'a' : 'A');
                if (digit >= 16)
                    break;
                val = (val << 4) | digit;
                c = *++src;
            } else
                break;
        }
        if (c == '.') {
            /*
             * Internet format:
             *      a.b.c.d
             *      a.b.c   (with c treated as 16 bits)
             *      a.b     (with b treated as 24 bits)
             *      a       (with a treated as 32 bits)
             */
            if (pp >= parts + 3)
                return (0);
            *pp++ = val;
            c = *++src;
        } else
            break;
    }
    /*
     * Check for trailing characters.
     */
    if (c != '\0' && !isspace(c))
        return (0);
    /*
     * Concoct the address according to
     * the number of parts specified.
     */
    n = pp - parts + 1;
    /* inet_pton() takes dotted-quad only.  it does not take shorthand. */
    if (pton && n != 4)
        return (0);
    switch (n) {

    case 0:
        return (0);             /* initial nondigit */

    case 1:                         /* a -- 32 bits */
        break;

    case 2:                         /* a.b -- 8.24 bits */
        if (parts[0] > 0xff || val > 0xffffff)
            return (0);
        val |= parts[0] << 24;
        break;

    case 3:                         /* a.b.c -- 8.8.16 bits */
        if ((parts[0] | parts[1]) > 0xff || val > 0xffff)
            return (0);
        val |= (parts[0] << 24) | (parts[1] << 16);
        break;

    case 4:                         /* a.b.c.d -- 8.8.8.8 bits */
        if ((parts[0] | parts[1] | parts[2] | val) > 0xff)
            return (0);
        val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
        break;
    }
    if (dst) {
        val = htonl(val);
        memcpy(dst, &val, INADDRSZ);
    }
    return (1);
}

/* int
 * inet_pton6(src, dst)
 *      convert presentation level address to network order binary form.
 * return:
 *      1 if `src' is a valid [RFC1884 2.2] address, else 0.
 * notice:
 *      (1) does not touch `dst' unless it's returning 1.
 *      (2) :: in a full address is silently ignored.
 * credit:
 *      inspired by Mark Andrews.
 * author:
 *      Paul Vixie, 1996.
 */
static int
inet_pton6 (const char *src, u_char *dst)
{
    static const char xdigits_l[] = "0123456789abcdef",
        xdigits_u[] = "0123456789ABCDEF";
    u_char tmp[IN6ADDRSZ], *tp, *endp, *colonp;
    const char *xdigits, *curtok;
    int ch, saw_xdigit;
    u_int val;

    memset((tp = tmp), '\0', IN6ADDRSZ);
    endp = tp + IN6ADDRSZ;
    colonp = NULL;
    /* Leading :: requires some special handling. */
    if (*src == ':')
        if (*++src != ':')
            return (0);
    curtok = src;
    saw_xdigit = 0;
    val = 0;
    while ((ch = *src++) != '\0') {
        const char *pch;

        if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
            pch = strchr((xdigits = xdigits_u), ch);
        if (pch != NULL) {
            val <<= 4;
            val |= (pch - xdigits);
            if (val > 0xffff)
                return (0);
            saw_xdigit = 1;
            continue;
        }
        if (ch == ':') {
            curtok = src;
            if (!saw_xdigit) {
                if (colonp)
                    return (0);
                colonp = tp;
                continue;
            } else if (*src == '\0')
                return (0);
            if (tp + INT16SZ > endp)
                return (0);
            *tp++ = (u_char) (val >> 8) & 0xff;
            *tp++ = (u_char) val & 0xff;
            saw_xdigit = 0;
            val = 0;
            continue;
        }
        if (ch == '.' && ((tp + INADDRSZ) <= endp) &&
            inet_pton4(curtok, tp, 1) > 0) {
            tp += INADDRSZ;
            saw_xdigit = 0;
            break;  /* '\0' was seen by inet_pton4(). */
        }
        return (0);
    }
    if (saw_xdigit) {
        if (tp + INT16SZ > endp)
            return (0);
        *tp++ = (u_char) (val >> 8) & 0xff;
        *tp++ = (u_char) val & 0xff;
    }
    if (colonp != NULL) {
        /*
         * Since some memmove()'s erroneously fail to handle
         * overlapping regions, we'll do the shift by hand.
         */
        const int n = tp - colonp;
        int i;

        if (tp == endp)
            return (0);
        for (i = 1; i <= n; i++) {
            endp[- i] = colonp[n - i];
            colonp[n - i] = 0;
        }
        tp = endp;
    }
    if (tp != endp)
        return (0);
    memcpy(dst, tmp, IN6ADDRSZ);
    return (1);
}

/* int
 * inet_pton(af, src, dst)
 *      convert from presentation format (which usually means ASCII printable)
 *      to network format (which is usually some kind of binary format).
 * return:
 *      1 if the address was valid for the specified address family
 *      0 if the address wasn't valid (`dst' is untouched in this case)
 *      -1 if some other error occurred (`dst' is untouched in this case, too)
 * author:
 *      Paul Vixie, 1996.
 */
int
ccnet_util_inet_pton (int af, const char *src, void *dst)
{
    switch (af) {
    case AF_INET:
        return (inet_pton4(src, dst, 1));
    case AF_INET6:
        return (inet_pton6(src, dst));
    default:
        errno = EAFNOSUPPORT;
        return (-1);
    }
    /* NOTREACHED */
}
#endif

#endif //WIN32
