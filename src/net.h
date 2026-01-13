/* Copyright © 1997—1999 Thomas Boutell <boutell@boutell.com>
                         and Boutell.Com, Inc.
             © 2003—2021 Sam Hocevar <sam@hocevar.net>
             © 2026 Marcin Gryszkalis <mg@fork.pl>

   This software is released for free use under the terms of
   the GNU Public License, version 2 or higher. NO WARRANTY
   IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK. */

#pragma once

#if _WIN32
    /* Define this to a reasonably large value */
#   include <winsock2.h>
#   include <ws2ipdef.h>
#   include <ws2tcpip.h>
#   include <windows.h>
#else
#   include <sys/types.h>
#   include <sys/socket.h>
#   include <sys/ioctl.h>
#   include <sys/un.h>
#   include <netdb.h>
#   include <netinet/in.h>
#   include <arpa/inet.h>
#endif

#include <stdint.h>

#if defined HAVE_ERRNO_H
#   include <errno.h>
#endif

#if defined HAVE_UNISTD_H
#   include <unistd.h>
#endif

/* We've got to get FIONBIO from somewhere. Try the Solaris location
    if it isn't defined yet by the above includes. */
#ifndef FIONBIO
#   include <sys/filio.h>
#endif /* FIONBIO */

#if HAVE_SSIZE_T
#   define SSIZE_T ssize_t
#else
#   define SSIZE_T int
#endif

#if HAVE_SOCKLEN_T
#   define SOCKLEN_T socklen_t
#else
#   define SOCKLEN_T int
#endif

#if _WIN32
#   define FIONBIO_ARG_T u_long
#else
#   define FIONBIO_ARG_T int
#endif

#if _WIN32
    /* _WIN32 doesn't really have WSAEAGAIN */
#   ifndef WSAEAGAIN
#       define WSAEAGAIN WSAEWOULDBLOCK
#   endif
#   ifdef gai_strerror
#       undef gai_strerror
#       define gai_strerror gai_strerrorA
#   endif
#else
    /* Windows sockets compatibility defines */
#   define INVALID_SOCKET (-1)
#   define SOCKET_ERROR (-1)
static inline int closesocket(int s)
{
    return close(s);
}
#   define WSAEWOULDBLOCK EWOULDBLOCK
#   define WSAEAGAIN EAGAIN
#   define WSAEINPROGRESS EINPROGRESS
#   define WSAEINTR EINTR
#   define SOCKET int
static inline int GetLastError(void)
{
    return errno;
}
#endif /* _WIN32 */

#include <uv.h>
#include "types.h"

int sameSocketAddress(struct sockaddr_storage *a, struct sockaddr_storage *b);
int getAddrInfoWithProto(char *address, char *port, int protocol, struct addrinfo **ai);
uint16_t getPort(struct addrinfo* ai);

/* Async DNS refresh functions */
int compareAddrinfo(struct addrinfo *a, struct addrinfo *b);
void dns_refresh_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *res);
int shouldEnableDnsRefresh(ServerInfo *srv);
int startAsyncDnsResolution(ServerInfo *srv);

/* Unix domain socket functions */
#define UNIX_SOCKET_PREFIX "unix:"
/* Portable max path length: sun_path size varies (Linux: 108, BSD: 104, old HP-UX: 92) */
#define UNIX_PATH_MAX (sizeof(((struct sockaddr_un *)0)->sun_path) - 1)

int isUnixSocketPath(const char *address);
int parseUnixSocketPath(const char *address, char **path, int *is_abstract);
int validateUnixSocketPath(const char *path, int is_abstract);
