/* Copyright © 1997—1999 Thomas Boutell <boutell@boutell.com>
                         and Boutell.Com, Inc.
             © 2003—2021 Sam Hocevar <sam@hocevar.net>
             © 2026 Marcin Gryszkalis <mg@fork.pl>
   This software is released for free use under the terms of
   the GNU Public License, version 2 or higher. NO WARRANTY
   IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK. */

#if HAVE_CONFIG_H
#   include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "net.h"
#include "rinetd.h"
#include "log.h"

int getAddrInfoWithProto(char *address, char *port, int protocol, struct addrinfo **ai)
{
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_protocol = protocol,
        .ai_socktype = protocol == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM,
        .ai_flags = AI_PASSIVE,
    };

    int ret = getaddrinfo(address, port, &hints, ai);
    if (ret != 0) {
        logError("cannot resolve host \"%s\" port %s (getaddrinfo() error: %s)\n", address ? address : "<null>", port ? port : "<null>", gai_strerror(ret));
    }

    return ret;
}

int sameSocketAddress(struct sockaddr_storage *a, struct sockaddr_storage *b)
{
    if (a->ss_family != b->ss_family)
        return 0;

    switch (a->ss_family) {
        case AF_INET: {
            struct sockaddr_in *a4 = (struct sockaddr_in *)a;
            struct sockaddr_in *b4 = (struct sockaddr_in *)b;
            return a4->sin_port == b4->sin_port
                && a4->sin_addr.s_addr == b4->sin_addr.s_addr;
        }
        case AF_INET6: {
            struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)a;
            struct sockaddr_in6 *b6 = (struct sockaddr_in6 *)b;
            return a6->sin6_port == b6->sin6_port
                && memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(a6->sin6_addr)) == 0;
        }
    }
    return 0;
}

uint16_t getPort(struct addrinfo* ai)
{
    switch (ai->ai_family) {
        case AF_INET:
            return ntohs(((struct sockaddr_in*)ai->ai_addr)->sin_port);
        case AF_INET6:
            return ntohs(((struct sockaddr_in6*)ai->ai_addr)->sin6_port);
        default:
            return 0;
    }
}

/* Compare two addrinfo structures - returns 1 if addresses match, 0 otherwise */
int compareAddrinfo(struct addrinfo *a, struct addrinfo *b)
{
    /* Compare first address only (rinetd uses first result) */
    if (!a || !b) return 0;
    if (!a->ai_addr || !b->ai_addr) return 0;
    if (a->ai_family != b->ai_family || a->ai_protocol != b->ai_protocol) return 0;

    if (a->ai_family == AF_INET) {
        struct sockaddr_in *a4 = (struct sockaddr_in *)a->ai_addr;
        struct sockaddr_in *b4 = (struct sockaddr_in *)b->ai_addr;
        return a4->sin_addr.s_addr == b4->sin_addr.s_addr &&
               a4->sin_port == b4->sin_port;
    } else if (a->ai_family == AF_INET6) {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)a->ai_addr;
        struct sockaddr_in6 *b6 = (struct sockaddr_in6 *)b->ai_addr;
        return memcmp(&a6->sin6_addr, &b6->sin6_addr, 16) == 0 &&
               a6->sin6_port == b6->sin6_port;
    }
    return 0;
}

/* Format IP address from addrinfo structure
 * Uses libuv's cross-platform uv_inet_ntop function
 * Returns pointer to buf on success, or empty string on failure */
const char *format_addr_ip(struct addrinfo *ai, char *buf, size_t buflen)
{
    if (!ai || !ai->ai_addr || !buf || buflen == 0) {
        if (buf && buflen > 0) buf[0] = '\0';
        return buf;
    }

    int err = 0;
    if (ai->ai_family == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *)ai->ai_addr;
        err = uv_inet_ntop(AF_INET, &addr->sin_addr, buf, buflen);
    } else if (ai->ai_family == AF_INET6) {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)ai->ai_addr;
        err = uv_inet_ntop(AF_INET6, &addr->sin6_addr, buf, buflen);
    } else {
        buf[0] = '\0';
        return buf;
    }

    if (err != 0) {
        buf[0] = '\0';
    }

    return buf;
}

/* Callback for async DNS resolution */
void dns_refresh_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *res)
{
    ServerInfo *srv = (ServerInfo *)req->data;
    free(req);
    srv->dns_req = NULL;

    if (status < 0) {
        logError("DNS refresh failed for %s: %s\n", srv->toHost, uv_strerror(status));
        return;  /* Keep using old address */
    }

    /* Compare addresses */
    if (!compareAddrinfo(res, srv->toAddrInfo)) {
        /* Address changed - log and update */
        char old_addr[INET6_ADDRSTRLEN], new_addr[INET6_ADDRSTRLEN];
        format_addr_ip(srv->toAddrInfo, old_addr, sizeof(old_addr));
        format_addr_ip(res, new_addr, sizeof(new_addr));

        logDebug("DNS refresh: %s resolved to new address %s (was %s)\n", srv->toHost, new_addr, old_addr);

        if (srv->toAddrInfo)
            uv_freeaddrinfo(srv->toAddrInfo);
        srv->toAddrInfo = res;
        srv->consecutive_failures = 0;
    } else {
        /* Address unchanged */
        uv_freeaddrinfo(res);
    }
}

/* Check if a string is an IP address (IPv4 or IPv6) */
static int isIpAddress(const char *str)
{
    if (!str) return 0;

    struct in_addr addr4;
    struct in6_addr addr6;

    /* Try parsing as IPv4 */
    if (inet_pton(AF_INET, str, &addr4) == 1) {
        return 1;
    }

    /* Try parsing as IPv6 (with or without brackets) */
    if (inet_pton(AF_INET6, str, &addr6) == 1) {
        return 1;
    }

    /* Remove brackets and try again for IPv6 */
    if (str[0] == '[') {
        size_t len = strlen(str);
        if (len > 2 && str[len-1] == ']') {
            char *stripped = malloc(len - 1);
            if (stripped) {
                memcpy(stripped, str + 1, len - 2);
                stripped[len - 2] = '\0';
                int result = inet_pton(AF_INET6, stripped, &addr6);
                free(stripped);
                if (result == 1) {
                    return 1;
                }
            }
        }
    }

    return 0;  /* Not an IP address */
}

/* Check if DNS refresh should be enabled for a server */
int shouldEnableDnsRefresh(ServerInfo *srv)
{
    /* Don't enable DNS refresh if period is 0 or negative */
    if (srv->dns_refresh_period <= 0) {
        return 0;
    }

    /* Don't enable DNS refresh if destination is already an IP address */
    if (isIpAddress(srv->toHost)) {
        return 0;
    }

    /* Enable DNS refresh for hostnames */
    return 1;
}

/* Start async DNS resolution for a server */
int startAsyncDnsResolution(ServerInfo *srv)
{
    if (srv->dns_req != NULL) {
        logDebug("DNS refresh already in progress for %s\n", srv->toHost);
        return 0;
    }

    uv_getaddrinfo_t *req = malloc(sizeof(uv_getaddrinfo_t));
    if (!req) {
        logError("malloc failed for DNS refresh request\n");
        return -1;
    }

    req->data = srv;
    srv->dns_req = req;

    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_protocol = srv->toProtocol_saved,
        .ai_socktype = srv->toProtocol_saved == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM,
        .ai_flags = AI_PASSIVE,
    };

    int ret = uv_getaddrinfo(main_loop, req, dns_refresh_cb, srv->toHost_saved, srv->toPort_saved, &hints);
    if (ret != 0) {
        logError("uv_getaddrinfo failed for %s: %s\n", srv->toHost, uv_strerror(ret));
        free(req);
        srv->dns_req = NULL;
        return -1;
    }
    return 0;
}

/* Check if address is a Unix domain socket path (starts with "unix:") */
int isUnixSocketPath(const char *address)
{
    if (!address) return 0;
    return strncmp(address, UNIX_SOCKET_PREFIX, strlen(UNIX_SOCKET_PREFIX)) == 0;
}

/* Parse Unix socket address into path and abstract flag
 * Returns: 0 on success, -1 on error
 * Sets *path to newly allocated string (caller must free)
 * Sets *is_abstract to 1 for abstract sockets (unix:@name), 0 for filesystem */
int parseUnixSocketPath(const char *address, char **path, int *is_abstract)
{
    if (!address || !path || !is_abstract) return -1;

    /* Check for unix: prefix */
    if (!isUnixSocketPath(address)) {
        logError("parseUnixSocketPath: address does not start with '%s'\n", UNIX_SOCKET_PREFIX);
        return -1;
    }

    const char *p = address + strlen(UNIX_SOCKET_PREFIX);

    /* Check for abstract socket (starts with @) */
    if (*p == '@') {
        *is_abstract = 1;
        p++;  /* Skip @ for the path */
        if (*p == '\0') {
            logError("parseUnixSocketPath: abstract socket name is empty\n");
            return -1;
        }
    } else {
        *is_abstract = 0;
        /* Filesystem sockets must start with / */
        if (*p != '/') {
            logError("parseUnixSocketPath: filesystem socket path must be absolute\n");
            return -1;
        }
    }

    *path = strdup(*is_abstract ? (p - 1) : p);  /* For abstract, include @ in path */
    if (!*path) {
        logError("parseUnixSocketPath: strdup failed\n");
        return -1;
    }

    return 0;
}

/* Validate Unix socket path
 * Returns: 0 on success, -1 on error */
int validateUnixSocketPath(const char *path, int is_abstract)
{
    (void)is_abstract;  /* Reserved for future use */
    if (!path) return -1;

    size_t len = strlen(path);

    /* Check length (sun_path is 108 bytes including null terminator) */
    if (len > UNIX_PATH_MAX) {
        logError("Unix socket path too long (%zu > %zu): %s\n", len, UNIX_PATH_MAX, path);
        return -1;
    }

    if (len == 0) {
        logError("Unix socket path is empty\n");
        return -1;
    }

    return 0;
}
