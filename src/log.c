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

#if _WIN32
#   include "getopt.h"
#else
#   include <unistd.h>
#   include <syslog.h>
#endif /* _WIN32 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "net.h"
#include "types.h"
#include "rinetd.h"
#include "log.h"

/* Log message strings (indexed by log event codes) */
char const *logMessages[] = {
    "unknown-error",
    "done-local-closed",
    "done-remote-closed",
    "accept-failed -",
    "local-socket-failed -",
    "local-bind-failed -",
    "local-connect-failed -",
    "opened",
    "allowed",
    "not-allowed",
    "denied",
};

/* Log file configuration (set by config parser) */
char *logFileName = NULL;
int logFormatCommon = 0;
uv_file logFd = -1;

/* Internal state set via log_init() */
static int log_forked = 0;
static int log_debug_enabled = 0;

/* Forward declarations */
static void get_gmtoff(int *tz, struct tm *result);
static void log_write_cb(uv_fs_t *req);


void log_init(void)
{
#if !_WIN32
    openlog("rinetd-uv", LOG_PID, LOG_DAEMON);
#endif
}

void log_shutdown(void)
{
#if !_WIN32
    closelog();
#endif
}

void log_set_forked(int forked)
{
    log_forked = forked;
}

void log_set_debug(int debug)
{
    log_debug_enabled = debug;
}


/* Format timestamp into buffer. Returns pointer to buffer. */
static char *format_timestamp(char *buf, size_t bufsize)
{
    int timz;
    struct tm t;
    get_gmtoff(&timz, &t);
    char sign = (timz < 0 ? '-' : '+');
    if (timz < 0) timz = -timz;
    int len = strftime(buf, bufsize, "%Y-%m-%dT%H:%M:%S", &t);
    if (len > 0 && (size_t)len < bufsize - 6)
        snprintf(buf + len, bufsize - len, "%c%02d%02d", sign, timz / 60, timz % 60);
    return buf;
}

/* Format connection discriminator into buffer. Returns pointer to buffer.
   Format: [src_ip:port/proto -> dst_ip:port/proto] or [unix:path -> unix:path] */
static char *format_connection_id(char *buf, size_t bufsize, ConnectionInfo const *cnx)
{
    if (!cnx) {
        buf[0] = '\0';
        return buf;
    }

    char src_addr[NI_MAXHOST] = "?";
    char src_port[NI_MAXSERV + 2] = "";  /* +2 for ':' and '\0' */
    char const *src_proto = "";
    char const *dst_host = cnx->log_toHost ? cnx->log_toHost : "?";
    uint16_t dst_port = cnx->log_toPort;
    char const *dst_proto = "";

    /* Determine source address */
    if (cnx->remoteAddress.ss_family == AF_UNIX) {
        snprintf(src_addr, sizeof(src_addr), "unix-client");
    } else if (cnx->remoteAddress.ss_family == AF_INET || cnx->remoteAddress.ss_family == AF_INET6) {
        char port_buf[NI_MAXSERV];
        getnameinfo((struct sockaddr *)&cnx->remoteAddress, sizeof(cnx->remoteAddress),
            src_addr, sizeof(src_addr), port_buf, sizeof(port_buf), NI_NUMERICHOST | NI_NUMERICSERV);
        snprintf(src_port, sizeof(src_port), ":%s", port_buf);
    }

    /* Determine protocol */
    if (cnx->remote.protocol == IPPROTO_TCP) {
        src_proto = "/tcp";
        dst_proto = "/tcp";
    } else if (cnx->remote.protocol == IPPROTO_UDP) {
        src_proto = "/udp";
        dst_proto = "/udp";
    } else if (cnx->remote.family == AF_UNIX || cnx->remoteAddress.ss_family == AF_UNIX) {
        src_proto = "";
        dst_proto = "";
    }

    /* Format the connection ID */
    if (cnx->remoteAddress.ss_family == AF_UNIX) {
        snprintf(buf, bufsize, "[%s -> %s:%d%s]", src_addr, dst_host, dst_port, dst_proto);
    } else if (dst_port > 0) {
        snprintf(buf, bufsize, "[%s%s%s -> %s:%d%s]", src_addr, src_port, src_proto, dst_host, dst_port, dst_proto);
    } else {
        snprintf(buf, bufsize, "[%s%s%s -> %s%s]", src_addr, src_port, src_proto, dst_host, dst_proto);
    }
    return buf;
}


/*
 * Internal helper for basic logging (no connection context).
 * Consolidates duplicate code from logError/logWarning/logInfo/logDebug.
 */
static void log_basic(int priority, char const *prefix, char const *fmt, va_list ap)
{
#if !_WIN32
    if (log_forked) {
        vsyslog(priority, fmt, ap);
        return;
    }
#endif
    char ts[32];
    if (prefix[0]) {
        fprintf(stderr, "%s rinetd-uv %s: ", format_timestamp(ts, sizeof(ts)), prefix);
    } else {
        fprintf(stderr, "%s rinetd-uv: ", format_timestamp(ts, sizeof(ts)));
    }
    vfprintf(stderr, fmt, ap);
}

/*
 * Internal helper for connection-aware logging.
 * Consolidates duplicate code from logErrorConn/logWarningConn/logInfoConn/logDebugConn.
 */
static void log_conn(int priority, char const *prefix, ConnectionInfo const *cnx,
                     char const *fmt, va_list ap)
{
#if !_WIN32
    if (log_forked) {
        char conn_id[256];
        char msg[1024];
        vsnprintf(msg, sizeof(msg), fmt, ap);
        syslog(priority, "%s %s", format_connection_id(conn_id, sizeof(conn_id), cnx), msg);
        return;
    }
#endif
    char ts[32];
    char conn_id[256];
    if (prefix[0]) {
        fprintf(stderr, "%s rinetd-uv %s: %s ", format_timestamp(ts, sizeof(ts)),
                prefix, format_connection_id(conn_id, sizeof(conn_id), cnx));
    } else {
        fprintf(stderr, "%s rinetd-uv: %s ", format_timestamp(ts, sizeof(ts)),
                format_connection_id(conn_id, sizeof(conn_id), cnx));
    }
    vfprintf(stderr, fmt, ap);
}


/* Basic logging functions (no connection context) */

void logError(char const *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_basic(LOG_ERR, "error", fmt, ap);
    va_end(ap);
}

void logWarning(char const *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_basic(LOG_WARNING, "warning", fmt, ap);
    va_end(ap);
}

void logInfo(char const *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_basic(LOG_INFO, "", fmt, ap);
    va_end(ap);
}

void logDebug(char const *fmt, ...)
{
    if (!log_debug_enabled)
        return;

    va_list ap;
    va_start(ap, fmt);
    log_basic(LOG_DEBUG, "debug", fmt, ap);
    va_end(ap);
}


/* Connection-aware logging functions */

void logErrorConn(ConnectionInfo const *cnx, char const *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_conn(LOG_ERR, "error", cnx, fmt, ap);
    va_end(ap);
}

void logWarningConn(ConnectionInfo const *cnx, char const *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_conn(LOG_WARNING, "warning", cnx, fmt, ap);
    va_end(ap);
}

void logInfoConn(ConnectionInfo const *cnx, char const *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_conn(LOG_INFO, "", cnx, fmt, ap);
    va_end(ap);
}

void logDebugConn(ConnectionInfo const *cnx, char const *fmt, ...)
{
    if (!log_debug_enabled)
        return;

    va_list ap;
    va_start(ap, fmt);
    log_conn(LOG_DEBUG, "debug", cnx, fmt, ap);
    va_end(ap);
}


/* Connection event logging (to log file) */
void logEvent(ConnectionInfo const *cnx, ServerInfo const *srv, int result)
{
    /* Bit of borrowing from Apache logging module here,
        thanks folks */
    int timz;
    char tstr[1024];
    char addressText[NI_MAXHOST] = { '?' };
    struct tm t;
    get_gmtoff(&timz, &t);
    char sign = (timz < 0 ? '-' : '+');
    if (timz < 0)
        timz = -timz;
    strftime(tstr, sizeof(tstr), "%Y-%m-%dT%H:%M:%S", &t);

    int64_t bytesOut = 0, bytesIn = 0;
    if (cnx != NULL) {
        /* Handle Unix socket clients - they don't have IP addresses */
        if (cnx->remoteAddress.ss_family == AF_UNIX) {
            snprintf(addressText, sizeof(addressText), "unix-client");
        } else {
            getnameinfo((struct sockaddr *)&cnx->remoteAddress, sizeof(cnx->remoteAddress),
                addressText, sizeof(addressText), NULL, 0, NI_NUMERICHOST);
        }
        bytesOut = cnx->remote.totalBytesOut;
        bytesIn = cnx->remote.totalBytesIn;
    }

    char const *fromHost = "?", *toHost = "?";
    uint16_t fromPort = 0, toPort = 0;
    /* Use cached server info from connection (survives server reload) */
    if (cnx && cnx->log_fromHost) {
        fromHost = cnx->log_fromHost;
        fromPort = cnx->log_fromPort;
        toHost = cnx->log_toHost;
        toPort = cnx->log_toPort;
    } else if (srv != NULL) {
        /* Fallback to srv if cached info not available */
        fromHost = srv->fromHost;
        fromPort = srv->fromAddrInfo ? getPort(srv->fromAddrInfo) : 0;
        toHost = srv->toHost;
        toPort = srv->toAddrInfo ? getPort(srv->toAddrInfo) : 0;
    }

    if (result == logNotAllowed || result == logDenied)
        logInfo("%s %s\n", addressText, logMessages[result]);
    if (logFd != -1) {
        char *log_buffer = malloc(RINETD_LOG_BUFFER_SIZE);
        if (!log_buffer) {
            return;
        }

        int len;
        if (logFormatCommon) {
            /* Fake a common log format log file in a way that
                most web analyzers can do something interesting with.
                We lie and say the protocol is HTTP because we don't
                want the web analyzer to reject the line. We also
                lie and claim success (code 200) because we don't
                want the web analyzer to ignore the line as an
                error and not analyze the "URL." We put a result
                message into our "URL" instead. The last field
                is an extra, giving the number of input bytes,
                after several placeholders meant to fill the
                positions frequently occupied by user agent,
                referrer, and server name information. */
            len = snprintf(log_buffer, RINETD_LOG_BUFFER_SIZE,
                           "%s - - [%s%c%.2d%.2d] \"GET /rinetd-services/%s/%d/%s/%d/%s HTTP/1.0\" 200 %llu - - - %llu\n",
                           addressText, tstr, sign, timz / 60, timz % 60, fromHost, (int)fromPort, toHost, (int)toPort, logMessages[result], (unsigned long long int)bytesOut, (unsigned long long int)bytesIn);
        } else {
            /* Write an rinetd-specific log entry with a
                less goofy format. */
            len = snprintf(log_buffer, RINETD_LOG_BUFFER_SIZE,
                           "%s%c%02d:%02d\t%s\t%s\t%d\t%s\t%d\t%llu\t%llu\t%s\n",
                           tstr, sign, timz / 60, timz % 60, addressText, fromHost, (int)fromPort, toHost, (int)toPort, (unsigned long long int)bytesIn, (unsigned long long int)bytesOut, logMessages[result]);
        }

        if (len > 0) {
            uv_fs_t *req = malloc(sizeof(uv_fs_t));
            if (req) {
                req->data = log_buffer;
                uv_buf_t buf = uv_buf_init(log_buffer, len);
                int ret = uv_fs_write(main_loop, req, logFd, &buf, 1, -1, log_write_cb);
                if (ret < 0) {
                    logError("uv_fs_write failed: %s\n", uv_strerror(ret));
                    free(log_buffer);
                    free(req);
                }
            } else {
                free(log_buffer);
            }
        } else {
            free(log_buffer);
        }
    }
}

static void log_write_cb(uv_fs_t *req)
{
    if (req->result < 0)
        logError("Async log write failed: %s\n", uv_strerror((int)req->result));

    /* Free the buffer stored in req->data */
    if (req->data)
        free(req->data);

    uv_fs_req_cleanup(req);
    free(req);
}


/* get_gmtoff was borrowed from Apache. Thanks folks. */
static void get_gmtoff(int *tz, struct tm *result)
{
    time_t tt = time(NULL);

    /* Assume we are never more than 24 hours away. */
    struct tm gmt;
    gmtime_r(&tt, &gmt);
    localtime_r(&tt, result);
    int days = result->tm_yday - gmt.tm_yday;
    int hours = ((days < -1 ? 24 : 1 < days ? -24 : days * 24)
        + result->tm_hour - gmt.tm_hour);
    int minutes = hours * 60 + result->tm_min - gmt.tm_min;
    *tz = minutes;
}
