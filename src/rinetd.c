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

#ifndef RETSIGTYPE
#   define RETSIGTYPE void
#endif

#ifdef _MSC_VER
#   include <malloc.h>
#endif

#if _WIN32
#   include "getopt.h"
#else
#   include <getopt.h>
#   include <unistd.h>
#   include <sys/time.h>
#   include <syslog.h>
#endif /* _WIN32 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>

#include "match.h"
#include "net.h"
#include "types.h"
#include "rinetd.h"
#include "parse.h"

Rule *allRules = NULL;
int allRulesCount = 0;
int globalRulesCount = 0;

ServerInfo *seInfo = NULL;
int seTotal = 0;

/* Connection management */
static ConnectionInfo *connectionListHead = NULL;
static int activeConnections = 0;

/* UDP hash table for O(1) connection lookup */
#define UDP_HASH_TABLE_SIZE 10007  /* Prime number for better distribution */

typedef struct {
    ConnectionInfo **buckets;
    size_t bucket_count;
} UdpConnectionHashTable;

static UdpConnectionHashTable *udp_hash_table = NULL;

/* libuv event loop */
uv_loop_t *main_loop = NULL;
static int should_exit = 0;  /* Flag to signal graceful shutdown */

/* libuv signal handlers */
static uv_signal_t sighup_handle, sigint_handle, sigterm_handle, sigpipe_handle;

char *logFileName = NULL;
char *pidLogFileName = NULL;
int logFormatCommon = 0;
uv_file logFd = -1;
int bufferSize = RINETD_DEFAULT_BUFFER_SIZE;
int globalDnsRefreshPeriod = RINETD_DEFAULT_DNS_REFRESH_PERIOD;

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

enum {
    logUnknownError = 0,
    logLocalClosedFirst,
    logRemoteClosedFirst,
    logAcceptFailed,
    logLocalSocketFailed,
    logLocalBindFailed,
    logLocalConnectFailed,
    logOpened,
    logAllowed,
    logNotAllowed,
    logDenied,
};

static RinetdOptions options = {
    .conf_file = RINETD_CONFIG_FILE,
    .foreground = 0,
    .debug = 0,
};

static int forked = 0;
static int config_reload_pending = 0;

static void handleClose(ConnectionInfo *cnx, Socket *socket, Socket *other_socket);
static ConnectionInfo *allocateConnection(void);
static void cacheServerInfoForLogging(ConnectionInfo *cnx, ServerInfo const *srv);
static int checkConnectionAllowed(ConnectionInfo const *cnx);

/* UDP hash table and LRU functions */
static void init_udp_hash_table(void);
static void cleanup_udp_hash_table(void);

static int readArgs(int argc, char **argv, RinetdOptions *options);
static void clearConfiguration(void);
static void readConfiguration(char const *file);

static void registerPID(char const *pid_file_name);
static void logEvent(ConnectionInfo const *cnx, ServerInfo const *srv, int result);
static struct tm *get_gmtoff(int *tz);

/* Signal handlers */
#if !_WIN32
static RETSIGTYPE hup(int s);
#endif
static RETSIGTYPE quit(int s);

/* libuv functions */
static void signal_cb(uv_signal_t *handle, int signum);
static void dns_refresh_timer_cb(uv_timer_t *timer);
static void startServerListening(ServerInfo *srv);
static void server_handle_close_cb(uv_handle_t *handle);
static void dns_timer_close_cb(uv_handle_t *handle);
static void check_all_servers_closed(void);
static void log_write_cb(uv_fs_t *req);


int main(int argc, char *argv[])
{
#ifdef _WIN32
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(1, 1), &wsaData);
    if (result != 0) {
        logError("Your computer was not connected to the Internet at the time that "
            "this program was launched, or you do not have a 32-bit connection to the Internet.\n");
        exit(1);
    }
#else
    openlog("rinetd-uv", LOG_PID, LOG_DAEMON);
#endif

    readArgs(argc, argv, &options);

    if (!options.foreground) {
#if HAVE_DAEMON
        if (daemon(0, 0) != 0) {
            exit(0);
        }
        forked = 1;
#elif HAVE_FORK
        if (fork() != 0) {
            exit(0);
        }
        forked = 1;
#endif
    }

    readConfiguration(options.conf_file);
    if (pidLogFileName || !options.foreground) {
        registerPID(pidLogFileName ? pidLogFileName : RINETD_PID_FILE);
    }

    /* Initialize libuv event loop */
    main_loop = uv_default_loop();
    if (!main_loop) {
        logError("failed to initialize libuv event loop\n");
        exit(1);
    }

    /* Set up signal handlers using libuv */
#ifndef _WIN32
    /* SIGPIPE - ignore (start with no-op callback) */
    uv_signal_init(main_loop, &sigpipe_handle);
    uv_signal_start(&sigpipe_handle, signal_cb, SIGPIPE);

    /* SIGHUP - reload configuration */
    uv_signal_init(main_loop, &sighup_handle);
    uv_signal_start(&sighup_handle, signal_cb, SIGHUP);
#endif

    /* SIGINT and SIGTERM - graceful shutdown */
    uv_signal_init(main_loop, &sigint_handle);
    uv_signal_start(&sigint_handle, signal_cb, SIGINT);

    uv_signal_init(main_loop, &sigterm_handle);
    uv_signal_start(&sigterm_handle, signal_cb, SIGTERM);

    /* Initialize UDP hash table for O(1) connection lookup */
    init_udp_hash_table();

    /* Start libuv event handling for all servers */
    for (int i = 0; i < seTotal; ++i) {
        startServerListening(&seInfo[i]);
    }

    logInfo("starting redirections...\n");

    /* Run the event loop */
    while (!should_exit) {
        int ret = uv_run(main_loop, UV_RUN_DEFAULT);
        if (ret == 0) {
            /* No more active handles/requests */
            if (should_exit) {
                /* Graceful shutdown requested */
                break;
            }
            /* This shouldn't normally happen since servers are always listening */
            logError("event loop finished unexpectedly\n");
            break;
        }
    }

    /* Close all remaining handles gracefully */
    uv_walk(main_loop, (uv_walk_cb)uv_close, NULL);
    uv_run(main_loop, UV_RUN_DEFAULT);  /* Process close callbacks */

    /* Cleanup UDP hash table */
    cleanup_udp_hash_table();

    /* Close the loop */
    uv_loop_close(main_loop);

    return 0;
}

void logError(char const *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
#if !_WIN32
    if (forked)
        vsyslog(LOG_ERR, fmt, ap);
    else
#endif
    {
        fprintf(stderr, "rinetd-uv error: ");
        vfprintf(stderr, fmt, ap);
    }
    va_end(ap);
}

void logWarning(char const *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
#if !_WIN32
    if (forked)
        vsyslog(LOG_WARNING, fmt, ap);
    else
#endif
    {
        fprintf(stderr, "rinetd-uv warning: ");
        vfprintf(stderr, fmt, ap);
    }
    va_end(ap);
}

void logInfo(char const *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
#if !_WIN32
    if (forked)
        vsyslog(LOG_INFO, fmt, ap);
    else
#endif
    {
        fprintf(stderr, "rinetd-uv: ");
        vfprintf(stderr, fmt, ap);
    }
    va_end(ap);
}

void logDebug(char const *fmt, ...)
{
    if (!options.debug)
        return;

    va_list ap;
    va_start(ap, fmt);
#if !_WIN32
    if (forked)
        vsyslog(LOG_DEBUG, fmt, ap);
    else
#endif
    {
        fprintf(stderr, "rinetd-uv debug: ");
        vfprintf(stderr, fmt, ap);
    }
    va_end(ap);
}

static void clearConfiguration(void) {
    /* Remove server references from all active connections */
    for (ConnectionInfo *cnx = connectionListHead; cnx; cnx = cnx->next) {
        cnx->server = NULL;
    }
    /* Close existing server libuv handles and sockets. */
    int any_handles_to_close = 0;
    for (int i = 0; i < seTotal; ++i) {
        ServerInfo *srv = &seInfo[i];
        if (srv->handle_initialized) {
            any_handles_to_close = 1;
            /* Stop listening/recv before closing */
            if (srv->handle_type == UV_TCP) {
                /* TCP: close the handle (this stops accepting) */
                uv_close((uv_handle_t*)&srv->uv_handle.tcp, server_handle_close_cb);
            } else if (srv->handle_type == UV_NAMED_PIPE) {
                /* Unix socket: close the pipe handle */
                uv_close((uv_handle_t*)&srv->uv_handle.pipe, server_handle_close_cb);
            } else {  /* UV_UDP */
                /* UDP: stop receiving before closing */
                uv_udp_recv_stop(&srv->uv_handle.udp);
                uv_close((uv_handle_t*)&srv->uv_handle.udp, server_handle_close_cb);
            }
        } else {
            /* Handle not initialized, just close socket directly */
            if (srv->fd != INVALID_SOCKET) {
                closesocket(srv->fd);
            }
            /* Free resources immediately if handle wasn't initialized */
            free(srv->fromHost);
            free(srv->toHost);
            if (srv->fromAddrInfo) freeaddrinfo(srv->fromAddrInfo);
            if (srv->toAddrInfo) freeaddrinfo(srv->toAddrInfo);
            if (srv->sourceAddrInfo) freeaddrinfo(srv->sourceAddrInfo);
            /* Free Unix socket paths */
            free(srv->fromUnixPath);
            free(srv->toUnixPath);
        }
    }
    /* If no handles to close, free seInfo immediately */
    if (!any_handles_to_close) {
        free(seInfo);
        seInfo = NULL;
        seTotal = 0;

        /* If config reload is pending, reload now (no async handles to wait for) */
        if (config_reload_pending) {
            config_reload_pending = 0;
            readConfiguration(options.conf_file);
            /* Start new servers listening */
            for (int i = 0; i < seTotal; ++i) {
                startServerListening(&seInfo[i]);
            }
            logInfo("configuration reloaded, %d server(s) listening\n", seTotal);
        }
    }
    /* Otherwise, seInfo will be freed in server_handle_close_cb after all handles close */
    /* Forget existing rules. */
    for (int i = 0; i < allRulesCount; ++i) {
        free(allRules[i].pattern);
    }
    /* Free memory associated with previous set. */
    free(allRules);
    allRules = NULL;
    allRulesCount = globalRulesCount = 0;
    /* Free file names */
    free(logFileName);
    logFileName = NULL;
    free(pidLogFileName);
    pidLogFileName = NULL;
}

static void readConfiguration(char const *file) {

    /* Parse the configuration file. */
    parseConfiguration(file);

    /* Open the log file */
    if (logFd != -1) {
        uv_fs_t req;
        uv_fs_close(NULL, &req, logFd, NULL);
        uv_fs_req_cleanup(&req);
        logFd = -1;
    }
    if (logFileName) {
        uv_fs_t req;
        logFd = uv_fs_open(NULL, &req, logFileName, O_WRONLY | O_CREAT | O_APPEND,
                           0644, NULL);
        uv_fs_req_cleanup(&req);
        if (logFd < 0) {
            logError("could not open %s to append: %s\n", logFileName,
                     uv_strerror((int)logFd));
            logFd = -1;
        }
    }
}

void addServer(char *bindAddress, char *bindPort, int bindProtocol,
               char *connectAddress, char *connectPort, int connectProtocol,
               int serverTimeout, char *sourceAddress,
               int keepalive, int dns_refresh_period, int socketMode)
{
    ServerInfo si = {
        .fromHost = strdup(bindAddress),
        .toHost = strdup(connectAddress),
        .serverTimeout = serverTimeout,
        .fd = INVALID_SOCKET,
        .keepalive = keepalive,
        .dns_refresh_period = dns_refresh_period,
        .dns_timer_initialized = 0,
        .dns_timer_closing = 0,
        .consecutive_failures = 0,
        .dns_req = NULL,
        .toHost_saved = strdup(connectAddress),
        .toPort_saved = strdup(connectPort),
        .toProtocol_saved = connectProtocol,
        .fromUnixPath = NULL,
        .toUnixPath = NULL,
        .fromIsAbstract = 0,
        .toIsAbstract = 0,
        .socketMode = (mode_t)socketMode,
    };

    int fromIsUnix = isUnixSocketPath(bindAddress);
    int toIsUnix = isUnixSocketPath(connectAddress);

    /* Handle Unix domain socket bind address */
    if (fromIsUnix) {
        char *path = NULL;
        int is_abstract = 0;

        if (parseUnixSocketPath(bindAddress, &path, &is_abstract) != 0) {
            exit(1);
        }
        if (validateUnixSocketPath(path, is_abstract) != 0) {
            free(path);
            exit(1);
        }

        si.fromUnixPath = path;
        si.fromIsAbstract = is_abstract;
        si.fromAddrInfo = NULL;  /* No IP address for Unix sockets */
        si.handle_type = UV_NAMED_PIPE;
    } else {
        /* Resolve bind address */
        struct addrinfo *ai;
        int ret = getAddrInfoWithProto(bindAddress, bindPort, bindProtocol, &ai);
        if (ret != 0) {
            exit(1);
        }
        si.fromAddrInfo = ai;
        si.handle_type = (bindProtocol == IPPROTO_TCP) ? UV_TCP : UV_UDP;
    }

    /* Handle Unix domain socket connect address */
    if (toIsUnix) {
        char *path = NULL;
        int is_abstract = 0;

        if (parseUnixSocketPath(connectAddress, &path, &is_abstract) != 0) {
            if (si.fromUnixPath) free(si.fromUnixPath);
            if (si.fromAddrInfo) freeaddrinfo(si.fromAddrInfo);
            exit(1);
        }
        if (validateUnixSocketPath(path, is_abstract) != 0) {
            free(path);
            if (si.fromUnixPath) free(si.fromUnixPath);
            if (si.fromAddrInfo) freeaddrinfo(si.fromAddrInfo);
            exit(1);
        }

        si.toUnixPath = path;
        si.toIsAbstract = is_abstract;
        si.toAddrInfo = NULL;  /* No IP address for Unix sockets */
    } else {
        /* Resolve destination address */
        struct addrinfo *ai;
        int ret = getAddrInfoWithProto(connectAddress, connectPort, connectProtocol, &ai);
        if (ret != 0) {
            if (si.fromUnixPath) free(si.fromUnixPath);
            if (si.fromAddrInfo) freeaddrinfo(si.fromAddrInfo);
            exit(1);
        }
        si.toAddrInfo = ai;
    }

    /* Validate mode option usage */
    if (si.socketMode != 0) {
        if (!fromIsUnix) {
            logWarning("mode option ignored: bind address is not a Unix socket\n");
            si.socketMode = 0;
        } else if (si.fromIsAbstract) {
            logWarning("mode option ignored: abstract sockets have no filesystem permissions\n");
            si.socketMode = 0;
        }
    }

    /* Resolve source address if applicable (only for non-Unix destinations) */
    if (sourceAddress && !toIsUnix) {
        struct addrinfo *ai;
        int ret = getAddrInfoWithProto(sourceAddress, NULL, connectProtocol, &ai);
        if (ret != 0) {
            if (si.fromUnixPath) free(si.fromUnixPath);
            if (si.fromAddrInfo) freeaddrinfo(si.fromAddrInfo);
            if (si.toUnixPath) free(si.toUnixPath);
            if (si.toAddrInfo) freeaddrinfo(si.toAddrInfo);
            exit(1);
        }
        si.sourceAddrInfo = ai;
    }

    si.handle_initialized = 0;

    /* Allocate server info */
    seInfo = (ServerInfo *)realloc(seInfo, sizeof(ServerInfo) * (seTotal + 1));
    if (!seInfo) {
        logError("realloc failed for ServerInfo");
        exit(1);
    }
    seInfo[seTotal] = si;
    ++seTotal;
}

/* Allocate a new connection dynamically */
static ConnectionInfo *allocateConnection(void)
{
    ConnectionInfo *cnx = (ConnectionInfo*)malloc(sizeof(ConnectionInfo));
    if (!cnx) {
        logError("malloc failed for ConnectionInfo\n");
        return NULL;
    }

    /* Initialize all fields to zero */
    memset(cnx, 0, sizeof(*cnx));

    /* Initialize socket state */
    cnx->local.fd = INVALID_SOCKET;
    cnx->remote.fd = INVALID_SOCKET;
    cnx->coLog = logUnknownError;

    /* Add to doubly-linked list (head insertion) */
    cnx->prev = NULL;
    cnx->next = connectionListHead;
    if (connectionListHead) {
        connectionListHead->prev = cnx;
    }
    connectionListHead = cnx;

    activeConnections++;

    return cnx;
}

/* Cache server info for logging - survives server reload/removal */
static void cacheServerInfoForLogging(ConnectionInfo *cnx, ServerInfo const *srv)
{
    if (!cnx || !srv) {
        return;
    }

    cnx->log_fromHost = strdup(srv->fromHost);
    cnx->log_fromPort = srv->fromAddrInfo ? getPort(srv->fromAddrInfo) : 0;
    cnx->log_toHost = strdup(srv->toHost);
    cnx->log_toPort = srv->toAddrInfo ? getPort(srv->toAddrInfo) : 0;
}

/* libuv callback forward declarations */
static void tcp_server_accept_cb(uv_stream_t *server, int status);
static void unix_server_accept_cb(uv_stream_t *server, int status);
static void unix_connect_cb(uv_connect_t *req, int status);

static void udp_server_recv_cb(uv_udp_t *handle, ssize_t nread,
                               const uv_buf_t *buf,
                               const struct sockaddr *addr,
                               unsigned flags);
static void alloc_buffer_udp_server_cb(uv_handle_t *handle, size_t suggested_size,
                                       uv_buf_t *buf);
static void alloc_buffer_cb(uv_handle_t *handle, size_t suggested_size,
                            uv_buf_t *buf);

/* libuv signal handler callback */
static void signal_cb(uv_signal_t *handle, int signum)
{
    (void)handle;  /* Unused parameter */
    if (signum == SIGHUP) {
        hup(signum);
    } else if (signum == SIGINT || signum == SIGTERM) {
        quit(signum);
    } else if (signum == SIGPIPE) {
        /* SIGPIPE is ignored (no-op callback) */
        /* This prevents the process from terminating on broken pipes */
    }
}

/* DNS refresh timer callback */
static void dns_refresh_timer_cb(uv_timer_t *timer)
{
    ServerInfo *srv = (ServerInfo *)timer->data;
    logDebug("Periodic DNS refresh for %s:%d -> %s (interval: %ds)\n",
            srv->fromHost, getPort(srv->fromAddrInfo),
            srv->toHost, srv->dns_refresh_period);
    startAsyncDnsResolution(srv);
}

/* Prepare abstract socket name by replacing '@' prefix with '\0'
 * Returns: prepared name length, or 0 on error
 * The name_buf must be at least UNIX_PATH_MAX + 2 bytes */
static size_t prepareAbstractSocketName(const char *path, char *name_buf)
{
    if (!path || !name_buf) return 0;

    size_t path_len = strlen(path);
    if (path_len == 0 || path[0] != '@') {
        logError("Invalid abstract socket name: %s\n", path);
        return 0;
    }

    /* Abstract namespace uses null byte instead of '@' */
    name_buf[0] = '\0';
    memcpy(name_buf + 1, path + 1, path_len - 1);
    return path_len;
}

/* Initialize and start libuv event handling for a server */
static void startServerListening(ServerInfo *srv)
{
    if (srv->handle_initialized) {
        return;  /* Already initialized */
    }

    int ret;

    if (srv->handle_type == UV_NAMED_PIPE) {
        /* Initialize Unix domain socket (pipe) handle */
        ret = uv_pipe_init(main_loop, &srv->uv_handle.pipe, 0);
        if (ret != 0) {
            logError("uv_pipe_init() failed: %s\n", uv_strerror(ret));
            exit(1);
        }
        srv->uv_handle.pipe.data = srv;

        /* For filesystem sockets, remove any existing socket file */
        if (!srv->fromIsAbstract && srv->fromUnixPath) {
            unlink(srv->fromUnixPath);
        }

        /* Bind to Unix socket path */
        /* Set umask before bind to avoid race condition with chmod */
        mode_t old_umask = 0;
        if (srv->socketMode != 0) {
            old_umask = umask(~srv->socketMode & 0777);
        }

        if (srv->fromIsAbstract) {
            char abstract_name[UNIX_PATH_MAX + 2];
            size_t name_len = prepareAbstractSocketName(srv->fromUnixPath, abstract_name);
            if (name_len == 0) {
                if (srv->socketMode != 0) umask(old_umask);
                exit(1);
            }
            ret = uv_pipe_bind2(&srv->uv_handle.pipe, abstract_name, name_len,
                                UV_PIPE_NO_TRUNCATE);
        } else {
            ret = uv_pipe_bind(&srv->uv_handle.pipe, srv->fromUnixPath);
        }

        /* Restore umask immediately after bind */
        if (srv->socketMode != 0) {
            umask(old_umask);
        }

        if (ret != 0) {
            logError("uv_pipe_bind() failed for %s: %s\n",
                srv->fromHost, uv_strerror(ret));
            exit(1);
        }

        /* Start listening for connections */
        ret = uv_listen((uv_stream_t*)&srv->uv_handle.pipe,
                        RINETD_LISTEN_BACKLOG, unix_server_accept_cb);
        if (ret != 0) {
            logError("uv_listen() failed for Unix socket: %s\n", uv_strerror(ret));
            exit(1);
        }

        /* Get the actual fd for logging/cleanup */
        uv_os_fd_t fd;
        uv_fileno((uv_handle_t*)&srv->uv_handle.pipe, &fd);
        srv->fd = fd;
    }
    else if (srv->handle_type == UV_TCP) {
        /* Initialize TCP handle */
        ret = uv_tcp_init(main_loop, &srv->uv_handle.tcp);
        if (ret != 0) {
            logError("uv_tcp_init() failed: %s\n", uv_strerror(ret));
            exit(1);
        }
        srv->uv_handle.tcp.data = srv;

        /* Bind to address (libuv sets SO_REUSEADDR automatically) */
        ret = uv_tcp_bind(&srv->uv_handle.tcp, srv->fromAddrInfo->ai_addr, 0);
        if (ret != 0) {
            logError("uv_tcp_bind() failed for %s:%d: %s\n",
                srv->fromHost, getPort(srv->fromAddrInfo), uv_strerror(ret));
            exit(1);
        }

        /* Start listening for connections */
        ret = uv_listen((uv_stream_t*)&srv->uv_handle.tcp,
                        RINETD_LISTEN_BACKLOG, tcp_server_accept_cb);
        if (ret != 0) {
            logError("uv_listen() failed: %s\n", uv_strerror(ret));
            exit(1);
        }

        /* Get the actual fd for logging/cleanup */
        uv_os_fd_t fd;
        uv_fileno((uv_handle_t*)&srv->uv_handle.tcp, &fd);
        srv->fd = fd;
    }
    else {  /* UV_UDP */
        /* Initialize UDP handle */
        ret = uv_udp_init(main_loop, &srv->uv_handle.udp);
        if (ret != 0) {
            logError("uv_udp_init() failed: %s\n", uv_strerror(ret));
            exit(1);
        }
        srv->uv_handle.udp.data = srv;

        /* Bind to address with SO_REUSEADDR */
        ret = uv_udp_bind(&srv->uv_handle.udp, srv->fromAddrInfo->ai_addr, UV_UDP_REUSEADDR);
        if (ret != 0) {
            logError("uv_udp_bind() failed for %s:%d: %s\n",
                srv->fromHost, getPort(srv->fromAddrInfo), uv_strerror(ret));
            exit(1);
        }

        /* Start receiving datagrams */
        ret = uv_udp_recv_start(&srv->uv_handle.udp,
                                alloc_buffer_udp_server_cb, udp_server_recv_cb);
        if (ret != 0) {
            logError("uv_udp_recv_start() failed: %s\n", uv_strerror(ret));
            exit(1);
        }

        /* Get the actual fd for logging/cleanup */
        uv_os_fd_t fd;
        uv_fileno((uv_handle_t*)&srv->uv_handle.udp, &fd);
        srv->fd = fd;
    }

    srv->handle_initialized = 1;

    /* Initialize DNS refresh timer if enabled and destination is a hostname (not Unix socket) */
    if (!srv->toUnixPath && shouldEnableDnsRefresh(srv) && !srv->dns_timer_initialized) {
        int ret = uv_timer_init(main_loop, &srv->dns_refresh_timer);
        if (ret == 0) {
            srv->dns_refresh_timer.data = srv;
            srv->dns_timer_initialized = 1;
            ret = uv_timer_start(&srv->dns_refresh_timer, dns_refresh_timer_cb,
                                srv->dns_refresh_period * 1000,
                                srv->dns_refresh_period * 1000);
            if (ret != 0) {
                logError("uv_timer_start() failed for DNS refresh: %s\n", uv_strerror(ret));
                uv_close((uv_handle_t*)&srv->dns_refresh_timer, NULL);
                srv->dns_timer_initialized = 0;
            } else {
                logDebug("DNS refresh enabled for %s -> %s (interval: %ds)\n",
                        srv->fromHost, srv->toHost, srv->dns_refresh_period);
            }
        } else {
            logError("uv_timer_init() failed for DNS refresh: %s\n", uv_strerror(ret));
        }
    }
}

/* Check if all server handles and DNS timers are closed - if so, free seInfo and reload */
static void check_all_servers_closed(void)
{
    if (!seInfo) {
        return;  /* Already freed */
    }

    int all_closed = 1;
    for (int i = 0; i < seTotal; ++i) {
        /* Check if server handle is still open or closing */
        if (seInfo[i].handle_initialized) {
            all_closed = 0;
            break;
        }
        /* Check if DNS timer is still closing */
        if (seInfo[i].dns_timer_closing) {
            all_closed = 0;
            break;
        }
    }

    if (all_closed) {
        free(seInfo);
        seInfo = NULL;
        seTotal = 0;

        /* If config reload is pending, reload now that all handles are closed */
        if (config_reload_pending) {
            config_reload_pending = 0;
            readConfiguration(options.conf_file);
            /* Start new servers listening */
            for (int i = 0; i < seTotal; ++i) {
                startServerListening(&seInfo[i]);
            }
            logInfo("configuration reloaded, %d server(s) listening\n", seTotal);
        }
    }
}

/* DNS timer close callback - called when DNS timer is fully closed */
static void dns_timer_close_cb(uv_handle_t *handle)
{
    if (!handle || !handle->data) {
        return;
    }

    ServerInfo *srv = (ServerInfo*)handle->data;
    srv->dns_timer_initialized = 0;
    srv->dns_timer_closing = 0;

    /* Check if we can now free seInfo */
    check_all_servers_closed();
}

/* Server handle close callback - frees server resources */
static void server_handle_close_cb(uv_handle_t *handle)
{
    if (!handle || !handle->data) {
        return;
    }

    ServerInfo *srv = (ServerInfo*)handle->data;

    /* Mark handle as no longer initialized */
    srv->handle_initialized = 0;

    /* libuv has already closed the socket, just clear the fd */
    srv->fd = INVALID_SOCKET;

    /* Stop and close DNS refresh timer (async - callback will check for seInfo free) */
    if (srv->dns_timer_initialized && !srv->dns_timer_closing) {
        uv_timer_stop(&srv->dns_refresh_timer);
        srv->dns_timer_closing = 1;
        uv_close((uv_handle_t*)&srv->dns_refresh_timer, dns_timer_close_cb);
    }

    /* Cancel pending DNS request */
    if (srv->dns_req != NULL) {
        uv_cancel((uv_req_t*)srv->dns_req);
        srv->dns_req = NULL;
    }

    /* Free saved DNS data */
    free(srv->toHost_saved);
    srv->toHost_saved = NULL;
    free(srv->toPort_saved);
    srv->toPort_saved = NULL;

    /* For filesystem Unix sockets, unlink the socket file */
    if (srv->fromUnixPath && !srv->fromIsAbstract) {
        unlink(srv->fromUnixPath);
    }

    /* Free server resources */
    free(srv->fromHost);
    srv->fromHost = NULL;
    free(srv->toHost);
    srv->toHost = NULL;
    if (srv->fromAddrInfo) {
        freeaddrinfo(srv->fromAddrInfo);
        srv->fromAddrInfo = NULL;
    }
    if (srv->toAddrInfo) {
        freeaddrinfo(srv->toAddrInfo);
        srv->toAddrInfo = NULL;
    }
    if (srv->sourceAddrInfo) {
        freeaddrinfo(srv->sourceAddrInfo);
        srv->sourceAddrInfo = NULL;
    }

    /* Free Unix socket paths */
    free(srv->fromUnixPath);
    srv->fromUnixPath = NULL;
    free(srv->toUnixPath);
    srv->toUnixPath = NULL;

    /* Check if all server handles and DNS timers are closed */
    check_all_servers_closed();
}

/* Forward declarations for connection handling */
static void handle_close_cb(uv_handle_t *handle);
static void tcp_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);

/* TCP backend connection callback */
static void tcp_connect_cb(uv_connect_t *req, int status)
{
    ConnectionInfo *cnx = (ConnectionInfo*)req->data;
    free(req);

    if (status < 0) {
        logError("connect error: %s\n", uv_strerror(status));
        logEvent(cnx, cnx->server, logLocalConnectFailed);

        /* Track failures and trigger DNS refresh if threshold reached */
        if (cnx->server) {
            ServerInfo *srv = (ServerInfo *)cnx->server;
            srv->consecutive_failures++;
            if (srv->consecutive_failures >= RINETD_DNS_REFRESH_FAILURE_THRESHOLD &&
                shouldEnableDnsRefresh(srv)) {
                logDebug("Backend failures (%d) reached threshold for %s, triggering DNS refresh\n",
                        srv->consecutive_failures, srv->toHost);
                startAsyncDnsResolution(srv);
            }
        }

        /* Close local handle that was initialized but failed to connect */
        cnx->local_handle_closing = 1;  /* Set BEFORE uv_close() */
        uv_close((uv_handle_t*)&cnx->local_uv_handle.tcp, handle_close_cb);
        /* Close remote handle */
        if (cnx->remote_handle_initialized) {
            cnx->remote_handle_closing = 1;  /* Set BEFORE uv_close() */
            uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
        }
        return;
    }

    /* Extract fd for Socket struct */
    uv_os_fd_t fd;
    uv_fileno((uv_handle_t*)&cnx->local_uv_handle.tcp, &fd);
    cnx->local.fd = fd;

    /* Enable TCP keepalive on backend connection if configured */
    if (cnx->server && cnx->server->keepalive) {
        /* Use 60 second delay before first keepalive probe */
        int ret = uv_tcp_keepalive(&cnx->local_uv_handle.tcp, 1, 60);
        if (ret != 0) {
            logError("uv_tcp_keepalive (local) error: %s\n", uv_strerror(ret));
            /* Continue anyway - keepalive is optional */
        }
    }

    /* Start reading from local (backend) */
    int ret = uv_read_start((uv_stream_t*)&cnx->local_uv_handle.tcp,
                            alloc_buffer_cb, tcp_read_cb);
    if (ret != 0) {
        logError("uv_read_start (local) error: %s\n", uv_strerror(ret));
        /* Close both handles - local read failed, remote never started */
        handleClose(cnx, &cnx->local, &cnx->remote);
        return;
    }

    /* NOW start reading from remote (client) - backend is connected */
    ret = uv_read_start((uv_stream_t*)&cnx->remote_uv_handle.tcp,
                        alloc_buffer_cb, tcp_read_cb);
    if (ret != 0) {
        logError("uv_read_start (remote) error: %s\n", uv_strerror(ret));
        /* Stop reading on local handle since remote read failed */
        uv_read_stop((uv_stream_t*)&cnx->local_uv_handle.tcp);
        /* Close both handles */
        handleClose(cnx, &cnx->local, &cnx->remote);
        return;
    }

    logEvent(cnx, cnx->server, logOpened);

    /* Reset failure counter on successful connection */
    if (cnx->server) {
        ((ServerInfo *)cnx->server)->consecutive_failures = 0;
    }
}

/* TCP server accept callback */
static void tcp_server_accept_cb(uv_stream_t *server, int status)
{
    if (status < 0) {
        logError("accept error: %s\n", uv_strerror(status));
        return;
    }

    ServerInfo *srv = (ServerInfo*)server->data;
    ConnectionInfo *cnx = allocateConnection();
    if (!cnx) {
        return;
    }

    /* Initialize remote handle (client connection) */
    uv_tcp_init(main_loop, &cnx->remote_uv_handle.tcp);
    cnx->remote_handle_type = UV_TCP;
    cnx->remote_handle_initialized = 1;
    cnx->remote_uv_handle.tcp.data = cnx;

    /* Accept the connection */
    int ret = uv_accept(server, (uv_stream_t*)&cnx->remote_uv_handle.tcp);
    if (ret != 0) {
        logError("uv_accept error: %s\n", uv_strerror(ret));
        cnx->remote_handle_closing = 1;  /* Set BEFORE uv_close() */
        uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
        return;
    }

    /* Enable TCP keepalive on client connection if configured */
    if (srv->keepalive) {
        /* Use 60 second delay before first keepalive probe */
        ret = uv_tcp_keepalive(&cnx->remote_uv_handle.tcp, 1, 60);
        if (ret != 0) {
            logError("uv_tcp_keepalive (remote) error: %s\n", uv_strerror(ret));
            /* Continue anyway - keepalive is optional */
        }
    }

    /* Get remote address */
    struct sockaddr_storage addr;
    int addrlen = sizeof(addr);
    uv_tcp_getpeername(&cnx->remote_uv_handle.tcp,
                       (struct sockaddr*)&addr, &addrlen);
    cnx->remoteAddress = addr;

    /* Extract fd for Socket struct */
    uv_os_fd_t remote_fd;
    uv_fileno((uv_handle_t*)&cnx->remote_uv_handle.tcp, &remote_fd);
    cnx->remote.fd = remote_fd;

    /* Initialize connection state */
    cnx->remote.family = srv->fromAddrInfo->ai_family;
    cnx->remote.protocol = IPPROTO_TCP;
    cnx->remote.totalBytesIn = cnx->remote.totalBytesOut = 0;

    cnx->local.fd = INVALID_SOCKET;
    /* Set local family based on backend type - Unix or TCP */
    cnx->local.family = srv->toUnixPath ? AF_UNIX : srv->toAddrInfo->ai_family;
    cnx->local.protocol = srv->toUnixPath ? 0 : IPPROTO_TCP;
    cnx->local.totalBytesIn = cnx->local.totalBytesOut = 0;

    cnx->coClosing = 0;
    cnx->coLog = logUnknownError;
    cnx->server = srv;
    cacheServerInfoForLogging(cnx, srv);
    cnx->timer_initialized = 0;

    /* Check access rules */
    int logCode = checkConnectionAllowed(cnx);
    if (logCode != logAllowed) {
        cnx->remote_handle_closing = 1;  /* Set BEFORE uv_close() */
        uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
        logEvent(cnx, srv, logCode);
        return;
    }

    /* Connect to backend - either TCP or Unix socket */
    if (srv->toUnixPath) {
        /* Backend is Unix socket */
        uv_pipe_init(main_loop, &cnx->local_uv_handle.pipe, 0);
        cnx->local_handle_type = UV_NAMED_PIPE;
        cnx->local_handle_initialized = 1;
        cnx->local_uv_handle.pipe.data = cnx;

        uv_connect_t *connect_req = malloc(sizeof(uv_connect_t));
        if (!connect_req) {
            logError("malloc failed for Unix connect request\n");
            cnx->local_handle_closing = 1;
            cnx->remote_handle_closing = 1;
            uv_close((uv_handle_t*)&cnx->local_uv_handle.pipe, handle_close_cb);
            uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
            return;
        }
        connect_req->data = cnx;

        /* Connect to Unix socket backend */
        if (srv->toIsAbstract) {
            char abstract_name[UNIX_PATH_MAX + 2];
            size_t name_len = prepareAbstractSocketName(srv->toUnixPath, abstract_name);
            if (name_len == 0) {
                free(connect_req);
                cnx->local_handle_closing = 1;
                cnx->remote_handle_closing = 1;
                uv_close((uv_handle_t*)&cnx->local_uv_handle.pipe, handle_close_cb);
                uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
                return;
            }
            uv_pipe_connect2(connect_req, &cnx->local_uv_handle.pipe,
                             abstract_name, name_len,
                             UV_PIPE_NO_TRUNCATE, unix_connect_cb);
        } else {
            uv_pipe_connect(connect_req, &cnx->local_uv_handle.pipe,
                            srv->toUnixPath, unix_connect_cb);
        }
    } else {
        /* Backend is TCP */
        uv_tcp_init(main_loop, &cnx->local_uv_handle.tcp);
        cnx->local_handle_type = UV_TCP;
        cnx->local_handle_initialized = 1;
        cnx->local_uv_handle.tcp.data = cnx;

        /* Bind to source address if specified */
        if (srv->sourceAddrInfo) {
            ret = uv_tcp_bind(&cnx->local_uv_handle.tcp,
                              srv->sourceAddrInfo->ai_addr, 0);
            if (ret != 0) {
                logError("bind (source) error: %s\n", uv_strerror(ret));
                /* Continue anyway - binding is optional */
            }
        }

        /* Connect to backend (async) */
        uv_connect_t *connect_req = malloc(sizeof(uv_connect_t));
        if (!connect_req) {
            logError("malloc failed for connect request\n");
            cnx->local_handle_closing = 1;
            cnx->remote_handle_closing = 1;
            uv_close((uv_handle_t*)&cnx->local_uv_handle.tcp, handle_close_cb);
            uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
            return;
        }
        connect_req->data = cnx;

        ret = uv_tcp_connect(connect_req, &cnx->local_uv_handle.tcp,
                             srv->toAddrInfo->ai_addr, tcp_connect_cb);
        if (ret != 0) {
            logError("uv_tcp_connect error: %s\n", uv_strerror(ret));
            free(connect_req);
            cnx->local_handle_closing = 1;
            cnx->remote_handle_closing = 1;
            uv_close((uv_handle_t*)&cnx->local_uv_handle.tcp, handle_close_cb);
            uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
            return;
        }
    }

    /* DON'T start reading from remote yet - wait for backend connection to complete */
    /* This will be done in tcp_connect_cb or unix_connect_cb */
}

/* Unix backend connection callback */
static void unix_connect_cb(uv_connect_t *req, int status)
{
    ConnectionInfo *cnx = (ConnectionInfo*)req->data;
    free(req);

    if (status < 0) {
        logError("Unix connect error: %s\n", uv_strerror(status));
        logEvent(cnx, cnx->server, logLocalConnectFailed);

        /* Close local handle that was initialized but failed to connect */
        cnx->local_handle_closing = 1;
        uv_close((uv_handle_t*)&cnx->local_uv_handle.pipe, handle_close_cb);
        /* Close remote handle */
        if (cnx->remote_handle_initialized) {
            cnx->remote_handle_closing = 1;
            if (cnx->remote_handle_type == UV_NAMED_PIPE) {
                uv_close((uv_handle_t*)&cnx->remote_uv_handle.pipe, handle_close_cb);
            } else {
                uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
            }
        }
        return;
    }

    /* Extract fd for Socket struct */
    uv_os_fd_t fd;
    uv_fileno((uv_handle_t*)&cnx->local_uv_handle.pipe, &fd);
    cnx->local.fd = fd;

    /* Start reading from local (backend) - pipe is a stream, tcp_read_cb works */
    int ret = uv_read_start((uv_stream_t*)&cnx->local_uv_handle.pipe,
                            alloc_buffer_cb, tcp_read_cb);
    if (ret != 0) {
        logError("uv_read_start (local unix) error: %s\n", uv_strerror(ret));
        handleClose(cnx, &cnx->local, &cnx->remote);
        return;
    }

    /* NOW start reading from remote (client) - backend is connected */
    uv_stream_t *remote_stream;
    if (cnx->remote_handle_type == UV_NAMED_PIPE) {
        remote_stream = (uv_stream_t*)&cnx->remote_uv_handle.pipe;
    } else {
        remote_stream = (uv_stream_t*)&cnx->remote_uv_handle.tcp;
    }

    ret = uv_read_start(remote_stream, alloc_buffer_cb, tcp_read_cb);
    if (ret != 0) {
        logError("uv_read_start (remote) error: %s\n", uv_strerror(ret));
        uv_read_stop((uv_stream_t*)&cnx->local_uv_handle.pipe);
        handleClose(cnx, &cnx->local, &cnx->remote);
        return;
    }

    logEvent(cnx, cnx->server, logOpened);

    /* Reset failure counter on successful connection */
    if (cnx->server) {
        ((ServerInfo *)cnx->server)->consecutive_failures = 0;
    }
}

/* Unix server accept callback */
static void unix_server_accept_cb(uv_stream_t *server, int status)
{
    if (status < 0) {
        logError("Unix accept error: %s\n", uv_strerror(status));
        return;
    }

    ServerInfo *srv = (ServerInfo*)server->data;
    ConnectionInfo *cnx = allocateConnection();
    if (!cnx) {
        return;
    }

    /* Initialize remote handle (client connection) - it's a Unix pipe */
    uv_pipe_init(main_loop, &cnx->remote_uv_handle.pipe, 0);
    cnx->remote_handle_type = UV_NAMED_PIPE;
    cnx->remote_handle_initialized = 1;
    cnx->remote_uv_handle.pipe.data = cnx;

    /* Accept the connection */
    int ret = uv_accept(server, (uv_stream_t*)&cnx->remote_uv_handle.pipe);
    if (ret != 0) {
        logError("uv_accept (Unix) error: %s\n", uv_strerror(ret));
        cnx->remote_handle_closing = 1;
        uv_close((uv_handle_t*)&cnx->remote_uv_handle.pipe, handle_close_cb);
        return;
    }

    /* Extract fd for Socket struct */
    uv_os_fd_t remote_fd;
    uv_fileno((uv_handle_t*)&cnx->remote_uv_handle.pipe, &remote_fd);
    cnx->remote.fd = remote_fd;

    /* Initialize connection state */
    cnx->remote.family = AF_UNIX;
    cnx->remote.protocol = 0;  /* Unix socket doesn't use IPPROTO */
    cnx->remote.totalBytesIn = cnx->remote.totalBytesOut = 0;

    /* Unix sockets don't have IP addresses - clear remote address */
    memset(&cnx->remoteAddress, 0, sizeof(cnx->remoteAddress));
    cnx->remoteAddress.ss_family = AF_UNIX;

    cnx->local.fd = INVALID_SOCKET;
    cnx->local.protocol = 0;  /* Will be set based on backend type */
    cnx->local.totalBytesIn = cnx->local.totalBytesOut = 0;

    cnx->coClosing = 0;
    cnx->coLog = logUnknownError;
    cnx->server = srv;
    cacheServerInfoForLogging(cnx, srv);
    cnx->timer_initialized = 0;

    /* No IP-based access control for Unix sockets - filesystem permissions apply */
    /* Skip checkConnectionAllowed() */

    /* Connect to backend - either TCP or Unix */
    if (srv->toUnixPath) {
        /* Backend is Unix socket */
        uv_pipe_init(main_loop, &cnx->local_uv_handle.pipe, 0);
        cnx->local_handle_type = UV_NAMED_PIPE;
        cnx->local_handle_initialized = 1;
        cnx->local_uv_handle.pipe.data = cnx;
        cnx->local.family = AF_UNIX;

        uv_connect_t *connect_req = malloc(sizeof(uv_connect_t));
        if (!connect_req) {
            logError("malloc failed for Unix connect request\n");
            cnx->local_handle_closing = 1;
            cnx->remote_handle_closing = 1;
            uv_close((uv_handle_t*)&cnx->local_uv_handle.pipe, handle_close_cb);
            uv_close((uv_handle_t*)&cnx->remote_uv_handle.pipe, handle_close_cb);
            return;
        }
        connect_req->data = cnx;

        /* Connect to Unix socket backend */
        if (srv->toIsAbstract) {
            /* Abstract socket */
            char abstract_name[UNIX_PATH_MAX + 1];
            size_t name_len = prepareAbstractSocketName(srv->toUnixPath, abstract_name);
            if (name_len == 0) {
                free(connect_req);
                cnx->local_handle_closing = 1;
                cnx->remote_handle_closing = 1;
                uv_close((uv_handle_t*)&cnx->local_uv_handle.pipe, handle_close_cb);
                uv_close((uv_handle_t*)&cnx->remote_uv_handle.pipe, handle_close_cb);
                return;
            }
            uv_pipe_connect2(connect_req, &cnx->local_uv_handle.pipe,
                             abstract_name, name_len,
                             UV_PIPE_NO_TRUNCATE, unix_connect_cb);
        } else {
            uv_pipe_connect(connect_req, &cnx->local_uv_handle.pipe,
                            srv->toUnixPath, unix_connect_cb);
        }
    } else {
        /* Backend is TCP */
        uv_tcp_init(main_loop, &cnx->local_uv_handle.tcp);
        cnx->local_handle_type = UV_TCP;
        cnx->local_handle_initialized = 1;
        cnx->local_uv_handle.tcp.data = cnx;
        cnx->local.family = srv->toAddrInfo->ai_family;
        cnx->local.protocol = IPPROTO_TCP;

        /* Bind to source address if specified */
        if (srv->sourceAddrInfo) {
            ret = uv_tcp_bind(&cnx->local_uv_handle.tcp,
                              srv->sourceAddrInfo->ai_addr, 0);
            if (ret != 0) {
                logError("bind (source) error: %s\n", uv_strerror(ret));
            }
        }

        uv_connect_t *connect_req = malloc(sizeof(uv_connect_t));
        if (!connect_req) {
            logError("malloc failed for TCP connect request\n");
            cnx->local_handle_closing = 1;
            cnx->remote_handle_closing = 1;
            uv_close((uv_handle_t*)&cnx->local_uv_handle.tcp, handle_close_cb);
            uv_close((uv_handle_t*)&cnx->remote_uv_handle.pipe, handle_close_cb);
            return;
        }
        connect_req->data = cnx;

        ret = uv_tcp_connect(connect_req, &cnx->local_uv_handle.tcp,
                             srv->toAddrInfo->ai_addr, tcp_connect_cb);
        if (ret != 0) {
            logError("uv_tcp_connect error: %s\n", uv_strerror(ret));
            free(connect_req);
            cnx->local_handle_closing = 1;
            cnx->remote_handle_closing = 1;
            uv_close((uv_handle_t*)&cnx->local_uv_handle.tcp, handle_close_cb);
            uv_close((uv_handle_t*)&cnx->remote_uv_handle.pipe, handle_close_cb);
            return;
        }
    }
}

/* Buffer allocation callback for UDP server sockets */
static void alloc_buffer_udp_server_cb(uv_handle_t *handle, size_t suggested_size,
                                       uv_buf_t *buf)
{
    (void)handle;
    (void)suggested_size;

    /* Allocate buffer for UDP datagrams */
    buf->base = malloc(bufferSize);
    if (!buf->base) {
        buf->len = 0;
    } else {
        buf->len = bufferSize;
    }
}

/* Buffer allocation callback for libuv reads (connections) */
static void alloc_buffer_cb(uv_handle_t *handle, size_t suggested_size,
                            uv_buf_t *buf)
{
    (void)handle;  /* Unused - we don't need connection info to allocate */
    (void)suggested_size;  /* Use configured bufferSize instead */

    /* Allocate buffer for each read - will be freed in write callback */
    char *buffer = (char*)malloc(bufferSize);
    if (!buffer) {
        logError("malloc failed for read buffer\n");
        buf->base = NULL;
        buf->len = 0;
        return;
    }

    buf->base = buffer;
    buf->len = bufferSize;
}

/* Forward declaration for write callback */
static void tcp_write_cb(uv_write_t *req, int status);

/* TCP read callback */
static void tcp_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    ConnectionInfo *cnx = (ConnectionInfo*)stream->data;

    /* Defensive null check */
    if (!cnx) {
        if (buf->base) {
            free(buf->base);
        }
        return;
    }

    /* Determine which socket and the other socket */
    Socket *socket, *other_socket;
    uv_stream_t *other_stream;
    if ((uv_stream_t*)&cnx->local_uv_handle.tcp == stream) {
        socket = &cnx->local;
        other_socket = &cnx->remote;
        other_stream = (uv_stream_t*)&cnx->remote_uv_handle.tcp;
    } else {
        socket = &cnx->remote;
        other_socket = &cnx->local;
        other_stream = (uv_stream_t*)&cnx->local_uv_handle.tcp;
    }

    if (nread < 0) {
        /* Error or EOF - free buffer and close */
        if (buf->base) {
            free(buf->base);
        }
        if (nread != UV_EOF) {
            logError("read error: %s\n", uv_strerror((int)nread));
        }
        handleClose(cnx, socket, other_socket);
        return;
    }

    if (nread == 0) {
        /* EAGAIN - free buffer and try again later */
        if (buf->base) {
            free(buf->base);
        }
        return;
    }

    /* Update statistics */
    socket->totalBytesIn += nread;

    /* Check if the other socket is still open before writing */
    int *other_closing = (other_socket == &cnx->local)
        ? &cnx->local_handle_closing
        : &cnx->remote_handle_closing;

    if (*other_closing || uv_is_closing((uv_handle_t*)other_stream)) {
        /* Other side is closing, discard this data */
        free(buf->base);
        return;
    }

    /* Create write request with buffer info */
    WriteReq *wreq = (WriteReq*)malloc(sizeof(WriteReq));
    if (!wreq) {
        logError("malloc failed for WriteReq\n");
        free(buf->base);
        handleClose(cnx, socket, other_socket);
        return;
    }

    wreq->cnx = cnx;
    wreq->buffer = buf->base;  /* Take ownership of buffer */
    wreq->buffer_size = nread;
    wreq->socket = other_socket;  /* Writing to OTHER socket */

    /* Set up uv_write request */
    uv_buf_t wrbuf = uv_buf_init(buf->base, nread);
    int ret = uv_write(&wreq->req, other_stream, &wrbuf, 1, tcp_write_cb);
    if (ret != 0) {
        logError("uv_write error: %s\n", uv_strerror(ret));
        free(wreq->buffer);
        free(wreq);
        handleClose(cnx, socket, other_socket);
        return;
    }

    /* Buffer and wreq will be freed in tcp_write_cb */
}

/* TCP write completion callback */
static void tcp_write_cb(uv_write_t *req, int status)
{
    /* Get WriteReq which contains the connection and buffer */
    WriteReq *wreq = (WriteReq*)req;
    ConnectionInfo *cnx = wreq->cnx;

    /* Update statistics */
    wreq->socket->totalBytesOut += wreq->buffer_size;

    /* Free the buffer that was allocated in tcp_read_cb */
    free(wreq->buffer);

    /* Handle write errors */
    if (status < 0) {
        logError("write error: %s\n", uv_strerror(status));
        /* Determine which socket failed based on handle */
        Socket *socket, *other_socket;
        if (req->handle == (uv_stream_t*)&cnx->local_uv_handle.tcp) {
            socket = &cnx->local;
            other_socket = &cnx->remote;
        } else {
            socket = &cnx->remote;
            other_socket = &cnx->local;
        }
        free(wreq);
        handleClose(cnx, socket, other_socket);
        return;
    }

    /* Free the write request */
    free(wreq);

    /* That's it! No flow control, no position tracking - just free and done */
}

/* Handle close callback */
static void handle_close_cb(uv_handle_t *handle)
{
    /* Called after handle fully closed */
    if (!handle || !handle->data) {
        return;
    }

    ConnectionInfo *cnx = (ConnectionInfo*)handle->data;

    /* Mark the specific handle as closed */
    if ((uv_handle_t*)&cnx->local_uv_handle == handle) {
        cnx->local_handle_closing = 0;
        cnx->local_handle_initialized = 0;
    } else if ((uv_handle_t*)&cnx->remote_uv_handle == handle) {
        cnx->remote_handle_closing = 0;
        cnx->remote_handle_initialized = 0;
    } else if ((uv_handle_t*)&cnx->timeout_timer == handle) {
        cnx->timer_closing = 0;
        cnx->timer_initialized = 0;
    }

    /* Check if all handles are closed - if so, free the connection */
    /* IMPORTANT: uv_close() waits for pending I/O before calling this callback,
       so we don't need to check for pending writes separately. */
    if (!cnx->local_handle_initialized && !cnx->local_handle_closing &&
        !cnx->remote_handle_initialized && !cnx->remote_handle_closing &&
        !cnx->timer_initialized && !cnx->timer_closing) {
        /* All handles are closed - safe to free the connection */

        /* Remove from doubly-linked list */
        if (cnx->prev) {
            cnx->prev->next = cnx->next;
        } else {
            connectionListHead = cnx->next;
        }
        if (cnx->next) {
            cnx->next->prev = cnx->prev;
        }

        activeConnections--;

        /* Clear all handle->data pointers AFTER removing from list but BEFORE freeing.
           This ensures any subsequent callbacks will see NULL and return early. */
        cnx->local_uv_handle.tcp.data = NULL;   /* Union - sets both tcp.data and udp.data */
        cnx->remote_uv_handle.tcp.data = NULL;  /* Union - sets both tcp.data and udp.data */
        cnx->timeout_timer.data = NULL;

        /* Free cached logging info */
        free(cnx->log_fromHost);
        free(cnx->log_toHost);

        /* Now safe to free the connection (no fixed buffers to free) */
        free(cnx);
    }
}

/* Forward declarations for UDP */
static void udp_send_cb(uv_udp_send_t *req, int status);
static void udp_timeout_cb(uv_timer_t *timer);
static void udp_local_recv_cb(uv_udp_t *handle, ssize_t nread,
                              const uv_buf_t *buf,
                              const struct sockaddr *addr,
                              unsigned flags);

/* UDP send to backend - takes ownership of buffer */
static void udp_send_to_backend(ConnectionInfo *cnx, char *data, int data_len)
{
    /* Check if local handle is closing */
    if (cnx->local_handle_closing || !cnx->local_handle_initialized ||
        uv_is_closing((uv_handle_t*)&cnx->local_uv_handle.udp)) {
        free(data);  /* Can't send, free the buffer */
        return;
    }

    /* Create send request with buffer info */
    UdpSendReq *sreq = (UdpSendReq*)malloc(sizeof(UdpSendReq));
    if (!sreq) {
        logError("malloc failed for UdpSendReq\n");
        free(data);
        return;
    }

    sreq->cnx = cnx;
    sreq->buffer = data;  /* Take ownership */
    sreq->buffer_size = data_len;
    sreq->is_to_backend = 1;
    sreq->dest_addr = *(struct sockaddr_storage*)cnx->server->toAddrInfo->ai_addr;

    /* Set up buffer for sending */
    uv_buf_t wrbuf = uv_buf_init(data, data_len);

    int ret = uv_udp_send(&sreq->req, &cnx->local_uv_handle.udp, &wrbuf, 1,
                          cnx->server->toAddrInfo->ai_addr, udp_send_cb);
    if (ret != 0) {
        logError("uv_udp_send (to backend) error: %s\n", uv_strerror(ret));
        free(sreq->buffer);
        free(sreq);
    }
}

/* UDP send to client - takes ownership of buffer */
static void udp_send_to_client(ConnectionInfo *cnx, char *data, int data_len)
{
    ServerInfo *srv = (ServerInfo *)cnx->server;
    if (!srv) {
        free(data);  /* Server gone, free the buffer */
        return;
    }

    /* Check if server UDP handle is closing */
    if (!srv->handle_initialized || uv_is_closing((uv_handle_t*)&srv->uv_handle.udp)) {
        free(data);  /* Can't send, free the buffer */
        return;
    }

    /* Create send request with buffer info */
    UdpSendReq *sreq = (UdpSendReq*)malloc(sizeof(UdpSendReq));
    if (!sreq) {
        logError("malloc failed for UdpSendReq\n");
        free(data);
        return;
    }

    sreq->cnx = cnx;
    sreq->buffer = data;  /* Take ownership */
    sreq->buffer_size = data_len;
    sreq->is_to_backend = 0;
    sreq->dest_addr = cnx->remoteAddress;

    /* Set up buffer for sending */
    uv_buf_t wrbuf = uv_buf_init(data, data_len);

    int ret = uv_udp_send(&sreq->req, &srv->uv_handle.udp, &wrbuf, 1,
                          (struct sockaddr*)&cnx->remoteAddress, udp_send_cb);
    if (ret != 0) {
        logError("uv_udp_send (to client) error: %s\n", uv_strerror(ret));
        free(sreq->buffer);
        free(sreq);
    }
}

/* UDP send completion callback */
static void udp_send_cb(uv_udp_send_t *req, int status)
{
    UdpSendReq *sreq = (UdpSendReq*)req;
    ConnectionInfo *cnx = sreq->cnx;

    /* Update statistics */
    if (sreq->is_to_backend) {
        cnx->local.totalBytesOut += sreq->buffer_size;
    } else {
        cnx->remote.totalBytesOut += sreq->buffer_size;
    }

    /* Free the buffer */
    free(sreq->buffer);

    if (status < 0) {
        logError("UDP send error: %s\n", uv_strerror(status));
        /* For UDP, we don't close on send errors - just log */

        /* Track backend failures and trigger DNS refresh if threshold reached */
        if (sreq->is_to_backend && cnx->server) {
            ServerInfo *srv = (ServerInfo *)cnx->server;
            srv->consecutive_failures++;
            if (srv->consecutive_failures >= RINETD_DNS_REFRESH_FAILURE_THRESHOLD &&
                shouldEnableDnsRefresh(srv)) {
                logDebug("UDP backend failures (%d) reached threshold for %s, triggering DNS refresh\n",
                        srv->consecutive_failures, srv->toHost);
                startAsyncDnsResolution(srv);
            }
        }
    } else {
        /* Reset failure counter on successful backend send */
        if (sreq->is_to_backend && cnx->server) {
            ((ServerInfo *)cnx->server)->consecutive_failures = 0;
        }
    }

    /* Free the send request */
    free(sreq);

    /* That's it! No position tracking, no buffer management */
}

/* ===== UDP Hash Table and LRU Functions ===== */

/* Compare two socket addresses for equality */
static int sockaddr_equal(struct sockaddr_storage const *a, struct sockaddr_storage const *b)
{
    if (a->ss_family != b->ss_family) return 0;

    if (a->ss_family == AF_INET) {
        struct sockaddr_in const *sin_a = (struct sockaddr_in const *)a;
        struct sockaddr_in const *sin_b = (struct sockaddr_in const *)b;
        return sin_a->sin_addr.s_addr == sin_b->sin_addr.s_addr &&
               sin_a->sin_port == sin_b->sin_port;
    } else if (a->ss_family == AF_INET6) {
        struct sockaddr_in6 const *sin6_a = (struct sockaddr_in6 const *)a;
        struct sockaddr_in6 const *sin6_b = (struct sockaddr_in6 const *)b;
        return memcmp(&sin6_a->sin6_addr, &sin6_b->sin6_addr, 16) == 0 &&
               sin6_a->sin6_port == sin6_b->sin6_port;
    }

    return 0;
}

/* Hash function for (server, remote_address) tuple - DJB2 algorithm */
static uint32_t hash_udp_connection(ServerInfo const *srv, struct sockaddr_storage const *addr)
{
    uint32_t hash = 5381;  /* DJB2 hash initialization */

    /* Hash server pointer */
    hash = ((hash << 5) + hash) + (uintptr_t)srv;

    /* Hash address based on family */
    if (addr->ss_family == AF_INET) {
        struct sockaddr_in const *sin = (struct sockaddr_in const *)addr;
        hash = ((hash << 5) + hash) + sin->sin_addr.s_addr;
        hash = ((hash << 5) + hash) + sin->sin_port;
    } else if (addr->ss_family == AF_INET6) {
        struct sockaddr_in6 const *sin6 = (struct sockaddr_in6 const *)addr;
        for (int i = 0; i < 16; i++) {
            hash = ((hash << 5) + hash) + sin6->sin6_addr.s6_addr[i];
        }
        hash = ((hash << 5) + hash) + sin6->sin6_port;
    }

    return hash % UDP_HASH_TABLE_SIZE;
}

/* Initialize UDP hash table */
static void init_udp_hash_table(void)
{
    if (udp_hash_table) return;  /* Already initialized */

    udp_hash_table = malloc(sizeof(UdpConnectionHashTable));
    if (!udp_hash_table) {
        logError("Failed to allocate UDP hash table\n");
        exit(1);
    }

    udp_hash_table->bucket_count = UDP_HASH_TABLE_SIZE;
    udp_hash_table->buckets = calloc(UDP_HASH_TABLE_SIZE, sizeof(ConnectionInfo*));
    if (!udp_hash_table->buckets) {
        logError("Failed to allocate UDP hash table buckets\n");
        exit(1);
    }
}

/* Lookup UDP connection in hash table by server and remote address */
static ConnectionInfo *lookup_udp_connection(ServerInfo const *srv,
                                             struct sockaddr_storage const *addr)
{
    if (!udp_hash_table) return NULL;

    uint32_t hash = hash_udp_connection(srv, addr);
    ConnectionInfo *conn = udp_hash_table->buckets[hash];

    /* Walk hash bucket chain */
    while (conn) {
        if (conn->server == srv &&
            conn->remote.protocol == IPPROTO_UDP &&
            sockaddr_equal(&conn->remoteAddress, addr)) {
            return conn;
        }
        conn = conn->hash_next;
    }

    return NULL;
}

/* Insert UDP connection into hash table */
static void hash_insert_udp_connection(ConnectionInfo *conn)
{
    if (!udp_hash_table) init_udp_hash_table();

    uint32_t hash = hash_udp_connection(conn->server, &conn->remoteAddress);

    /* Insert at head of bucket chain */
    conn->hash_next = udp_hash_table->buckets[hash];
    udp_hash_table->buckets[hash] = conn;
}

/* Remove UDP connection from hash table */
static void hash_remove_udp_connection(ConnectionInfo *conn)
{
    if (!udp_hash_table) return;

    uint32_t hash = hash_udp_connection(conn->server, &conn->remoteAddress);

    /* Find and remove from bucket chain */
    ConnectionInfo **pp = &udp_hash_table->buckets[hash];
    while (*pp && *pp != conn) {
        pp = &(*pp)->hash_next;
    }
    if (*pp) {
        *pp = conn->hash_next;
        conn->hash_next = NULL;
    }
}

/* Insert at head of LRU list (most recently used) */
static void lru_insert_head(ServerInfo *srv, ConnectionInfo *conn)
{
    conn->lru_prev = NULL;
    conn->lru_next = srv->udp_lru_head;

    if (srv->udp_lru_head) {
        srv->udp_lru_head->lru_prev = conn;
    } else {
        /* List was empty */
        srv->udp_lru_tail = conn;
    }

    srv->udp_lru_head = conn;
}

/* Remove from LRU list */
static void lru_remove(ServerInfo *srv, ConnectionInfo *conn)
{
    if (conn->lru_prev) {
        conn->lru_prev->lru_next = conn->lru_next;
    } else {
        /* Was at head */
        srv->udp_lru_head = conn->lru_next;
    }

    if (conn->lru_next) {
        conn->lru_next->lru_prev = conn->lru_prev;
    } else {
        /* Was at tail */
        srv->udp_lru_tail = conn->lru_prev;
    }

    conn->lru_prev = conn->lru_next = NULL;
}

/* Move to head of LRU list (mark as recently used) */
static void lru_touch(ServerInfo *srv, ConnectionInfo *conn)
{
    if (srv->udp_lru_head == conn) return;  /* Already at head */

    lru_remove(srv, conn);
    lru_insert_head(srv, conn);
}

/* Cleanup UDP hash table */
static void cleanup_udp_hash_table(void)
{
    if (!udp_hash_table) return;

    free(udp_hash_table->buckets);
    free(udp_hash_table);
    udp_hash_table = NULL;
}

/* ===== End of UDP Hash Table and LRU Functions ===== */

/* Find and close the oldest UDP connection for a given server (LRU eviction) */
static void close_oldest_udp_connection(ServerInfo *srv)
{
    /* O(1) - just get tail of LRU list */
    ConnectionInfo *oldest = srv->udp_lru_tail;

    if (oldest && !oldest->coClosing) {
        handleClose(oldest, &oldest->remote, &oldest->local);
    }
}

/* UDP timeout callback */
static void udp_timeout_cb(uv_timer_t *timer)
{
    ConnectionInfo *cnx = (ConnectionInfo*)timer->data;
    handleClose(cnx, &cnx->remote, &cnx->local);
}

/* UDP local (backend) receive callback */
static void udp_local_recv_cb(uv_udp_t *handle, ssize_t nread,
                              const uv_buf_t *buf,
                              const struct sockaddr *addr,
                              unsigned flags)
{
    (void)addr;  /* Unused - we already know the backend */
    (void)flags;

    if (nread < 0) {
        logError("UDP local recv error: %s\n", uv_strerror((int)nread));
        if (buf->base) free(buf->base);
        return;
    }

    if (nread == 0) {
        if (buf->base) free(buf->base);
        return;
    }

    ConnectionInfo *cnx = (ConnectionInfo*)handle->data;

    /* Update statistics */
    cnx->local.totalBytesIn += nread;

    /* Send immediately to client - udp_send_to_client takes ownership of buf->base */
    udp_send_to_client(cnx, buf->base, (int)nread);
}

/* UDP server receive callback */
static void udp_server_recv_cb(uv_udp_t *handle, ssize_t nread,
                               const uv_buf_t *buf,
                               const struct sockaddr *addr,
                               unsigned flags)
{
    (void)flags;

    if (nread < 0) {
        logError("UDP server recv error: %s\n", uv_strerror((int)nread));
        if (buf->base) free(buf->base);
        return;
    }

    if (nread == 0 || addr == NULL) {
        if (buf->base) free(buf->base);
        return;
    }

    ServerInfo *srv = (ServerInfo*)handle->data;
    uv_os_fd_t server_fd;
    uv_fileno((uv_handle_t*)handle, &server_fd);

    /* Convert to sockaddr_storage for hashing */
    struct sockaddr_storage addr_storage;
    memcpy(&addr_storage, addr,
           addr->sa_family == AF_INET ? sizeof(struct sockaddr_in) :
                                         sizeof(struct sockaddr_in6));

    /* O(1) hash lookup instead of O(n) list scan */
    ConnectionInfo *cnx = lookup_udp_connection(srv, &addr_storage);

    if (cnx) {
        /* Existing connection - mark as recently used */
        lru_touch(srv, cnx);

        /* Refresh timeout */
        cnx->remoteTimeout = time(NULL) + srv->serverTimeout;
        uv_timer_again(&cnx->timeout_timer);

        /* Update statistics */
        cnx->remote.totalBytesIn += nread;

        /* Send immediately to backend - udp_send_to_backend takes ownership of buf->base */
        udp_send_to_backend(cnx, buf->base, (int)nread);
        return;
    }

    /* New connection - check if we've reached the limit */
    if (srv->udp_connection_count >= RINETD_MAX_UDP_CONNECTIONS) {
        /* Close oldest connection to make room */
        close_oldest_udp_connection((ServerInfo*)srv);
    }

    cnx = allocateConnection();
    if (!cnx) {
        free(buf->base);
        return;
    }

    /* Setup UDP-specific connection state (allocateConnection already initialized most fields) */
    cnx->remote.fd = server_fd;
    cnx->remote.family = srv->fromAddrInfo->ai_family;
    cnx->remote.protocol = IPPROTO_UDP;
    cnx->remoteAddress = *(struct sockaddr_storage*)addr;
    cnx->remoteTimeout = time(NULL) + srv->serverTimeout;
    cnx->server = srv;
    cacheServerInfoForLogging(cnx, srv);

    /* Remote handle shared with server (don't initialize separate handle) */
    cnx->remote_handle_initialized = 0;

    /* Initialize timeout timer */
    uv_timer_init(main_loop, &cnx->timeout_timer);
    cnx->timeout_timer.data = cnx;
    int ret = uv_timer_start(&cnx->timeout_timer, udp_timeout_cb,
                             srv->serverTimeout * 1000, 0);
    if (ret != 0) {
        logError("uv_timer_start error: %s\n", uv_strerror(ret));
        free(buf->base);
        return;
    }
    cnx->timer_initialized = 1;

    /* Check access rules */
    int logCode = checkConnectionAllowed(cnx);
    if (logCode != logAllowed) {
        uv_timer_stop(&cnx->timeout_timer);
        cnx->timer_closing = 1;  /* Set BEFORE uv_close() */
        uv_close((uv_handle_t*)&cnx->timeout_timer, handle_close_cb);
        cnx->timer_initialized = 0;
        logEvent(cnx, srv, logCode);
        free(buf->base);
        return;
    }

    /* Create local UDP socket for backend */
    uv_udp_init(main_loop, &cnx->local_uv_handle.udp);
    cnx->local_handle_type = UV_UDP;
    cnx->local_handle_initialized = 1;
    cnx->local_uv_handle.udp.data = cnx;

    cnx->local.family = srv->toAddrInfo->ai_family;
    cnx->local.protocol = IPPROTO_UDP;
    cnx->local.totalBytesIn = cnx->local.totalBytesOut = 0;

    /* Bind to source if specified */
    if (srv->sourceAddrInfo) {
        ret = uv_udp_bind(&cnx->local_uv_handle.udp,
                          srv->sourceAddrInfo->ai_addr, 0);
        if (ret != 0) {
            logError("UDP bind (source) error: %s\n", uv_strerror(ret));
            /* Continue anyway */
        }
    }

    /* Extract fd */
    uv_os_fd_t local_fd;
    uv_fileno((uv_handle_t*)&cnx->local_uv_handle.udp, &local_fd);
    cnx->local.fd = local_fd;

    /* Start receiving on local socket */
    ret = uv_udp_recv_start(&cnx->local_uv_handle.udp,
                            alloc_buffer_udp_server_cb, udp_local_recv_cb);
    if (ret != 0) {
        logError("uv_udp_recv_start (local) error: %s\n", uv_strerror(ret));
        handleClose(cnx, &cnx->local, &cnx->remote);
        free(buf->base);
        return;
    }

    /* Update statistics for initial data */
    cnx->remote.totalBytesIn += nread;

    /* Send initial data to backend - udp_send_to_backend takes ownership of buf->base */
    udp_send_to_backend(cnx, buf->base, (int)nread);

    logEvent(cnx, srv, logOpened);

    /* Add to both hash table and LRU list */
    hash_insert_udp_connection(cnx);
    lru_insert_head(srv, cnx);

    /* Increment UDP connection count for this forwarding rule */
    ((ServerInfo*)srv)->udp_connection_count++;
}

static void handleClose(ConnectionInfo *cnx, Socket *socket, Socket *other_socket)
{
    /* If not already closing, log the event with final byte counts.
       Note: handleClose() may be called twice (once for each socket) - this is normal.
       We only log on the first call. */
    if (!cnx->coClosing) {
        cnx->coLog = (socket == &cnx->local) ?
            logLocalClosedFirst : logRemoteClosedFirst;
        logEvent(cnx, cnx->server, cnx->coLog);
        cnx->coClosing = 1;

        /* Cleanup UDP connection: remove from hash table and LRU list */
        if (cnx->remote.protocol == IPPROTO_UDP && cnx->server) {
            /* Remove from hash table */
            hash_remove_udp_connection(cnx);

            /* Remove from LRU list */
            ServerInfo *srv = (ServerInfo*)cnx->server;
            lru_remove(srv, cnx);

            /* Decrement counter */
            if (srv->udp_connection_count > 0) {
                srv->udp_connection_count--;
            }
        }
    }

    /* Close the socket's libuv handle */
    if (socket->fd != INVALID_SOCKET) {
        uv_handle_t *handle = NULL;
        int *closing_flag = NULL;

        if (socket == &cnx->local && cnx->local_handle_initialized) {
            if (cnx->local_handle_type == UV_TCP) {
                handle = (uv_handle_t*)&cnx->local_uv_handle.tcp;
            } else if (cnx->local_handle_type == UV_NAMED_PIPE) {
                handle = (uv_handle_t*)&cnx->local_uv_handle.pipe;
            } else {
                handle = (uv_handle_t*)&cnx->local_uv_handle.udp;
            }
            closing_flag = &cnx->local_handle_closing;
        } else if (socket == &cnx->remote && cnx->remote_handle_initialized) {
            if (cnx->remote_handle_type == UV_TCP) {
                handle = (uv_handle_t*)&cnx->remote_uv_handle.tcp;
            } else if (cnx->remote_handle_type == UV_NAMED_PIPE) {
                handle = (uv_handle_t*)&cnx->remote_uv_handle.pipe;
            } else {
                handle = (uv_handle_t*)&cnx->remote_uv_handle.udp;
            }
            closing_flag = &cnx->remote_handle_closing;
        }

        if (handle && closing_flag && !(*closing_flag) && !uv_is_closing(handle)) {
            /* Stop reading/recv before closing (libuv best practice) */
            if (socket->protocol == IPPROTO_TCP || socket->family == AF_UNIX) {
                uv_read_stop((uv_stream_t*)handle);
            } else if (socket->protocol == IPPROTO_UDP) {
                uv_udp_recv_stop((uv_udp_t*)handle);
            }
            *closing_flag = 1;  /* Set BEFORE calling uv_close() */
            uv_close(handle, handle_close_cb);
        }

        socket->fd = INVALID_SOCKET;
    }

    /* Close timer if active */
    if (cnx->timer_initialized && !cnx->timer_closing && !uv_is_closing((uv_handle_t*)&cnx->timeout_timer)) {
        cnx->timer_closing = 1;  /* Set BEFORE calling uv_close() */
        uv_close((uv_handle_t*)&cnx->timeout_timer, handle_close_cb);
    }

    /* Close the other socket as well - no need to wait for buffers to drain */
    /* uv_close() will wait for pending I/O operations to complete */
    if (other_socket->fd != INVALID_SOCKET) {
        uv_handle_t *other_handle = NULL;
        int *other_closing_flag = NULL;

        if (other_socket == &cnx->local && cnx->local_handle_initialized) {
            if (cnx->local_handle_type == UV_TCP) {
                other_handle = (uv_handle_t*)&cnx->local_uv_handle.tcp;
            } else if (cnx->local_handle_type == UV_NAMED_PIPE) {
                other_handle = (uv_handle_t*)&cnx->local_uv_handle.pipe;
            } else {
                other_handle = (uv_handle_t*)&cnx->local_uv_handle.udp;
            }
            other_closing_flag = &cnx->local_handle_closing;
        } else if (other_socket == &cnx->remote && cnx->remote_handle_initialized) {
            if (cnx->remote_handle_type == UV_TCP) {
                other_handle = (uv_handle_t*)&cnx->remote_uv_handle.tcp;
            } else if (cnx->remote_handle_type == UV_NAMED_PIPE) {
                other_handle = (uv_handle_t*)&cnx->remote_uv_handle.pipe;
            } else {
                other_handle = (uv_handle_t*)&cnx->remote_uv_handle.udp;
            }
            other_closing_flag = &cnx->remote_handle_closing;
        }

        if (other_handle && other_closing_flag && !(*other_closing_flag) && !uv_is_closing(other_handle)) {
            /* Stop reading/recv before closing (libuv best practice) */
            if (other_socket->protocol == IPPROTO_TCP || other_socket->family == AF_UNIX) {
                uv_read_stop((uv_stream_t*)other_handle);
            } else if (other_socket->protocol == IPPROTO_UDP) {
                uv_udp_recv_stop((uv_udp_t*)other_handle);
            }
            *other_closing_flag = 1;  /* Set BEFORE calling uv_close() */
            uv_close(other_handle, handle_close_cb);
            other_socket->fd = INVALID_SOCKET;
        }
    }
}

static int checkConnectionAllowed(ConnectionInfo const *cnx)
{
    ServerInfo const *srv = cnx->server;

    char addressText[NI_MAXHOST];
    getnameinfo((struct sockaddr *)&cnx->remoteAddress, sizeof(cnx->remoteAddress),
        addressText, sizeof(addressText), NULL, 0, NI_NUMERICHOST);

    /* 1. Check global allow rules. If there are no
        global allow rules, it's presumed OK at
        this step. If there are any, and it doesn't
        match at least one, kick it out. */
    int good = 1;
    for (int j = 0; j < globalRulesCount; ++j) {
        if (allRules[j].type == allowRule) {
            good = 0;
            if (match(addressText, allRules[j].pattern)) {
                good = 1;
                break;
            }
        }
    }
    if (!good) {
        return logNotAllowed;
    }
    /* 2. Check global deny rules. If it matches
        any of the global deny rules, kick it out. */
    for (int j = 0; j < globalRulesCount; ++j) {
        if (allRules[j].type == denyRule
            && match(addressText, allRules[j].pattern)) {
            return logDenied;
        }
    }
    /* 3. Check allow rules specific to this forwarding rule.
        If there are none, it's OK. If there are any,
        it must match at least one. */
    good = 1;
    for (int j = 0; j < srv->rulesCount; ++j) {
        if (allRules[srv->rulesStart + j].type == allowRule) {
            good = 0;
            if (match(addressText,
                allRules[srv->rulesStart + j].pattern)) {
                good = 1;
                break;
            }
        }
    }
    if (!good) {
        return logNotAllowed;
    }
    /* 4. Check deny rules specific to this forwarding rule. If
        it matches any of the deny rules, kick it out. */
    for (int j = 0; j < srv->rulesCount; ++j) {
        if (allRules[srv->rulesStart + j].type == denyRule
            && match(addressText, allRules[srv->rulesStart + j].pattern)) {
            return logDenied;
        }
    }

    return logAllowed;
}

#if !_WIN32
RETSIGTYPE hup(int s)
{
    (void)s;

    /* Ignore if reload is already in progress */
    if (config_reload_pending) {
        return;
    }

    logInfo("received SIGHUP, reloading configuration...\n");
    /* Set flag - readConfiguration() will be called after all handles close */
    config_reload_pending = 1;
    /* Clear old configuration - this starts async close of server handles */
    clearConfiguration();
}
#endif /* _WIN32 */

RETSIGTYPE quit(int s)
{
    (void)s;

    /* Obey the request, but first flush the log */
    if (logFd != -1) {
        uv_fs_t req;
        uv_fs_close(NULL, &req, logFd, NULL);
        uv_fs_req_cleanup(&req);
        logFd = -1;
    }

    logInfo("forced quit\n");

    /* Clear configuration (connections will be freed when process exits) */
    clearConfiguration();
    exit(0);
}

void registerPID(char const *pid_file_name)
{
#if !_WIN32
    FILE *pid_file = fopen(pid_file_name, "w");
    if (pid_file == NULL) {
        /* non-fatal, non-Linux may lack /var/run... */
        goto error;
    } else {
        fprintf(pid_file, "%d\n", getpid());
        /* errors aren't fatal */
        if (fclose(pid_file))
            goto error;
    }
    return;
error:
    logError("couldn't write to %s. PID was not logged (%m).\n", pid_file_name);
#else
    /* add other systems with wherever they register processes */
    (void)pid_file_name;
#endif
}

static void logEvent(ConnectionInfo const *cnx, ServerInfo const *srv, int result)
{
    /* Bit of borrowing from Apache logging module here,
        thanks folks */
    int timz;
    char tstr[1024];
    char addressText[NI_MAXHOST] = { '?' };
    struct tm *t = get_gmtoff(&timz);
    char sign = (timz < 0 ? '-' : '+');
    if (timz < 0) {
        timz = -timz;
    }
    strftime(tstr, sizeof(tstr), "%Y-%m-%dT%H:%M:%S", t);

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
                           "%s - - "
                           "[%s %c%.2d%.2d] "
                           "\"GET /rinetd-services/%s/%d/%s/%d/%s HTTP/1.0\" "
                           "200 %llu - - - %llu\n",
                           addressText, tstr, sign, timz / 60, timz % 60, fromHost,
                           (int)fromPort, toHost, (int)toPort, logMessages[result],
                           (unsigned long long int)bytesOut,
                           (unsigned long long int)bytesIn);
        } else {
            /* Write an rinetd-specific log entry with a
                less goofy format. */
            len = snprintf(log_buffer, RINETD_LOG_BUFFER_SIZE,
                           "%s%c%02d:%02d\t%s\t%s\t%d\t%s\t%d\t%llu"
                           "\t%llu\t%s\n",
                           tstr, sign, timz / 60, timz % 60,
                           addressText, fromHost, (int)fromPort, toHost,
                           (int)toPort, (unsigned long long int)bytesIn,
                           (unsigned long long int)bytesOut, logMessages[result]);
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

static void log_write_cb(uv_fs_t *req) {
    if (req->result < 0) {
        logError("Async log write failed: %s\n", uv_strerror((int)req->result));
    }

    /* Free the buffer stored in req->data */
    if (req->data) {
        free(req->data);
    }

    uv_fs_req_cleanup(req);
    free(req);
}

static int readArgs (int argc, char **argv, RinetdOptions *options)
{
    for (;;) {
        int option_index = 0;
        static struct option long_options[] = {
            {"conf-file",  1, 0, 'c'},
            {"debug",      0, 0, 'd'},
            {"foreground", 0, 0, 'f'},
            {"help",       0, 0, 'h'},
            {"version",    0, 0, 'v'},
            {0, 0, 0, 0}
        };

        int c = getopt_long(argc, argv, "c:dfhv", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'c':
                options->conf_file = optarg;
                if (!options->conf_file) {
                    logError("configuration filename not accepted\n");
                    exit(1);
                }
                break;
            case 'd':
                options->debug = 1;
                break;
            case 'f':
                options->foreground = 1;
                break;
            case 'h':
                printf("Usage: rinetd-uv [OPTION]\n"
                    "  -c, --conf-file FILE   read configuration "
                    "from FILE\n"
                    "  -d, --debug            enable debug logging\n"
                    "  -f, --foreground       do not run in the "
                    "background\n"
                    "  -h, --help             display this help\n"
                    "  -v, --version          display version "
                    "number\n\n");
                printf("Most options are controlled through the\n"
                    "configuration file. See the rinetd-uv(8)\n"
                    "manpage for more information.\n");
                exit(0);
            case 'v':
                printf ("rinetd-uv %s\n", PACKAGE_VERSION);
                exit(0);
            case '?':
            default:
                exit(1);
        }
    }
    return 0;
}

/* get_gmtoff was borrowed from Apache. Thanks folks. */
static struct tm *get_gmtoff(int *tz)
{
    time_t tt = time(NULL);

    /* Assume we are never more than 24 hours away. */
    struct tm gmt = *gmtime(&tt); /* remember gmtime/localtime return ptr to static */
    struct tm *t = localtime(&tt); /* buffer... so be careful */
    int days = t->tm_yday - gmt.tm_yday;
    int hours = ((days < -1 ? 24 : 1 < days ? -24 : days * 24)
        + t->tm_hour - gmt.tm_hour);
    int minutes = hours * 60 + t->tm_min - gmt.tm_min;
    *tz = minutes;
    return t;
}
