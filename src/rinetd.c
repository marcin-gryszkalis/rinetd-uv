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
#include "log.h"
#include "parse.h"
#include "buffer_pool.h"
#include "loadbalancer.h"
#include "affinity.h"
#include "yaml_config.h"
#include "stats.h"

Rule *allRules = NULL;
int allRulesCount = 0;
int globalRulesCount = 0;

ServerInfo *seInfo = NULL;
int seTotal = 0;

/* YAML configuration state */
RuleInfo *yamlRules = NULL;
int yamlRulesCount = 0;
int usingYamlConfig = 0;

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

char *pidFileName = NULL;
int bufferSize = RINETD_DEFAULT_BUFFER_SIZE;
int globalDnsRefreshPeriod = RINETD_DEFAULT_DNS_REFRESH_PERIOD;
int globalDnsMultiIpExpand = 0;  /* Default: disabled (legacy .conf files) */
int globalDnsMultiIpProto = 4;   /* Default: IPv4 only */
int poolMinFree = RINETD_DEFAULT_POOL_MIN_FREE;
int poolMaxFree = RINETD_DEFAULT_POOL_MAX_FREE;
int poolTrimDelay = RINETD_DEFAULT_POOL_TRIM_DELAY;
int listenBacklog = RINETD_DEFAULT_LISTEN_BACKLOG;
int maxUdpConnections = RINETD_DEFAULT_MAX_UDP_CONNECTIONS;
int globalConnectTimeout = RINETD_DEFAULT_CONNECT_TIMEOUT;

static RinetdOptions options = {
    .conf_file = NULL,  /* Will be determined by findConfigFile() if not specified with -c */
    .foreground = 0,
    .debug = 0,
};

static int conf_file_explicit = 0;  /* Set to 1 if -c was used */

static int forked = 0;
static int config_reload_pending = 0;

static void handleClose(ConnectionInfo *cnx, Socket *socket, Socket *other_socket);
static ConnectionInfo *allocateConnection(void);
static void freeUnhandledConnection(ConnectionInfo *cnx);
static void cacheServerInfoForLogging(ConnectionInfo *cnx, ServerInfo const *srv);
static int checkConnectionAllowedAddr(struct sockaddr_storage const *addr, ServerInfo const *srv);
static int checkConnectionAllowed(ConnectionInfo const *cnx);

/* UDP hash table and LRU functions */
static void init_udp_hash_table(void);
static void cleanup_udp_hash_table(void);
static void hash_remove_udp_connection(ConnectionInfo *cnx);
static void lru_remove(ServerInfo *srv, ConnectionInfo *cnx);
static void cleanup_yaml_rules(void);

static int readArgs(int argc, char **argv, RinetdOptions *options);
static char const *findConfigFile(void);
static void clearConfiguration(void);
static void readConfiguration(char const *file);

static void registerPID(char const *pid_file_name);

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


int main(int argc, char *argv[])
{
    log_init();
    stats_init();

#ifdef _WIN32
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(1, 1), &wsaData);
    if (result != 0) {
        logError("Your computer was not connected to the Internet at the time that this program was launched, or you do not have a 32-bit connection to the Internet.\n");
        exit(1);
    }
#endif

    readArgs(argc, argv, &options);
    log_set_debug(options.debug);

    /* If -c not specified, find config file in order: .yaml, .yml, .conf */
    if (!conf_file_explicit) {
        options.conf_file = findConfigFile();
    }

    if (!options.foreground) {
#if HAVE_DAEMON
        if (daemon(0, 0) != 0) {
            exit(0);
        }
        forked = 1;
        log_set_forked(1);
#elif HAVE_FORK
        if (fork() != 0)
            exit(0);
        forked = 1;
        log_set_forked(1);
#endif
    }

    readConfiguration(options.conf_file);

    /* If using YAML config, initialize from rules */
    if (usingYamlConfig)
        initializeFromYamlRules();

    if (pidFileName || !options.foreground)
        registerPID(pidFileName ? pidFileName : RINETD_PID_FILE);

    /* Initialize libuv event loop */
    main_loop = uv_default_loop();
    if (!main_loop) {
        logError("failed to initialize libuv event loop\n");
        exit(1);
    }

    /* Set up signal handlers using libuv */
    int ret;
#ifndef _WIN32
    /* SIGPIPE - ignore (start with no-op callback) */
    ret = uv_signal_init(main_loop, &sigpipe_handle);
    if (ret != 0) {
        logError("uv_signal_init (SIGPIPE) failed: %s\n", uv_strerror(ret));
        exit(1);
    }
    ret = uv_signal_start(&sigpipe_handle, signal_cb, SIGPIPE);
    if (ret != 0) {
        logError("uv_signal_start (SIGPIPE) failed: %s\n", uv_strerror(ret));
        exit(1);
    }

    /* SIGHUP - reload configuration */
    ret = uv_signal_init(main_loop, &sighup_handle);
    if (ret != 0) {
        logError("uv_signal_init (SIGHUP) failed: %s\n", uv_strerror(ret));
        exit(1);
    }
    ret = uv_signal_start(&sighup_handle, signal_cb, SIGHUP);
    if (ret != 0) {
        logError("uv_signal_start (SIGHUP) failed: %s\n", uv_strerror(ret));
        exit(1);
    }
#endif

    /* SIGINT and SIGTERM - graceful shutdown */
    ret = uv_signal_init(main_loop, &sigint_handle);
    if (ret != 0) {
        logError("uv_signal_init (SIGINT) failed: %s\n", uv_strerror(ret));
        exit(1);
    }
    ret = uv_signal_start(&sigint_handle, signal_cb, SIGINT);
    if (ret != 0) {
        logError("uv_signal_start (SIGINT) failed: %s\n", uv_strerror(ret));
        exit(1);
    }

    ret = uv_signal_init(main_loop, &sigterm_handle);
    if (ret != 0) {
        logError("uv_signal_init (SIGTERM) failed: %s\n", uv_strerror(ret));
        exit(1);
    }
    ret = uv_signal_start(&sigterm_handle, signal_cb, SIGTERM);
    if (ret != 0) {
        logError("uv_signal_start (SIGTERM) failed: %s\n", uv_strerror(ret));
        exit(1);
    }

    /* Initialize UDP hash table for O(1) connection lookup */
    init_udp_hash_table();

    /* Initialize buffer pool */
    buffer_pool_init(bufferSize, poolMinFree, poolMaxFree, poolTrimDelay);
    buffer_pool_warm();

    /* Start status reporting timers */
    stats_start_timers();

    /* Start libuv event handling for all servers */
    for (int i = 0; i < seTotal; ++i)
        startServerListening(&seInfo[i]);

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

    /* Perform graceful cleanup (called outside signal callback context) */
    quit(0);

    return 0;
}

static void cleanup_yaml_rules(void)
{
    if (!usingYamlConfig || !yamlRules)
        return;

    for (int i = 0; i < yamlRulesCount; i++) {
        RuleInfo *rule = &yamlRules[i];

        /* Free listeners array (the ServerInfo structs themselves are in seInfo,
         * which is freed separately) */
        free(rule->listeners);

        /* Free backends */
        for (int j = 0; j < rule->backend_count; j++)
            lb_backend_cleanup(&rule->backends[j]);
        free(rule->backends);

        /* Free affinity table */
        if (rule->affinity_table)
            affinity_table_free(rule->affinity_table);

        free(rule->name);
    }
    free(yamlRules);
    yamlRules = NULL;
    yamlRulesCount = 0;
}

static void clearConfiguration(void)
{
    /* Remove server references from all active connections */
    for (ConnectionInfo *cnx = connectionListHead; cnx; cnx = cnx->next)
        cnx->server = NULL;
    /* Close existing server libuv handles and sockets. */
    int any_handles_to_close = 0;
    for (int i = 0; i < seTotal; ++i) {
        ServerInfo *srv = &seInfo[i];

        /* Close DNS refresh timer if initialized */
        if (srv->dns_timer_initialized && !srv->dns_timer_closing) {
            uv_timer_stop(&srv->dns_refresh_timer);
            srv->dns_timer_closing = 1;
            uv_close((uv_handle_t*)&srv->dns_refresh_timer, dns_timer_close_cb);
            any_handles_to_close = 1;
        }

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
            /* Update buffer pool config (stale buffers handled on return) */
            buffer_pool_update_config(bufferSize, poolMinFree, poolMaxFree, poolTrimDelay);
            /* Start new servers listening */
            for (int i = 0; i < seTotal; ++i)
                startServerListening(&seInfo[i]);
            /* Update stats and restart timers */
            stats_on_config_reload();
            stats_restart_timers_if_needed();
            logInfo("configuration reloaded, %d server(s) listening\n", seTotal);
        }
    }
    /* Otherwise, seInfo will be freed in server_handle_close_cb after all handles close */
    /* Forget existing rules. */
    for (int i = 0; i < allRulesCount; ++i)
        free(allRules[i].pattern);
    /* Free memory associated with previous set. */
    free(allRules);
    allRules = NULL;
    allRulesCount = globalRulesCount = 0;

    /* Cleanup YAML rules if using YAML config */
    cleanup_yaml_rules();

    /* Free file names */
    free(logFileName);
    logFileName = NULL;
    free(pidFileName);
    pidFileName = NULL;
}

static void readConfiguration(char const *file)
{
    logInfo("loading configuration from: %s\n", file);

    /* Reset configurable values to defaults before re-parsing (for SIGHUP) */
    bufferSize = RINETD_DEFAULT_BUFFER_SIZE;
    globalDnsRefreshPeriod = RINETD_DEFAULT_DNS_REFRESH_PERIOD;
    poolMinFree = RINETD_DEFAULT_POOL_MIN_FREE;
    poolMaxFree = RINETD_DEFAULT_POOL_MAX_FREE;
    poolTrimDelay = RINETD_DEFAULT_POOL_TRIM_DELAY;
    listenBacklog = RINETD_DEFAULT_LISTEN_BACKLOG;
    maxUdpConnections = RINETD_DEFAULT_MAX_UDP_CONNECTIONS;

    /* Check if this is a YAML config file */
    if (yaml_config_is_yaml_file(file)) {
        YamlConfig *config = yaml_config_parse(file);
        if (!config) {
            logError("Failed to parse YAML configuration: %s\n", file);
            exit(1);
        }

        /* Apply global settings */
        yaml_config_apply_globals(config);

        /* Store rules for later initialization */
        yamlRules = config->rules;
        yamlRulesCount = config->rule_count;
        usingYamlConfig = 1;

        /* Transfer ownership - don't free rules, just the config wrapper */
        config->rules = NULL;
        config->rule_count = 0;
        yaml_config_free(config);
    } else {
        /* Parse legacy configuration file */
        usingYamlConfig = 0;
        parseConfiguration(file);
    }

    /* Open the log file */
    if (logFd != -1) {
        uv_fs_t req;
        int ret = uv_fs_close(NULL, &req, logFd, NULL);
        uv_fs_req_cleanup(&req);
        if (ret < 0) {
            logWarning("uv_fs_close failed: %s\n", uv_strerror(ret));
        }
        logFd = -1;
    }
    if (logFileName) {
        uv_fs_t req;
        logFd = uv_fs_open(NULL, &req, logFileName, O_WRONLY | O_CREAT | O_APPEND, 0644, NULL);
        uv_fs_req_cleanup(&req);
        if (logFd < 0) {
            logError("could not open %s to append: %s\n", logFileName, uv_strerror((int)logFd));
            logFd = -1;
        }
    }
}

void addServer(char *bindAddress, char *bindPort, int bindProtocol,
               char *connectAddress, char *connectPort, int connectProtocol,
               int serverTimeout, char *sourceAddress,
               int keepalive, int dns_refresh_period, int socketMode,
               int connectTimeout)
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
        .connectTimeout = connectTimeout,
    };

    int fromIsUnix = isUnixSocketPath(bindAddress);
    int toIsUnix = isUnixSocketPath(connectAddress);

    /* Handle Unix domain socket bind address */
    if (fromIsUnix) {
        char *path = NULL;
        int is_abstract = 0;

        if (parseUnixSocketPath(bindAddress, &path, &is_abstract) != 0)
            exit(1);
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
        if (ret != 0)
            exit(1);
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
    if (connectionListHead)
        connectionListHead->prev = cnx;
    connectionListHead = cnx;

    activeConnections++;

    return cnx;
}

/* Remove connection from linked list and free it.
 * Only for connections with NO initialized uv handles -- those must go through
 * handle_close_cb instead (which waits for pending I/O to complete). */
static void freeUnhandledConnection(ConnectionInfo *cnx)
{
    if (cnx->prev)
        cnx->prev->next = cnx->next;
    else
        connectionListHead = cnx->next;
    if (cnx->next)
        cnx->next->prev = cnx->prev;
    activeConnections--;
    free(cnx->log_fromHost);
    free(cnx->log_toHost);
    free(cnx);
}

/* Cache server info for logging - survives server reload/removal */
static void cacheServerInfoForLogging(ConnectionInfo *cnx, ServerInfo const *srv)
{
    if (!cnx || !srv)
        return;

    cnx->log_fromHost = strdup(srv->fromHost);
    cnx->log_fromPort = srv->fromAddrInfo ? getPort(srv->fromAddrInfo) : 0;
    cnx->log_toHost = strdup(srv->toHost);
    cnx->log_toPort = srv->toAddrInfo ? getPort(srv->toAddrInfo) : 0;
}

/* libuv callback forward declarations */
static void tcp_server_accept_cb(uv_stream_t *server, int status);
static void unix_server_accept_cb(uv_stream_t *server, int status);
static void unix_connect_cb(uv_connect_t *req, int status);
static void connect_timeout_cb(uv_timer_t *timer);

static void udp_server_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags);
static void alloc_buffer_udp_server_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void alloc_buffer_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);

static void set_socket_buffer_sizes(uv_handle_t *handle)
{
    /*
     * Linux kernel doubles the requested buffer size and returns the doubled value.
     * Other platforms (FreeBSD, macOS) set exactly what's requested.
     * To get consistent behavior, request 2x on non-Linux platforms.
     * see: man socket(7)
     */
#ifdef __linux__
    int requested = bufferSize;
#else
    int requested = bufferSize * 2;
#endif

    int send_size = requested;
    int ret = uv_send_buffer_size(handle, &send_size);
    if (ret != 0)
        logError("uv_send_buffer_size failed: %s\n", uv_strerror(ret));
    else if (send_size < bufferSize)
        logError("send buffer size %d less than requested %d\n", send_size, bufferSize);

    int recv_size = requested;
    ret = uv_recv_buffer_size(handle, &recv_size);
    if (ret != 0)
        logError("uv_recv_buffer_size failed: %s\n", uv_strerror(ret));
    else if (recv_size < bufferSize)
        logError("recv buffer size %d less than requested %d\n", recv_size, bufferSize);
}

/* libuv signal handler callback */
static void signal_cb(uv_signal_t *handle, int signum)
{
    (void)handle;  /* Unused parameter */
    if (signum == SIGHUP) {
        hup(signum);
    } else if (signum == SIGINT || signum == SIGTERM) {
        logInfo("received %s signal - initiating graceful shutdown\n", signum == SIGINT ? "INT" : "TERM");
        should_exit = 1;
        uv_stop(main_loop);  /* Interrupt current UV_RUN_DEFAULT iteration */
    } else if (signum == SIGPIPE) {
        /* SIGPIPE is ignored (no-op callback) */
        /* This prevents the process from terminating on broken pipes */
        logInfo("received SIGPIPE signal - ignored\n");
    }
}

/* DNS refresh timer callback */
static void dns_refresh_timer_cb(uv_timer_t *timer)
{
    ServerInfo *srv = (ServerInfo *)timer->data;
    logDebug("Periodic DNS refresh for %s:%d -> %s (interval: %ds)\n", srv->fromHost, getPort(srv->fromAddrInfo), srv->toHost, srv->dns_refresh_period);
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
    if (srv->handle_initialized)
        return;  /* Already initialized */

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
            uv_fs_t req;
            uv_fs_unlink(NULL, &req, srv->fromUnixPath, NULL);
            uv_fs_req_cleanup(&req);
        }

        /* Bind to Unix socket path */
        /* Set umask before bind to avoid race condition with chmod */
        mode_t old_umask = 0;
        if (srv->socketMode != 0)
            old_umask = umask(~srv->socketMode & 0777);

        if (srv->fromIsAbstract) {
            char abstract_name[UNIX_PATH_MAX + 2];
            size_t name_len = prepareAbstractSocketName(srv->fromUnixPath, abstract_name);
            if (name_len == 0) {
                if (srv->socketMode != 0) umask(old_umask);
                exit(1);
            }
            ret = uv_pipe_bind2(&srv->uv_handle.pipe, abstract_name, name_len, UV_PIPE_NO_TRUNCATE);
        } else {
            ret = uv_pipe_bind(&srv->uv_handle.pipe, srv->fromUnixPath);
        }

        /* Restore umask immediately after bind */
        if (srv->socketMode != 0)
            umask(old_umask);

        if (ret != 0) {
            logError("uv_pipe_bind() failed for %s: %s\n", srv->fromHost, uv_strerror(ret));
            exit(1);
        }

        set_socket_buffer_sizes((uv_handle_t *)&srv->uv_handle.pipe);

        /* Start listening for connections */
        ret = uv_listen((uv_stream_t*)&srv->uv_handle.pipe, listenBacklog, unix_server_accept_cb);
        if (ret != 0) {
            logError("uv_listen() failed for Unix socket: %s\n", uv_strerror(ret));
            exit(1);
        }

        /* Get the actual fd for logging/cleanup */
        uv_os_fd_t fd = INVALID_SOCKET;
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
            logError("uv_tcp_bind() failed for %s:%d: %s\n", srv->fromHost, getPort(srv->fromAddrInfo), uv_strerror(ret));
            exit(1);
        }

        set_socket_buffer_sizes((uv_handle_t *)&srv->uv_handle.tcp);

        /* Start listening for connections */
        ret = uv_listen((uv_stream_t*)&srv->uv_handle.tcp, listenBacklog, tcp_server_accept_cb);
        if (ret != 0) {
            logError("uv_listen() failed: %s\n", uv_strerror(ret));
            exit(1);
        }

        /* Get the actual fd for logging/cleanup */
        uv_os_fd_t fd = INVALID_SOCKET;
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
            logError("uv_udp_bind() failed for %s:%d: %s\n", srv->fromHost, getPort(srv->fromAddrInfo), uv_strerror(ret));
            exit(1);
        }

        set_socket_buffer_sizes((uv_handle_t *)&srv->uv_handle.udp);

        /* Start receiving datagrams */
        ret = uv_udp_recv_start(&srv->uv_handle.udp, alloc_buffer_udp_server_cb, udp_server_recv_cb);
        if (ret != 0) {
            logError("uv_udp_recv_start() failed: %s\n", uv_strerror(ret));
            exit(1);
        }

        /* Get the actual fd for logging/cleanup */
        uv_os_fd_t fd = INVALID_SOCKET;
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
            ret = uv_timer_start(&srv->dns_refresh_timer, dns_refresh_timer_cb, srv->dns_refresh_period * 1000, srv->dns_refresh_period * 1000);
            if (ret != 0) {
                logError("uv_timer_start() failed for DNS refresh: %s\n", uv_strerror(ret));
                uv_close((uv_handle_t*)&srv->dns_refresh_timer, NULL);
                srv->dns_timer_initialized = 0;
            } else {
                logDebug("DNS refresh enabled for %s -> %s (interval: %ds)\n", srv->fromHost, srv->toHost, srv->dns_refresh_period);
            }
        } else {
            logError("uv_timer_init() failed for DNS refresh: %s\n", uv_strerror(ret));
        }
    }
}

/* Check if all server handles and DNS timers are closed - if so, free seInfo and reload */
static void check_all_servers_closed(void)
{
    if (!seInfo)
        return;  /* Already freed */

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
            /* Update buffer pool config (stale buffers handled on return) */
            buffer_pool_update_config(bufferSize, poolMinFree, poolMaxFree, poolTrimDelay);
            /* Start new servers listening */
            for (int i = 0; i < seTotal; ++i)
                startServerListening(&seInfo[i]);
            /* Update stats and restart timers */
            stats_on_config_reload();
            stats_restart_timers_if_needed();
            logInfo("configuration reloaded, %d server(s) listening\n", seTotal);
        }
    }
}

/* DNS timer close callback - called when DNS timer is fully closed */
static void dns_timer_close_cb(uv_handle_t *handle)
{
    if (!handle || !handle->data)
        return;

    ServerInfo *srv = (ServerInfo*)handle->data;
    srv->dns_timer_initialized = 0;
    srv->dns_timer_closing = 0;

    /* Check if we can now free seInfo */
    check_all_servers_closed();
}

/* Server handle close callback - frees server resources */
static void server_handle_close_cb(uv_handle_t *handle)
{
    if (!handle || !handle->data)
        return;

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
        uv_fs_t req;
        uv_fs_unlink(NULL, &req, srv->fromUnixPath, NULL);
        uv_fs_req_cleanup(&req);
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

/* Backend connect timeout callback - fires when TCP connect takes too long */
static void connect_timeout_cb(uv_timer_t *timer)
{
    ConnectionInfo *cnx = (ConnectionInfo*)timer->data;
    logErrorConn(cnx, "backend connect timeout\n");
    stats_error_connect();
    logEvent(cnx, cnx->server, logLocalConnectFailed);

    if (cnx->selected_backend && cnx->rule) {
        lb_backend_mark_failure(cnx->selected_backend, cnx->rule);
        lb_backend_connection_end(cnx->selected_backend, 0, 0);
    }

    /* Close connect timer */
    cnx->connect_timer_closing = 1;
    uv_close((uv_handle_t*)&cnx->connect_timer, handle_close_cb);

    /* Close local (backend) handle */
    if (cnx->local_handle_initialized && !cnx->local_handle_closing) {
        cnx->local_handle_closing = 1;
        if (cnx->local_handle_type == UV_TCP)
            uv_close((uv_handle_t*)&cnx->local_uv_handle.tcp, handle_close_cb);
        else if (cnx->local_handle_type == UV_NAMED_PIPE)
            uv_close((uv_handle_t*)&cnx->local_uv_handle.pipe, handle_close_cb);
    }

    /* Close remote (client) handle */
    if (cnx->remote_handle_initialized && !cnx->remote_handle_closing) {
        cnx->remote_handle_closing = 1;
        if (cnx->remote_handle_type == UV_TCP)
            uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
        else if (cnx->remote_handle_type == UV_NAMED_PIPE)
            uv_close((uv_handle_t*)&cnx->remote_uv_handle.pipe, handle_close_cb);
    }
}

/* TCP backend connection callback */
static void tcp_connect_cb(uv_connect_t *req, int status)
{
    ConnectionInfo *cnx = (ConnectionInfo*)req->data;
    free(req);

    /* Stop connect timeout timer (connection completed - success or failure) */
    if (cnx->connect_timer_initialized && !cnx->connect_timer_closing) {
        uv_timer_stop(&cnx->connect_timer);
        cnx->connect_timer_closing = 1;
        uv_close((uv_handle_t*)&cnx->connect_timer, handle_close_cb);
    }

    /* If handles are already closing, connect_timeout_cb already handled cleanup.
       This happens when the timeout fires, closes the local TCP handle, and libuv
       then calls this callback with UV_ECANCELED. */
    if (cnx->local_handle_closing)
        return;

    if (status < 0) {
        logErrorConn(cnx, "connect error: %s\n", uv_strerror(status));
        stats_error_connect();
        logEvent(cnx, cnx->server, logLocalConnectFailed);

        /* Track backend health for load balancing */
        if (cnx->selected_backend && cnx->rule) {
            lb_backend_mark_failure(cnx->selected_backend, cnx->rule);
            lb_backend_connection_end(cnx->selected_backend, 0, 0);
        }

        /* Track failures and trigger DNS refresh if threshold reached (legacy) */
        if (cnx->server && !cnx->selected_backend) {
            ServerInfo *srv = (ServerInfo *)cnx->server;
            srv->consecutive_failures++;
            if (srv->consecutive_failures >= RINETD_DNS_REFRESH_FAILURE_THRESHOLD &&
                shouldEnableDnsRefresh(srv)) {
                logDebug("Backend failures (%d) reached threshold for %s, triggering DNS refresh\n", srv->consecutive_failures, srv->toHost);
                startAsyncDnsResolution(srv);
            }
        }

        /* Close local handle that was initialized but failed to connect */
        cnx->local_handle_closing = 1;  /* Set BEFORE uv_close() */
        uv_close((uv_handle_t*)&cnx->local_uv_handle.tcp, handle_close_cb);
        /* Close remote handle */
        if (cnx->remote_handle_initialized && !cnx->remote_handle_closing) {
            cnx->remote_handle_closing = 1;  /* Set BEFORE uv_close() */
            uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
        }
        return;
    }

    /* Extract fd for Socket struct */
    uv_os_fd_t fd = INVALID_SOCKET;
    uv_fileno((uv_handle_t*)&cnx->local_uv_handle.tcp, &fd);
    cnx->local.fd = fd;

    set_socket_buffer_sizes((uv_handle_t *)&cnx->local_uv_handle.tcp);

    /* Enable TCP keepalive on backend connection if configured */
    if (cnx->server && cnx->server->keepalive) {
        /* Use 60 second delay before first keepalive probe */
        int ret = uv_tcp_keepalive(&cnx->local_uv_handle.tcp, 1, 60);
        if (ret != 0) {
            logErrorConn(cnx, "uv_tcp_keepalive (local) error: %s\n", uv_strerror(ret));
            /* Continue anyway - keepalive is optional */
        }
    }

    /* Start reading from local (backend) */
    int ret = uv_read_start((uv_stream_t*)&cnx->local_uv_handle.tcp, alloc_buffer_cb, tcp_read_cb);
    if (ret != 0) {
        logErrorConn(cnx, "uv_read_start (local) error: %s\n", uv_strerror(ret));
        /* Close both handles - local read failed, remote never started */
        handleClose(cnx, &cnx->local, &cnx->remote);
        return;
    }

    /* NOW start reading from remote (client) - backend is connected */
    ret = uv_read_start((uv_stream_t*)&cnx->remote_uv_handle.tcp, alloc_buffer_cb, tcp_read_cb);
    if (ret != 0) {
        logErrorConn(cnx, "uv_read_start (remote) error: %s\n", uv_strerror(ret));
        /* Stop reading on local handle since remote read failed */
        uv_read_stop((uv_stream_t*)&cnx->local_uv_handle.tcp);
        /* Close both handles */
        handleClose(cnx, &cnx->local, &cnx->remote);
        return;
    }

    logEvent(cnx, cnx->server, logOpened);
    stats_connection_accepted(IPPROTO_TCP);

    /* Mark backend healthy on successful connection (load balancing) */
    if (cnx->selected_backend && cnx->rule)
        lb_backend_mark_success(cnx->selected_backend, cnx->rule);

    /* Reset failure counter on successful connection (legacy) */
    if (cnx->server && !cnx->selected_backend)
        ((ServerInfo *)cnx->server)->consecutive_failures = 0;
}

/* TCP server accept callback */
static void tcp_server_accept_cb(uv_stream_t *server, int status)
{
    if (status < 0) {
        logError("accept error: %s\n", uv_strerror(status));
        stats_error_accept();
        return;
    }

    ServerInfo *srv = (ServerInfo*)server->data;
    ConnectionInfo *cnx = allocateConnection();
    if (!cnx)
        return;

    /* Initialize remote handle (client connection) */
    int ret = uv_tcp_init(main_loop, &cnx->remote_uv_handle.tcp);
    if (ret != 0) {
        logError("uv_tcp_init error: %s\n", uv_strerror(ret));
        freeUnhandledConnection(cnx);
        return;
    }
    cnx->remote_handle_type = UV_TCP;
    cnx->remote_handle_initialized = 1;
    cnx->remote_uv_handle.tcp.data = cnx;

    /* Accept the connection */
    ret = uv_accept(server, (uv_stream_t*)&cnx->remote_uv_handle.tcp);
    if (ret != 0) {
        logError("uv_accept error: %s\n", uv_strerror(ret));
        cnx->remote_handle_closing = 1;  /* Set BEFORE uv_close() */
        uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
        return;
    }

    set_socket_buffer_sizes((uv_handle_t *)&cnx->remote_uv_handle.tcp);

    /* Get remote address immediately after accept */
    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    int addrlen = sizeof(addr);
    ret = uv_tcp_getpeername(&cnx->remote_uv_handle.tcp, (struct sockaddr*)&addr, &addrlen);
    if (ret != 0) {
        logError("uv_tcp_getpeername error: %s\n", uv_strerror(ret));
        cnx->remote_handle_closing = 1;
        uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
        return;
    }
    cnx->remoteAddress = addr;
    cnx->server = srv;  /* Needed for checkConnectionAllowed */

    int logCode = checkConnectionAllowed(cnx);
    if (logCode != logAllowed) {
        stats_connection_denied();
        cnx->remote_handle_closing = 1;  /* Set BEFORE uv_close() */
        uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
        logEvent(cnx, srv, logCode);
        return;
    }

    /* Enable TCP keepalive on client connection if configured */
    if (srv->keepalive) {
        /* Use 60 second delay before first keepalive probe */
        ret = uv_tcp_keepalive(&cnx->remote_uv_handle.tcp, 1, 60);
        if (ret != 0) {
            logErrorConn(cnx, "uv_tcp_keepalive (remote) error: %s\n", uv_strerror(ret));
            /* Continue anyway - keepalive is optional */
        }
    }

    /* Extract fd for Socket struct */
    uv_os_fd_t remote_fd = INVALID_SOCKET;
    uv_fileno((uv_handle_t*)&cnx->remote_uv_handle.tcp, &remote_fd);
    cnx->remote.fd = remote_fd;

    /* Initialize connection state */
    cnx->remote.family = srv->fromAddrInfo->ai_family;
    cnx->remote.protocol = IPPROTO_TCP;
    cnx->remote.totalBytesIn = cnx->remote.totalBytesOut = 0;

    cnx->local.fd = INVALID_SOCKET;
    /* local.family will be set after backend selection */
    cnx->local.totalBytesIn = cnx->local.totalBytesOut = 0;

    cnx->coClosing = 0;
    cnx->coLog = logUnknownError;
    cacheServerInfoForLogging(cnx, srv);
    cnx->timer_initialized = 0;

    /* Load balancing: select backend if rule has multiple backends */
    BackendInfo *backend = NULL;
    struct addrinfo *backend_addr = NULL;
    char *backend_unix_path = NULL;
    int backend_is_abstract = 0;
    struct addrinfo *backend_source = NULL;

    if (srv->rule && srv->rule->backend_count > 0) {
        /* YAML config with load balancing */
        backend = lb_select_backend(srv->rule, &cnx->remoteAddress);
        if (backend) {
            cnx->selected_backend = backend;
            cnx->rule = srv->rule;
            lb_backend_connection_start(backend);
            backend_addr = backend->addrInfo;
            backend_unix_path = backend->unixPath;
            backend_is_abstract = backend->isAbstract;
            backend_source = backend->sourceAddrInfo;

            /* Log connection details for debugging */
            if (backend_addr) {
                char dest_ip[INET6_ADDRSTRLEN];
                format_addr_ip(backend_addr, dest_ip, sizeof(dest_ip));
                logDebug("New connection -> backend=%s host=%s ip=%s port=%s\n",
                        backend->name ? backend->name : "unknown",
                        backend->host ? backend->host : "N/A",
                        dest_ip,
                        backend->port ? backend->port : "N/A");
            } else if (backend_unix_path) {
                logDebug("New connection -> backend=%s unix=%s%s\n",
                        backend->name ? backend->name : "unknown",
                        backend_is_abstract ? "@" : "",
                        backend_unix_path);
            }
        }
    }

    /* Fall back to legacy ServerInfo fields if no backend selected */
    if (!backend_addr && !backend_unix_path) {
        backend_addr = srv->toAddrInfo;
        backend_unix_path = srv->toUnixPath;
        backend_is_abstract = srv->toIsAbstract;
        backend_source = srv->sourceAddrInfo;
    }

    /* Set local family/protocol based on backend type */
    if (backend_unix_path) {
        cnx->local.family = AF_UNIX;
        cnx->local.protocol = 0;
    } else if (backend_addr) {
        cnx->local.family = backend_addr->ai_family;
        cnx->local.protocol = IPPROTO_TCP;
    } else {
        /* No backend available - this shouldn't happen */
        logErrorConn(cnx, "No backend address available\n");
        cnx->remote_handle_closing = 1;
        uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
        return;
    }

    /* Connect to backend - either TCP or Unix socket */
    if (backend_unix_path) {
        /* Backend is Unix socket */
        ret = uv_pipe_init(main_loop, &cnx->local_uv_handle.pipe, 0);
        if (ret != 0) {
            logErrorConn(cnx, "uv_pipe_init error: %s\n", uv_strerror(ret));
            if (cnx->selected_backend) lb_backend_connection_end(cnx->selected_backend, 0, 0);
            cnx->remote_handle_closing = 1;
            uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
            return;
        }
        cnx->local_handle_type = UV_NAMED_PIPE;
        cnx->local_handle_initialized = 1;
        cnx->local_uv_handle.pipe.data = cnx;

        uv_connect_t *connect_req = malloc(sizeof(uv_connect_t));
        if (!connect_req) {
            logErrorConn(cnx, "malloc failed for Unix connect request\n");
            if (cnx->selected_backend) lb_backend_connection_end(cnx->selected_backend, 0, 0);
            cnx->local_handle_closing = 1;
            cnx->remote_handle_closing = 1;
            uv_close((uv_handle_t*)&cnx->local_uv_handle.pipe, handle_close_cb);
            uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
            return;
        }
        connect_req->data = cnx;

        /* Connect to Unix socket backend */
        if (backend_is_abstract) {
            char abstract_name[UNIX_PATH_MAX + 2];
            size_t name_len = prepareAbstractSocketName(backend_unix_path, abstract_name);
            if (name_len == 0) {
                free(connect_req);
                if (cnx->selected_backend) lb_backend_connection_end(cnx->selected_backend, 0, 0);
                cnx->local_handle_closing = 1;
                cnx->remote_handle_closing = 1;
                uv_close((uv_handle_t*)&cnx->local_uv_handle.pipe, handle_close_cb);
                uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
                return;
            }
            uv_pipe_connect2(connect_req, &cnx->local_uv_handle.pipe, abstract_name, name_len, UV_PIPE_NO_TRUNCATE, unix_connect_cb);
        } else {
            uv_pipe_connect(connect_req, &cnx->local_uv_handle.pipe, backend_unix_path, unix_connect_cb);
        }
    } else {
        /* Backend is TCP */
        ret = uv_tcp_init(main_loop, &cnx->local_uv_handle.tcp);
        if (ret != 0) {
            logErrorConn(cnx, "uv_tcp_init error: %s\n", uv_strerror(ret));
            if (cnx->selected_backend) lb_backend_connection_end(cnx->selected_backend, 0, 0);
            cnx->remote_handle_closing = 1;
            uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
            return;
        }
        cnx->local_handle_type = UV_TCP;
        cnx->local_handle_initialized = 1;
        cnx->local_uv_handle.tcp.data = cnx;

        /* Bind to source address if specified (backend-specific or server default) */
        struct addrinfo *source = backend_source ? backend_source : srv->sourceAddrInfo;
        if (source) {
            ret = uv_tcp_bind(&cnx->local_uv_handle.tcp, source->ai_addr, 0);
            if (ret != 0) {
                logErrorConn(cnx, "bind (source) error: %s\n", uv_strerror(ret));
                /* Continue anyway - binding is optional */
            }
        }

        /* Connect to backend (async) */
        uv_connect_t *connect_req = malloc(sizeof(uv_connect_t));
        if (!connect_req) {
            logErrorConn(cnx, "malloc failed for connect request\n");
            if (cnx->selected_backend) lb_backend_connection_end(cnx->selected_backend, 0, 0);
            cnx->local_handle_closing = 1;
            cnx->remote_handle_closing = 1;
            uv_close((uv_handle_t*)&cnx->local_uv_handle.tcp, handle_close_cb);
            uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
            return;
        }
        connect_req->data = cnx;

        ret = uv_tcp_connect(connect_req, &cnx->local_uv_handle.tcp, backend_addr->ai_addr, tcp_connect_cb);
        if (ret != 0) {
            logErrorConn(cnx, "uv_tcp_connect error: %s\n", uv_strerror(ret));
            stats_error_connect();
            logEvent(cnx, cnx->server, logLocalConnectFailed);

            /* Track backend health for load balancing */
            if (cnx->selected_backend && cnx->rule)
                lb_backend_mark_failure(cnx->selected_backend, cnx->rule);

            free(connect_req);
            if (cnx->selected_backend) lb_backend_connection_end(cnx->selected_backend, 0, 0);
            cnx->local_handle_closing = 1;
            cnx->remote_handle_closing = 1;
            uv_close((uv_handle_t*)&cnx->local_uv_handle.tcp, handle_close_cb);
            uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
            return;
        }

        /* Start connect timeout timer if configured */
        int ct = 0;
        if (srv->rule && srv->rule->connect_timeout > 0)
            ct = srv->rule->connect_timeout;
        else if (srv->connectTimeout > 0)
            ct = srv->connectTimeout;
        else if (globalConnectTimeout > 0)
            ct = globalConnectTimeout;

        if (ct > 0) {
            ret = uv_timer_init(main_loop, &cnx->connect_timer);
            if (ret == 0) {
                cnx->connect_timer.data = cnx;
                cnx->connect_timer_initialized = 1;
                ret = uv_timer_start(&cnx->connect_timer, connect_timeout_cb, ct * 1000, 0);
                if (ret != 0) {
                    cnx->connect_timer_closing = 1;
                    uv_close((uv_handle_t*)&cnx->connect_timer, handle_close_cb);
                }
            }
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
        logErrorConn(cnx, "Unix connect error: %s\n", uv_strerror(status));
        stats_error_connect();
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
    uv_os_fd_t fd = INVALID_SOCKET;
    uv_fileno((uv_handle_t*)&cnx->local_uv_handle.pipe, &fd);
    cnx->local.fd = fd;

    set_socket_buffer_sizes((uv_handle_t *)&cnx->local_uv_handle.pipe);

    /* Start reading from local (backend) - pipe is a stream, tcp_read_cb works */
    int ret = uv_read_start((uv_stream_t*)&cnx->local_uv_handle.pipe, alloc_buffer_cb, tcp_read_cb);
    if (ret != 0) {
        logErrorConn(cnx, "uv_read_start (local unix) error: %s\n", uv_strerror(ret));
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
        logErrorConn(cnx, "uv_read_start (remote) error: %s\n", uv_strerror(ret));
        uv_read_stop((uv_stream_t*)&cnx->local_uv_handle.pipe);
        handleClose(cnx, &cnx->local, &cnx->remote);
        return;
    }

    logEvent(cnx, cnx->server, logOpened);
    stats_connection_accepted(0);  /* Unix socket - protocol 0 */

    /* Reset failure counter on successful connection */
    if (cnx->server)
        ((ServerInfo *)cnx->server)->consecutive_failures = 0;
}

/* Unix server accept callback */
static void unix_server_accept_cb(uv_stream_t *server, int status)
{
    if (status < 0) {
        logError("Unix accept error: %s\n", uv_strerror(status));
        stats_error_accept();
        return;
    }

    ServerInfo *srv = (ServerInfo*)server->data;
    ConnectionInfo *cnx = allocateConnection();
    if (!cnx)
        return;

    /* Initialize remote handle (client connection) - it's a Unix pipe */
    int ret = uv_pipe_init(main_loop, &cnx->remote_uv_handle.pipe, 0);
    if (ret != 0) {
        logError("uv_pipe_init error: %s\n", uv_strerror(ret));
        freeUnhandledConnection(cnx);
        return;
    }
    cnx->remote_handle_type = UV_NAMED_PIPE;
    cnx->remote_handle_initialized = 1;
    cnx->remote_uv_handle.pipe.data = cnx;

    /* Accept the connection */
    ret = uv_accept(server, (uv_stream_t*)&cnx->remote_uv_handle.pipe);
    if (ret != 0) {
        logErrorConn(cnx, "uv_accept (Unix) error: %s\n", uv_strerror(ret));
        cnx->remote_handle_closing = 1;
        uv_close((uv_handle_t*)&cnx->remote_uv_handle.pipe, handle_close_cb);
        return;
    }

    set_socket_buffer_sizes((uv_handle_t *)&cnx->remote_uv_handle.pipe);

    /* Extract fd for Socket struct */
    uv_os_fd_t remote_fd = INVALID_SOCKET;
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

    /* Load balancing: select backend if rule has multiple backends */
    BackendInfo *backend = NULL;
    struct addrinfo *backend_addr = NULL;
    char *backend_unix_path = NULL;
    int backend_is_abstract = 0;
    struct addrinfo *backend_source = NULL;

    if (srv->rule && srv->rule->backend_count > 0) {
        /* YAML config with load balancing */
        backend = lb_select_backend(srv->rule, &cnx->remoteAddress);
        if (backend) {
            cnx->selected_backend = backend;
            cnx->rule = srv->rule;
            lb_backend_connection_start(backend);
            backend_addr = backend->addrInfo;
            backend_unix_path = backend->unixPath;
            backend_is_abstract = backend->isAbstract;
            backend_source = backend->sourceAddrInfo;

            /* Log connection details for debugging */
            if (backend_addr) {
                char dest_ip[INET6_ADDRSTRLEN];
                format_addr_ip(backend_addr, dest_ip, sizeof(dest_ip));
                logDebug("New connection -> backend=%s host=%s ip=%s port=%s\n",
                        backend->name ? backend->name : "unknown",
                        backend->host ? backend->host : "N/A",
                        dest_ip,
                        backend->port ? backend->port : "N/A");
            } else if (backend_unix_path) {
                logDebug("New connection -> backend=%s unix=%s%s\n",
                        backend->name ? backend->name : "unknown",
                        backend_is_abstract ? "@" : "",
                        backend_unix_path);
            }
        }
    }

    /* Fall back to legacy ServerInfo fields if no backend selected */
    if (!backend_addr && !backend_unix_path) {
        backend_addr = srv->toAddrInfo;
        backend_unix_path = srv->toUnixPath;
        backend_is_abstract = srv->toIsAbstract;
        backend_source = srv->sourceAddrInfo;
    }

    /* Set local family/protocol based on backend type */
    if (backend_unix_path) {
        cnx->local.family = AF_UNIX;
        cnx->local.protocol = 0;
    } else if (backend_addr) {
        cnx->local.family = backend_addr->ai_family;
        cnx->local.protocol = IPPROTO_TCP;
    } else {
        /* No backend available */
        logErrorConn(cnx, "No backend address available\n");
        cnx->remote_handle_closing = 1;
        uv_close((uv_handle_t*)&cnx->remote_uv_handle.pipe, handle_close_cb);
        return;
    }

    /* Connect to backend - either TCP or Unix */
    if (backend_unix_path) {
        /* Backend is Unix socket */
        ret = uv_pipe_init(main_loop, &cnx->local_uv_handle.pipe, 0);
        if (ret != 0) {
            logErrorConn(cnx, "uv_pipe_init error: %s\n", uv_strerror(ret));
            if (cnx->selected_backend) lb_backend_connection_end(cnx->selected_backend, 0, 0);
            cnx->remote_handle_closing = 1;
            uv_close((uv_handle_t*)&cnx->remote_uv_handle.pipe, handle_close_cb);
            return;
        }
        cnx->local_handle_type = UV_NAMED_PIPE;
        cnx->local_handle_initialized = 1;
        cnx->local_uv_handle.pipe.data = cnx;

        uv_connect_t *connect_req = malloc(sizeof(uv_connect_t));
        if (!connect_req) {
            logErrorConn(cnx, "malloc failed for Unix connect request\n");
            if (cnx->selected_backend) lb_backend_connection_end(cnx->selected_backend, 0, 0);
            cnx->local_handle_closing = 1;
            cnx->remote_handle_closing = 1;
            uv_close((uv_handle_t*)&cnx->local_uv_handle.pipe, handle_close_cb);
            uv_close((uv_handle_t*)&cnx->remote_uv_handle.pipe, handle_close_cb);
            return;
        }
        connect_req->data = cnx;

        /* Connect to Unix socket backend */
        if (backend_is_abstract) {
            /* Abstract socket */
            char abstract_name[UNIX_PATH_MAX + 1];
            size_t name_len = prepareAbstractSocketName(backend_unix_path, abstract_name);
            if (name_len == 0) {
                free(connect_req);
                if (cnx->selected_backend) lb_backend_connection_end(cnx->selected_backend, 0, 0);
                cnx->local_handle_closing = 1;
                cnx->remote_handle_closing = 1;
                uv_close((uv_handle_t*)&cnx->local_uv_handle.pipe, handle_close_cb);
                uv_close((uv_handle_t*)&cnx->remote_uv_handle.pipe, handle_close_cb);
                return;
            }
            uv_pipe_connect2(connect_req, &cnx->local_uv_handle.pipe, abstract_name, name_len, UV_PIPE_NO_TRUNCATE, unix_connect_cb);
        } else {
            uv_pipe_connect(connect_req, &cnx->local_uv_handle.pipe, backend_unix_path, unix_connect_cb);
        }
    } else {
        /* Backend is TCP */
        ret = uv_tcp_init(main_loop, &cnx->local_uv_handle.tcp);
        if (ret != 0) {
            logErrorConn(cnx, "uv_tcp_init error: %s\n", uv_strerror(ret));
            if (cnx->selected_backend) lb_backend_connection_end(cnx->selected_backend, 0, 0);
            cnx->remote_handle_closing = 1;
            uv_close((uv_handle_t*)&cnx->remote_uv_handle.pipe, handle_close_cb);
            return;
        }
        cnx->local_handle_type = UV_TCP;
        cnx->local_handle_initialized = 1;
        cnx->local_uv_handle.tcp.data = cnx;

        /* Bind to source address if specified */
        if (backend_source) {
            ret = uv_tcp_bind(&cnx->local_uv_handle.tcp, backend_source->ai_addr, 0);
            if (ret != 0)
                logErrorConn(cnx, "bind (source) error: %s\n", uv_strerror(ret));
        }

        uv_connect_t *connect_req = malloc(sizeof(uv_connect_t));
        if (!connect_req) {
            logErrorConn(cnx, "malloc failed for TCP connect request\n");
            if (cnx->selected_backend) lb_backend_connection_end(cnx->selected_backend, 0, 0);
            cnx->local_handle_closing = 1;
            cnx->remote_handle_closing = 1;
            uv_close((uv_handle_t*)&cnx->local_uv_handle.tcp, handle_close_cb);
            uv_close((uv_handle_t*)&cnx->remote_uv_handle.pipe, handle_close_cb);
            return;
        }
        connect_req->data = cnx;

        ret = uv_tcp_connect(connect_req, &cnx->local_uv_handle.tcp, backend_addr->ai_addr, tcp_connect_cb);
        if (ret != 0) {
            logErrorConn(cnx, "uv_tcp_connect error: %s\n", uv_strerror(ret));
            free(connect_req);
            if (cnx->selected_backend) lb_backend_connection_end(cnx->selected_backend, 0, 0);
            cnx->local_handle_closing = 1;
            cnx->remote_handle_closing = 1;
            uv_close((uv_handle_t*)&cnx->local_uv_handle.tcp, handle_close_cb);
            uv_close((uv_handle_t*)&cnx->remote_uv_handle.pipe, handle_close_cb);
            return;
        }
    }
}

/* Buffer allocation callback for UDP server sockets */
static void alloc_buffer_udp_server_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    (void)handle;
    (void)suggested_size;

    /* Allocate buffer for UDP datagrams from pool */
    buf->base = buffer_pool_alloc();
    if (!buf->base) {
        buf->len = 0;
    } else {
        buf->len = bufferSize;
    }
}

/* Buffer allocation callback for libuv reads (connections) */
static void alloc_buffer_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    (void)handle;  /* Unused - we don't need connection info to allocate */
    (void)suggested_size;  /* Use configured bufferSize instead */

    /* Allocate buffer from pool - will be freed in write callback */
    char *buffer = buffer_pool_alloc();
    if (!buffer) {
        logError("buffer_pool_alloc failed for read buffer\n");
        buf->base = NULL;
        buf->len = 0;
        return;
    }

    buf->base = buffer;
    buf->len = bufferSize;
}

/* Forward declaration for write callback */
static void tcp_write_cb(uv_write_t *req, int status);

/* Forward declaration for shutdown callback */
static void shutdown_cb(uv_shutdown_t *req, int status);

/* Helper: finalize connection statistics and cleanup (called once per connection) */
static void finalizeConnection(ConnectionInfo *cnx, int logReason)
{
    if (cnx->coClosing)
        return;

    cnx->coLog = logReason;
    logEvent(cnx, cnx->server, cnx->coLog);
    cnx->coClosing = 1;

    /* Update global statistics */
    uint64_t bytes_in = cnx->local.totalBytesIn + cnx->remote.totalBytesIn;
    uint64_t bytes_out = cnx->local.totalBytesOut + cnx->remote.totalBytesOut;
    stats_connection_closed(cnx->remote.protocol, bytes_in, bytes_out);

    /* Update load balancing statistics */
    if (cnx->selected_backend)
        lb_backend_connection_end(cnx->selected_backend, bytes_in, bytes_out);

    /* Cleanup UDP connection: remove from hash table and LRU list */
    if (cnx->remote.protocol == IPPROTO_UDP && cnx->server) {
        hash_remove_udp_connection(cnx);
        ServerInfo *srv = (ServerInfo*)cnx->server;
        lru_remove(srv, cnx);
        if (srv->udp_connection_count > 0)
            srv->udp_connection_count--;
    }
}

/* Helper: check if connection can be fully closed (both sides EOF) */
static void tryFullClose(ConnectionInfo *cnx)
{
    /* Only close when both sides have received EOF */
    if (!cnx->local_read_eof || !cnx->remote_read_eof)
        return;

    /* Both sides have EOF - finalize stats before closing handles */
    finalizeConnection(cnx, logLocalClosedFirst);  /* Arbitrary log reason for dual-EOF */

    /* Close local handle if not already closing */
    if (cnx->local_handle_initialized && !cnx->local_handle_closing) {
        uv_handle_t *handle = (cnx->local_handle_type == UV_TCP)
            ? (uv_handle_t*)&cnx->local_uv_handle.tcp
            : (cnx->local_handle_type == UV_NAMED_PIPE)
            ? (uv_handle_t*)&cnx->local_uv_handle.pipe
            : (uv_handle_t*)&cnx->local_uv_handle.udp;
        if (!uv_is_closing(handle)) {
            uv_read_stop((uv_stream_t*)handle);
            cnx->local_handle_closing = 1;
            uv_close(handle, handle_close_cb);
        }
        cnx->local.fd = INVALID_SOCKET;
    }

    /* Close remote handle if not already closing */
    if (cnx->remote_handle_initialized && !cnx->remote_handle_closing) {
        uv_handle_t *handle = (cnx->remote_handle_type == UV_TCP)
            ? (uv_handle_t*)&cnx->remote_uv_handle.tcp
            : (cnx->remote_handle_type == UV_NAMED_PIPE)
            ? (uv_handle_t*)&cnx->remote_uv_handle.pipe
            : (uv_handle_t*)&cnx->remote_uv_handle.udp;
        if (!uv_is_closing(handle)) {
            uv_read_stop((uv_stream_t*)handle);
            cnx->remote_handle_closing = 1;
            uv_close(handle, handle_close_cb);
        }
        cnx->remote.fd = INVALID_SOCKET;
    }

    /* Close timer if active */
    if (cnx->timer_initialized && !cnx->timer_closing &&
        !uv_is_closing((uv_handle_t*)&cnx->timeout_timer)) {
        cnx->timer_closing = 1;
        uv_close((uv_handle_t*)&cnx->timeout_timer, handle_close_cb);
    }
}

/* Shutdown callback - called when uv_shutdown completes (pending writes flushed, FIN sent) */
static void shutdown_cb(uv_shutdown_t *req, int status)
{
    ConnectionInfo *cnx = (ConnectionInfo*)req->data;
    if (!cnx)
        return;

    if (status < 0 && status != UV_ECANCELED && status != UV_ENOTCONN) {
        logErrorConn(cnx, "shutdown error: %s\n", uv_strerror(status));
    }

    /* On error (especially ENOTCONN on FreeBSD Unix sockets), force both EOFs */
    if (status < 0 && status != UV_ECANCELED) {
        cnx->local_read_eof = 1;
        cnx->remote_read_eof = 1;
    }

    /* Shutdown complete - check if we can fully close now */
    tryFullClose(cnx);
}

/* Handle EOF on a stream with half-close semantics */
static void handleReadEOF(ConnectionInfo *cnx, Socket *socket,
                          Socket *other_socket __attribute__((unused)),
                          uv_stream_t *stream, uv_stream_t *other_stream)
{
    int is_local = (socket == &cnx->local);
    int *my_eof = is_local ? &cnx->local_read_eof : &cnx->remote_read_eof;
    int *other_shutdown = is_local ? &cnx->remote_shutdown_sent : &cnx->local_shutdown_sent;
    uv_shutdown_t *shutdown_req = is_local ? &cnx->remote_shutdown_req : &cnx->local_shutdown_req;

    /* Mark this side as EOF */
    *my_eof = 1;

    /* Stop reading from this side */
    uv_read_stop(stream);

    /* Check if other side already got EOF too */
    if (cnx->local_read_eof && cnx->remote_read_eof) {
        /* Both sides done - close everything */
        tryFullClose(cnx);
        return;
    }

    /* Other side still active - send shutdown (FIN) to signal our EOF
       but keep reading from other side so we can forward to this side's write */
    if (!*other_shutdown && !uv_is_closing((uv_handle_t*)other_stream)) {
        *other_shutdown = 1;
        shutdown_req->data = cnx;
        int ret = uv_shutdown(shutdown_req, other_stream, shutdown_cb);
        if (ret != 0) {
            logErrorConn(cnx, "uv_shutdown error: %s\n", uv_strerror(ret));
            /* Shutdown failed - force close */
            cnx->local_read_eof = 1;
            cnx->remote_read_eof = 1;
            tryFullClose(cnx);
        }
    }
}

/* TCP read callback */
static void tcp_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    ConnectionInfo *cnx = (ConnectionInfo*)stream->data;

    /* Defensive null check */
    if (!cnx) {
        if (buf->base)
            buffer_pool_free(buf->base, buf->len);
        return;
    }

    /* Determine which socket and the other socket */
    Socket *socket, *other_socket;
    uv_stream_t *other_stream;

    /* Get proper stream pointers based on handle type */
    uv_stream_t *local_stream = (cnx->local_handle_type == UV_TCP)
        ? (uv_stream_t*)&cnx->local_uv_handle.tcp
        : (uv_stream_t*)&cnx->local_uv_handle.pipe;

    uv_stream_t *remote_stream = (cnx->remote_handle_type == UV_TCP)
        ? (uv_stream_t*)&cnx->remote_uv_handle.tcp
        : (uv_stream_t*)&cnx->remote_uv_handle.pipe;

    if (stream == local_stream) {
        socket = &cnx->local;
        other_socket = &cnx->remote;
        other_stream = remote_stream;
    } else {
        socket = &cnx->remote;
        other_socket = &cnx->local;
        other_stream = local_stream;
    }

    if (nread < 0) {
        /* Error or EOF - free buffer */
        if (buf->base)
            buffer_pool_free(buf->base, buf->len);

        if (nread == UV_EOF) {
            /* Clean EOF - use half-close semantics for TCP/Unix streams */
            if (socket->protocol == IPPROTO_TCP || socket->family == AF_UNIX) {
                handleReadEOF(cnx, socket, other_socket, stream, other_stream);
                return;
            }
        } else {
            /* Actual error - log it */
            logErrorConn(cnx, "read error: %s\n", uv_strerror((int)nread));
        }
        /* For errors or UDP, do immediate close */
        handleClose(cnx, socket, other_socket);
        return;
    }

    if (nread == 0) {
        /* EAGAIN - free buffer and try again later */
        if (buf->base)
            buffer_pool_free(buf->base, buf->len);
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
        buffer_pool_free(buf->base, buf->len);
        return;
    }

    /* Create write request with buffer info */
    WriteReq *wreq = (WriteReq*)malloc(sizeof(WriteReq));
    if (!wreq) {
        logErrorConn(cnx, "malloc failed for WriteReq\n");
        buffer_pool_free(buf->base, buf->len);
        handleClose(cnx, socket, other_socket);
        return;
    }

    wreq->cnx = cnx;
    wreq->buffer = buf->base;   /* Take ownership of buffer */
    wreq->buffer_size = nread;  /* Bytes being written (for stats) */
    wreq->alloc_size = buf->len; /* Allocated size (for pool) */
    wreq->socket = other_socket; /* Writing to OTHER socket */

    /* Set up uv_write request */
    uv_buf_t wrbuf = uv_buf_init(buf->base, nread);
    int ret = uv_write(&wreq->req, other_stream, &wrbuf, 1, tcp_write_cb);
    if (ret != 0) {
        logErrorConn(cnx, "uv_write error: %s\n", uv_strerror(ret));
        buffer_pool_free(wreq->buffer, wreq->alloc_size);
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

    /* Return buffer to pool */
    buffer_pool_free(wreq->buffer, wreq->alloc_size);

    /* Handle write errors */
    if (status < 0) {
        logErrorConn(cnx, "write error: %s\n", uv_strerror(status));
        /* Determine which socket failed based on handle */
        Socket *socket, *other_socket;

        /* Get proper stream pointer based on handle type */
        uv_stream_t *local_stream = (cnx->local_handle_type == UV_TCP)
            ? (uv_stream_t*)&cnx->local_uv_handle.tcp
            : (uv_stream_t*)&cnx->local_uv_handle.pipe;

        if (req->handle == local_stream) {
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
    if (!handle || !handle->data)
        return;

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
    } else if ((uv_handle_t*)&cnx->connect_timer == handle) {
        cnx->connect_timer_closing = 0;
        cnx->connect_timer_initialized = 0;
    }

    /* Check if all handles are closed - if so, free the connection */
    /* IMPORTANT: uv_close() waits for pending I/O before calling this callback,
       so we don't need to check for pending writes separately. */
    if (!cnx->local_handle_initialized && !cnx->local_handle_closing &&
        !cnx->remote_handle_initialized && !cnx->remote_handle_closing &&
        !cnx->timer_initialized && !cnx->timer_closing &&
        !cnx->connect_timer_initialized && !cnx->connect_timer_closing) {
        /* All handles are closed - safe to free the connection */

        /* Remove from doubly-linked list */
        if (cnx->prev) {
            cnx->prev->next = cnx->next;
        } else {
            connectionListHead = cnx->next;
        }
        if (cnx->next)
            cnx->next->prev = cnx->prev;

        activeConnections--;

        /* Clear all handle->data pointers AFTER removing from list but BEFORE freeing.
           This ensures any subsequent callbacks will see NULL and return early. */
        cnx->local_uv_handle.tcp.data = NULL;   /* Union - sets both tcp.data and udp.data */
        cnx->remote_uv_handle.tcp.data = NULL;  /* Union - sets both tcp.data and udp.data */
        cnx->timeout_timer.data = NULL;
        cnx->connect_timer.data = NULL;

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
static void udp_local_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags);

/* UDP send to backend - takes ownership of buffer */
static void udp_send_to_backend(ConnectionInfo *cnx, char *data, int data_len, int alloc_size)
{
    /* Check if local handle is closing */
    if (cnx->local_handle_closing || !cnx->local_handle_initialized ||
        uv_is_closing((uv_handle_t*)&cnx->local_uv_handle.udp)) {
        buffer_pool_free(data, alloc_size);  /* Can't send, return to pool */
        return;
    }

    /* Create send request with buffer info */
    UdpSendReq *sreq = (UdpSendReq*)malloc(sizeof(UdpSendReq));
    if (!sreq) {
        logErrorConn(cnx, "malloc failed for UdpSendReq\n");
        buffer_pool_free(data, alloc_size);
        return;
    }

    sreq->cnx = cnx;
    sreq->buffer = data;        /* Take ownership */
    sreq->buffer_size = data_len; /* Bytes being sent (for stats) */
    sreq->alloc_size = alloc_size; /* Allocated size (for pool) */
    sreq->is_to_backend = 1;

    /* Use selected backend address or fall back to server address */
    struct addrinfo *backend_addr = cnx->selected_backend ?
        cnx->selected_backend->addrInfo : cnx->server->toAddrInfo;

    /* Copy address with correct size (not full sockaddr_storage which would overrun) */
    memset(&sreq->dest_addr, 0, sizeof(sreq->dest_addr));
    memcpy(&sreq->dest_addr, backend_addr->ai_addr, backend_addr->ai_addrlen);

    /* Set up buffer for sending */
    uv_buf_t wrbuf = uv_buf_init(data, data_len);

    int ret = uv_udp_send(&sreq->req, &cnx->local_uv_handle.udp, &wrbuf, 1, backend_addr->ai_addr, udp_send_cb);
    if (ret != 0) {
        logErrorConn(cnx, "uv_udp_send (to backend) error: %s\n", uv_strerror(ret));
        buffer_pool_free(sreq->buffer, sreq->alloc_size);
        free(sreq);
    }
}

/* UDP send to client - takes ownership of buffer */
static void udp_send_to_client(ConnectionInfo *cnx, char *data, int data_len, int alloc_size)
{
    ServerInfo *srv = (ServerInfo *)cnx->server;
    if (!srv) {
        buffer_pool_free(data, alloc_size);  /* Server gone, return to pool */
        return;
    }

    /* Check if server UDP handle is closing */
    if (!srv->handle_initialized || uv_is_closing((uv_handle_t*)&srv->uv_handle.udp)) {
        buffer_pool_free(data, alloc_size);  /* Can't send, return to pool */
        return;
    }

    /* Create send request with buffer info */
    UdpSendReq *sreq = (UdpSendReq*)malloc(sizeof(UdpSendReq));
    if (!sreq) {
        logErrorConn(cnx, "malloc failed for UdpSendReq\n");
        buffer_pool_free(data, alloc_size);
        return;
    }

    sreq->cnx = cnx;
    sreq->buffer = data;        /* Take ownership */
    sreq->buffer_size = data_len; /* Bytes being sent (for stats) */
    sreq->alloc_size = alloc_size; /* Allocated size (for pool) */
    sreq->is_to_backend = 0;
    sreq->dest_addr = cnx->remoteAddress;

    /* Set up buffer for sending */
    uv_buf_t wrbuf = uv_buf_init(data, data_len);

    int ret = uv_udp_send(&sreq->req, &srv->uv_handle.udp, &wrbuf, 1, (struct sockaddr*)&cnx->remoteAddress, udp_send_cb);
    if (ret != 0) {
        logErrorConn(cnx, "uv_udp_send (to client) error: %s\n", uv_strerror(ret));
        buffer_pool_free(sreq->buffer, sreq->alloc_size);
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

    /* Return buffer to pool */
    buffer_pool_free(sreq->buffer, sreq->alloc_size);

    if (status < 0) {
        logErrorConn(cnx, "UDP send error: %s\n", uv_strerror(status));
        /* For UDP, we don't close on send errors - just log */

        /* Track backend failures and trigger DNS refresh if threshold reached */
        if (sreq->is_to_backend && cnx->server) {
            ServerInfo *srv = (ServerInfo *)cnx->server;
            srv->consecutive_failures++;
            if (srv->consecutive_failures >= RINETD_DNS_REFRESH_FAILURE_THRESHOLD &&
                shouldEnableDnsRefresh(srv)) {
                logDebug("UDP backend failures (%d) reached threshold for %s, triggering DNS refresh\n", srv->consecutive_failures, srv->toHost);
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
static ConnectionInfo *lookup_udp_connection(ServerInfo const *srv, struct sockaddr_storage const *addr)
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
    while (*pp && *pp != conn)
        pp = &(*pp)->hash_next;
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

    if (oldest && !oldest->coClosing)
        handleClose(oldest, &oldest->remote, &oldest->local);
}

/* UDP timeout callback */
static void udp_timeout_cb(uv_timer_t *timer)
{
    ConnectionInfo *cnx = (ConnectionInfo*)timer->data;
    handleClose(cnx, &cnx->remote, &cnx->local);
}

/* UDP local (backend) receive callback */
static void udp_local_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags)
{
    (void)addr;  /* Unused - we already know the backend */
    (void)flags;
    ConnectionInfo *cnx = (ConnectionInfo*)handle->data;

    if (nread < 0) {
        logErrorConn(cnx, "UDP local recv error: %s\n", uv_strerror((int)nread));
        if (buf->base)
            buffer_pool_free(buf->base, buf->len);
        return;
    }

    if (nread == 0) {
        if (buf->base)
            buffer_pool_free(buf->base, buf->len);
        return;
    }

    /* Update statistics */
    cnx->local.totalBytesIn += nread;

    /* Send immediately to client - udp_send_to_client takes ownership of buf->base */
    udp_send_to_client(cnx, buf->base, (int)nread, buf->len);
}

/* UDP server receive callback */
static void udp_server_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags)
{
    (void)flags;

    if (nread < 0) {
        logError("UDP server recv error: %s\n", uv_strerror((int)nread));
        if (buf->base)
            buffer_pool_free(buf->base, buf->len);
        return;
    }

    if (nread == 0 || addr == NULL) {
        if (buf->base)
            buffer_pool_free(buf->base, buf->len);
        return;
    }

    ServerInfo *srv = (ServerInfo*)handle->data;
    uv_os_fd_t server_fd = INVALID_SOCKET;
    uv_fileno((uv_handle_t*)handle, &server_fd);

    /* Convert to sockaddr_storage for hashing (zero-init to avoid uninitialized padding) */
    struct sockaddr_storage addr_storage;
    memset(&addr_storage, 0, sizeof(addr_storage));
    memcpy(&addr_storage, addr, addr->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));

    /* O(1) hash lookup instead of O(n) list scan */
    ConnectionInfo *cnx = lookup_udp_connection(srv, &addr_storage);

    if (cnx) {
        /* Existing connection - mark as recently used */
        lru_touch(srv, cnx);

        /* Refresh timeout (note: uv_timer_again is a no-op with repeat=0) */
        cnx->remoteTimeout = time(NULL) + srv->serverTimeout;
        uv_timer_stop(&cnx->timeout_timer);
        int timer_ret = uv_timer_start(&cnx->timeout_timer, udp_timeout_cb, srv->serverTimeout * 1000, 0);
        if (timer_ret != 0)
            logErrorConn(cnx, "uv_timer_start error: %s\n", uv_strerror(timer_ret));

        /* Update statistics */
        cnx->remote.totalBytesIn += nread;

        /* Send immediately to backend - udp_send_to_backend takes ownership of buf->base */
        udp_send_to_backend(cnx, buf->base, (int)nread, buf->len);
        return;
    }

    /* New connection - check if we've reached the limit */
    if (srv->udp_connection_count >= (uint64_t)maxUdpConnections) {
        /* Close oldest connection to make room */
        close_oldest_udp_connection((ServerInfo*)srv);
    }

    cnx = allocateConnection();
    if (!cnx) {
        buffer_pool_free(buf->base, buf->len);
        return;
    }

    /* Setup minimal state needed for rule check */
    /* Copy address with correct size based on family (not full sockaddr_storage) */
    memset(&cnx->remoteAddress, 0, sizeof(cnx->remoteAddress));
    size_t addr_len = (addr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) :
                      (addr->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6) :
                      sizeof(struct sockaddr);
    memcpy(&cnx->remoteAddress, addr, addr_len);
    cnx->server = srv;

    int logCode = checkConnectionAllowed(cnx);
    if (logCode != logAllowed) {
        stats_connection_denied();
        logEvent(cnx, srv, logCode);
        buffer_pool_free(buf->base, buf->len);
        freeUnhandledConnection(cnx);
        return;
    }

    /* Connection allowed - continue with full setup */
    cnx->remote.fd = server_fd;
    cnx->remote.family = srv->fromAddrInfo->ai_family;
    cnx->remote.protocol = IPPROTO_UDP;
    cnx->remoteTimeout = time(NULL) + srv->serverTimeout;
    cacheServerInfoForLogging(cnx, srv);

    /* Load balancing: select backend if rule has multiple backends */
    BackendInfo *backend = NULL;
    struct addrinfo *backend_addr = NULL;
    struct addrinfo *backend_source = NULL;

    if (srv->rule && srv->rule->backend_count > 0) {
        backend = lb_select_backend(srv->rule, &cnx->remoteAddress);
        if (backend) {
            cnx->selected_backend = backend;
            cnx->rule = srv->rule;
            lb_backend_connection_start(backend);
            backend_addr = backend->addrInfo;
            backend_source = backend->sourceAddrInfo;

            /* Log connection details for debugging */
            if (backend_addr) {
                char dest_ip[INET6_ADDRSTRLEN];
                format_addr_ip(backend_addr, dest_ip, sizeof(dest_ip));
                logDebug("New UDP session -> backend=%s host=%s ip=%s port=%s\n",
                        backend->name ? backend->name : "unknown",
                        backend->host ? backend->host : "N/A",
                        dest_ip,
                        backend->port ? backend->port : "N/A");
            }
        }
    }

    /* Fall back to legacy ServerInfo fields */
    if (!backend_addr) {
        backend_addr = srv->toAddrInfo;
        backend_source = srv->sourceAddrInfo;
    }

    /* Remote handle shared with server (don't initialize separate handle) */
    cnx->remote_handle_initialized = 0;

    /* Initialize timeout timer */
    int ret = uv_timer_init(main_loop, &cnx->timeout_timer);
    if (ret != 0) {
        logErrorConn(cnx, "uv_timer_init error: %s\n", uv_strerror(ret));
        if (cnx->selected_backend) lb_backend_connection_end(cnx->selected_backend, 0, 0);
        buffer_pool_free(buf->base, buf->len);
        freeUnhandledConnection(cnx);
        return;
    }
    cnx->timeout_timer.data = cnx;
    ret = uv_timer_start(&cnx->timeout_timer, udp_timeout_cb, srv->serverTimeout * 1000, 0);
    if (ret != 0) {
        logErrorConn(cnx, "uv_timer_start error: %s\n", uv_strerror(ret));
        if (cnx->selected_backend) lb_backend_connection_end(cnx->selected_backend, 0, 0);
        uv_close((uv_handle_t*)&cnx->timeout_timer, handle_close_cb);
        buffer_pool_free(buf->base, buf->len);
        return;
    }
    cnx->timer_initialized = 1;

    /* Create local UDP socket for backend */
    ret = uv_udp_init(main_loop, &cnx->local_uv_handle.udp);
    if (ret != 0) {
        logErrorConn(cnx, "uv_udp_init error: %s\n", uv_strerror(ret));
        if (cnx->selected_backend) lb_backend_connection_end(cnx->selected_backend, 0, 0);
        cnx->timer_closing = 1;
        uv_close((uv_handle_t*)&cnx->timeout_timer, handle_close_cb);
        buffer_pool_free(buf->base, buf->len);
        return;
    }
    cnx->local_handle_type = UV_UDP;
    cnx->local_handle_initialized = 1;
    cnx->local_uv_handle.udp.data = cnx;

    cnx->local.family = backend_addr->ai_family;
    cnx->local.protocol = IPPROTO_UDP;
    cnx->local.totalBytesIn = cnx->local.totalBytesOut = 0;

    /* Bind socket - required to get fd for buffer size setting */
    if (backend_source) {
        ret = uv_udp_bind(&cnx->local_uv_handle.udp, backend_source->ai_addr, 0);
    } else {
        struct sockaddr_storage any_addr;
        memset(&any_addr, 0, sizeof(any_addr));
        if (backend_addr->ai_family == AF_INET6) {
            struct sockaddr_in6 *a = (struct sockaddr_in6 *)&any_addr;
            a->sin6_family = AF_INET6;
        } else {
            struct sockaddr_in *a = (struct sockaddr_in *)&any_addr;
            a->sin_family = AF_INET;
        }
        ret = uv_udp_bind(&cnx->local_uv_handle.udp, (struct sockaddr *)&any_addr, 0);
    }
    if (ret != 0)
        logErrorConn(cnx, "UDP bind error: %s\n", uv_strerror(ret));

    set_socket_buffer_sizes((uv_handle_t *)&cnx->local_uv_handle.udp);

    /* Extract fd */
    uv_os_fd_t local_fd = INVALID_SOCKET;
    uv_fileno((uv_handle_t*)&cnx->local_uv_handle.udp, &local_fd);
    cnx->local.fd = local_fd;

    /* Start receiving on local socket */
    ret = uv_udp_recv_start(&cnx->local_uv_handle.udp, alloc_buffer_udp_server_cb, udp_local_recv_cb);
    if (ret != 0) {
        logErrorConn(cnx, "uv_udp_recv_start (local) error: %s\n", uv_strerror(ret));
        handleClose(cnx, &cnx->local, &cnx->remote);
        buffer_pool_free(buf->base, buf->len);
        return;
    }

    /* Update statistics for initial data */
    cnx->remote.totalBytesIn += nread;

    /* Send initial data to backend - udp_send_to_backend takes ownership of buf->base */
    udp_send_to_backend(cnx, buf->base, (int)nread, buf->len);

    logEvent(cnx, srv, logOpened);
    stats_connection_accepted(IPPROTO_UDP);

    /* Add to both hash table and LRU list */
    hash_insert_udp_connection(cnx);
    lru_insert_head(srv, cnx);

    /* Increment UDP connection count for this forwarding rule */
    ((ServerInfo*)srv)->udp_connection_count++;
}

static void handleClose(ConnectionInfo *cnx, Socket *socket, Socket *other_socket)
{
    /* Finalize stats on first call (handleClose may be called twice, once per socket) */
    int logReason = (socket == &cnx->local) ? logLocalClosedFirst : logRemoteClosedFirst;
    finalizeConnection(cnx, logReason);

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

    /* Close connect timer if active */
    if (cnx->connect_timer_initialized && !cnx->connect_timer_closing && !uv_is_closing((uv_handle_t*)&cnx->connect_timer)) {
        uv_timer_stop(&cnx->connect_timer);
        cnx->connect_timer_closing = 1;
        uv_close((uv_handle_t*)&cnx->connect_timer, handle_close_cb);
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

static int checkConnectionAllowedAddr(struct sockaddr_storage const *addr, ServerInfo const *srv)
{
    char addressText[NI_MAXHOST];
    int gni_ret = getnameinfo((struct sockaddr *)addr, sizeof(*addr),
        addressText, sizeof(addressText), NULL, 0, NI_NUMERICHOST);
    if (gni_ret != 0) {
        logError("getnameinfo failed: %s\n", gai_strerror(gni_ret));
        return logDenied;
    }

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
    if (!good)
        return logNotAllowed;
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
            if (match(addressText, allRules[srv->rulesStart + j].pattern)) {
                good = 1;
                break;
            }
        }
    }
    if (!good)
        return logNotAllowed;
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

static int checkConnectionAllowed(ConnectionInfo const *cnx)
{
    return checkConnectionAllowedAddr(&cnx->remoteAddress, cnx->server);
}

#if !_WIN32
RETSIGTYPE hup(int s)
{
    (void)s;

    /* Ignore if reload is already in progress */
    if (config_reload_pending)
        return;

    logInfo("received SIGHUP, reloading configuration...\n");
    /* Stop stats timers before reload */
    stats_stop_timers();
    /* Set flag - readConfiguration() will be called after all handles close */
    config_reload_pending = 1;
    /* Clear old configuration - this starts async close of server handles */
    clearConfiguration();
}
#endif /* _WIN32 */

/* Debug: walk all handles and print their type/state */
static void debug_walk_cb(uv_handle_t* handle, void* arg)
{
    int *count = (int*)arg;
    const char *type_name = uv_handle_type_name(handle->type);
    if (!type_name)
        type_name = "unknown";

    logDebug("  handle %d: type=%s, closing=%d, data=%p\n", *count, type_name, uv_is_closing(handle), handle->data);
    (*count)++;
}

/* Signal handle close callback - called when signal handle finishes closing */
static void signal_handle_close_cb(uv_handle_t* handle)
{
    logDebug("signal handle close callback\n");
    (void)handle;
    /* Nothing to do - just allows the close to complete properly */
}

RETSIGTYPE quit(int s)
{
    (void)s;

    logInfo("forced quit - closing connections gracefully\n");

    /* Stop and close signal handlers to allow loop to exit cleanly */
    uv_signal_stop(&sighup_handle);
    uv_signal_stop(&sigint_handle);
    uv_signal_stop(&sigterm_handle);
    uv_signal_stop(&sigpipe_handle);
    uv_close((uv_handle_t*)&sighup_handle, signal_handle_close_cb);
    uv_close((uv_handle_t*)&sigint_handle, signal_handle_close_cb);
    uv_close((uv_handle_t*)&sigterm_handle, signal_handle_close_cb);
    uv_close((uv_handle_t*)&sigpipe_handle, signal_handle_close_cb);

    /* Stop and close stats timers */
    stats_shutdown();

    /* Close buffer pool trim timer (keeps loop alive if not closed) */
    buffer_pool_close_timer();

    /* Close all server listeners (stops accepting new connections) */
    clearConfiguration();

    /* Close backend DNS refresh timers (keeps loop alive if not closed) */
    if (usingYamlConfig && yamlRules) {
        for (int r = 0; r < yamlRulesCount; r++) {
            RuleInfo *rule = &yamlRules[r];
            for (int b = 0; b < rule->backend_count; b++) {
                BackendInfo *backend = &rule->backends[b];
                if (backend->dns_timer_initialized && !backend->dns_timer_closing) {
                    backend->dns_timer_closing = 1;
                    uv_timer_stop(&backend->dns_timer);
                    uv_close((uv_handle_t*)&backend->dns_timer, NULL);
                }
            }
        }
    }

    /* Close all active connection handles (iterate carefully as list may be modified) */
    ConnectionInfo *cnx = connectionListHead;
    while (cnx) {
        ConnectionInfo *next = cnx->next;  /* Save next before async close */

        /* Close local handle if initialized and not already closing */
        if (cnx->local_handle_initialized && !cnx->local_handle_closing) {
            cnx->local_handle_closing = 1;
            if (cnx->local_handle_type == UV_TCP) {
                uv_close((uv_handle_t*)&cnx->local_uv_handle.tcp, NULL);
            } else if (cnx->local_handle_type == UV_UDP) {
                uv_close((uv_handle_t*)&cnx->local_uv_handle.udp, NULL);
            } else if (cnx->local_handle_type == UV_NAMED_PIPE) {
                uv_close((uv_handle_t*)&cnx->local_uv_handle.pipe, NULL);
            }
        }

        /* Close remote handle if initialized and not already closing */
        if (cnx->remote_handle_initialized && !cnx->remote_handle_closing) {
            cnx->remote_handle_closing = 1;
            if (cnx->remote_handle_type == UV_TCP) {
                uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, NULL);
            } else if (cnx->remote_handle_type == UV_UDP) {
                uv_close((uv_handle_t*)&cnx->remote_uv_handle.udp, NULL);
            } else if (cnx->remote_handle_type == UV_NAMED_PIPE) {
                uv_close((uv_handle_t*)&cnx->remote_uv_handle.pipe, NULL);
            }
        }

        /* Close timeout timer if initialized and not already closing */
        if (cnx->timer_initialized && !cnx->timer_closing) {
            cnx->timer_closing = 1;
            uv_close((uv_handle_t*)&cnx->timeout_timer, NULL);
        }

        cnx = next;
    }

    /* Run event loop to process close callbacks
     * Hybrid approach: UV_RUN_NOWAIT (fast) + periodic UV_RUN_ONCE (ensures close callbacks) */
    logDebug("processing close callbacks...\n");
    int iterations = 0;

    while (uv_loop_alive(main_loop) && iterations < RINETD_CLEANUP_MAX_ITERATIONS) {
        /* Use UV_RUN_ONCE to wait for events (including close callbacks)
         * This ensures close callbacks are processed without busy-waiting */
        uv_run(main_loop, UV_RUN_ONCE);

        iterations++;

        /* Diagnostic logging */
        if (iterations % 10 == 0) {
            uv_metrics_t metrics;
            uv_metrics_info(main_loop, &metrics);
            logDebug("closing: iteration %d -- %lld events -- alive=%d -- handles=%u\n",
                     iterations, metrics.events_waiting, uv_loop_alive(main_loop),
                     main_loop->active_handles);
        }
    }

    if (iterations >= RINETD_CLEANUP_MAX_ITERATIONS) {
        logWarning("some handles may not have closed cleanly\n");
        /* Debug: enumerate all remaining handles */
        int handle_count = 0;
        logDebug("enumerating remaining handles:\n");
        uv_walk(main_loop, debug_walk_cb, &handle_count);
        logDebug("total handles: %d\n", handle_count);
    } else {
        logDebug("all handles closed successfully\n");
    }

    /* Flush the log before closing */
    if (logFd != -1) {
        uv_fs_t req;
        int ret = uv_fs_close(NULL, &req, logFd, NULL);
        uv_fs_req_cleanup(&req);
        if (ret < 0) {
            /* Don't use logWarning here - log file is being closed */
            fprintf(stderr, "uv_fs_close failed during shutdown: %s\n", uv_strerror(ret));
        }
        logFd = -1;
    }

    /* Shutdown buffer pool */
    buffer_pool_shutdown();

    /* Cleanup UDP hash table */
    cleanup_udp_hash_table();

    /* Cleanup YAML rules */
    cleanup_yaml_rules();

    /* Close the event loop */
    uv_loop_close(main_loop);

    logInfo("graceful shutdown complete\n");
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

/* Initialize servers from YAML rules (called after yaml_config_parse) */
void initializeFromYamlRules(void)
{
    if (!usingYamlConfig || !yamlRules)
        return;

    /* Collect all listeners from all rules into seInfo array */
    for (int r = 0; r < yamlRulesCount; r++) {
        RuleInfo *rule = &yamlRules[r];

        for (int l = 0; l < rule->listener_count; l++) {
            ServerInfo *srv_original = rule->listeners[l];

            /* Link listener to its rule */
            srv_original->rule = rule;

            /* Copy access rules reference */
            srv_original->rulesStart = rule->rulesStart;
            srv_original->rulesCount = rule->rulesCount;

            /* Add to global seInfo array */
            seInfo = (ServerInfo *)realloc(seInfo, sizeof(ServerInfo) * (seTotal + 1));
            if (!seInfo) {
                logError("realloc failed for ServerInfo\n");
                exit(1);
            }

            /* Copy ServerInfo (but keep pointer to rule) */
            seInfo[seTotal] = *srv_original;
            seInfo[seTotal].rule = rule;

            /* Update the rule's listener pointer to point to seInfo entry */
            rule->listeners[l] = &seInfo[seTotal];

            /* Free the original ServerInfo shell (fields now owned by seInfo) */
            free(srv_original);

            seTotal++;
        }

        logInfo("Rule '%s': %d listener(s), %d backend(s), algorithm=%s\n",
                rule->name ? rule->name : "unnamed",
                rule->listener_count,
                rule->backend_count,
                lb_algorithm_name(rule->algorithm));
    }
}

static char const *findConfigFile(void)
{
    /* Check for config files in order: .yaml, .yml, .conf */
    static char const *candidates[] = {
        RINETD_CONFIG_FILE_YAML,
        RINETD_CONFIG_FILE_YML,
        RINETD_CONFIG_FILE_CONF,
        NULL
    };

    for (int i = 0; candidates[i] != NULL; i++) {
        if (access(candidates[i], R_OK) == 0) {
            return candidates[i];
        }
    }

    /* None found - return the legacy default (will fail with clear error message) */
    return RINETD_CONFIG_FILE_CONF;
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
                conf_file_explicit = 1;
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
                    "  -c, --conf-file FILE   read configuration from FILE\n"
                    "  -d, --debug            enable debug logging\n"
                    "  -f, --foreground       do not run in the background\n"
                    "  -h, --help             display this help\n"
                    "  -v, --version          display version number\n\n"
                    "Without -c, searches for config in order:\n"
                    "  " RINETD_CONFIG_FILE_YAML "\n"
                    "  " RINETD_CONFIG_FILE_YML "\n"
                    "  " RINETD_CONFIG_FILE_CONF "\n\n"
                    "Most options are controlled through the configuration file.\n"
                    "See the rinetd-uv(8) manpage for more information.\n");
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
