/* Copyright © 1997—1999 Thomas Boutell <boutell@boutell.com>
                         and Boutell.Com, Inc.
             © 2003—2021 Sam Hocevar <sam@hocevar.net>
             © 2026 Marcin Gryszkalis <mg@fork.pl>

   This software is released for free use under the terms of
   the GNU Public License, version 2 or higher. NO WARRANTY
   IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK. */

#pragma once

#include <time.h>
#include <stdint.h>
#include <sys/types.h>
#include <uv.h>

/* Socket type compatibility */
#if _WIN32
#   include <winsock2.h>
#else
#   ifndef SOCKET
#       define SOCKET int
#   endif
#   ifndef INVALID_SOCKET
#       define INVALID_SOCKET (-1)
#   endif
#endif

typedef enum _rule_type ruleType;
enum _rule_type {
    allowRule,
    denyRule,
};

/* Log event codes */
typedef enum {
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
} LogEventCode;

/* Load balancing algorithm types */
typedef enum _lb_algorithm LbAlgorithm;
enum _lb_algorithm {
    LB_NONE = 0,
    LB_ROUND_ROBIN,
    LB_LEAST_CONN,
    LB_RANDOM,
    LB_IP_HASH,
    LB_INVALID = -1
};

typedef struct _rule Rule;
struct _rule
{
    char *pattern;
    ruleType type;
};

/* Forward declarations */
typedef struct _connection_info ConnectionInfo;
typedef struct _server_info ServerInfo;
typedef struct _rule_info RuleInfo;
typedef struct _backend_info BackendInfo;
typedef struct _affinity_table AffinityTable;

/* Backend information for load balancing */
struct _backend_info {
    /* Human-readable name for status/stats output (no sensitive data exposure) */
    char *name;

    /* Address info (mutually exclusive with unixPath) */
    struct addrinfo *addrInfo;
    int addrInfo_is_dup;                /* 1 if addrInfo from dup_single_addrinfo (free with free()),
                                           0 if from getaddrinfo (free with freeaddrinfo()) */
    char *host;
    char *port;
    int protocol;                       /* IPPROTO_TCP or IPPROTO_UDP */

    /* Unix socket (mutually exclusive with host/port) */
    char *unixPath;
    int isAbstract;

    /* Outbound source address */
    struct addrinfo *sourceAddrInfo;
    int sourceAddrInfo_is_dup;           /* 1 if from dup_single_addrinfo, 0 if from getaddrinfo */

    /* Health state */
    int healthy;                        /* 1=healthy, 0=unhealthy */
    int consecutive_failures;
    time_t last_failure_time;
    time_t next_retry_time;

    /* Statistics */
    uint64_t total_connections;
    uint64_t active_connections;
    uint64_t total_bytes_in;
    uint64_t total_bytes_out;

    /* Weight for weighted algorithms */
    int weight;                         /* Configured weight (default: 1) */
    int64_t current_weight;              /* For smooth weighted round-robin */
    int effective_weight;               /* Weight adjusted by health */

    /* DNS refresh (per-backend override) */
    uv_getaddrinfo_t *dns_req;
    uv_timer_t dns_timer;
    int dns_timer_initialized;
    int dns_timer_closing;
    int dns_refresh_period;             /* 0 = use rule/global default */
    char *host_saved;                   /* Hostname for async resolution */
    char *port_saved;                   /* Port for async resolution */

    /* DNS multi-IP expansion tracking */
    char *dns_parent_name;              /* Original hostname (NULL for explicit backends) */
    int is_implicit;                    /* 1 if auto-created from DNS multi-IP, 0 if explicit */
    int dns_ip_index;                   /* Index within DNS result set (0, 1, 2...) */
};

/* Rule information for YAML config (replaces ServerInfo for LB rules) */
struct _rule_info {
    char *name;                         /* Rule name from YAML */

    /* Listeners (can be multiple for many:many) */
    ServerInfo **listeners;             /* Array of listening sockets */
    int listener_count;
    int listener_capacity;

    /* Backends */
    BackendInfo *backends;
    int backend_count;
    int backend_capacity;

    /* Load balancing state */
    LbAlgorithm algorithm;
    uint64_t rr_index;                  /* Round-robin counter (uint64 to avoid overflow) */
    uint64_t total_weight;              /* Sum of all backend weights (uint64 to avoid overflow) */

    /* Health checking configuration */
    int health_threshold;               /* Failures before marking unhealthy */
    int recovery_timeout;               /* Seconds before retry after marking unhealthy */
    int healthy_count;                  /* Number of currently healthy backends */

    /* Affinity (session persistence) */
    AffinityTable *affinity_table;
    int affinity_ttl;                   /* Seconds, 0 = disabled */
    int affinity_max_entries;

    /* Access control */
    int rulesStart;                     /* Offset into global allRules array */
    int rulesCount;                     /* Number of allow/deny rules */

    /* Per-rule options */
    int timeout;                        /* UDP timeout in seconds */
    int keepalive;                      /* TCP keepalive: 1=enabled, 0=disabled */
    int connect_timeout;                /* Backend connect timeout in seconds (0 = OS default) */
    int dns_refresh_period;             /* Default DNS refresh for backends */
    int socketMode;                     /* Unix socket file permissions (octal, 0 = use default) */
};

struct _server_info {
    SOCKET fd;

    /* libuv handles for event-driven I/O */
    union {
        uv_tcp_t tcp;
        uv_udp_t udp;
        uv_pipe_t pipe;  /* Unix domain socket */
    } uv_handle;
    uv_handle_type handle_type;  /* UV_TCP, UV_UDP, or UV_NAMED_PIPE */
    int handle_initialized;      /* Track if uv_*_init() called */

    /* In network order, for network purposes */
    struct addrinfo *fromAddrInfo, *toAddrInfo, *sourceAddrInfo;

    /* Unix domain socket paths (NULL if not Unix socket) */
    char *fromUnixPath;     /* Bind path */
    char *toUnixPath;       /* Connect path */
    int fromIsAbstract;     /* 1 if abstract namespace (Linux-only) */
    int toIsAbstract;       /* 1 if abstract namespace */
    mode_t socketMode;      /* File mode for Unix socket (0 = use default) */

    /* In ASCII, for logging purposes */
    char *fromHost, *toHost;

    /* Offset and count into list of allow and deny rules. Any rules
        prior to globalAllowRules and globalDenyRules are global rules. */
    int rulesStart, rulesCount;
    /* Timeout for UDP traffic before we consider the connection
        was dropped by the remote host. */
    int serverTimeout;
    /* Track number of active UDP connections for this forwarding rule
       to prevent file descriptor exhaustion (uint64 to avoid overflow) */
    uint64_t udp_connection_count;
    /* UDP LRU list for O(1) eviction */
    ConnectionInfo *udp_lru_head;   /* Most recently used (front) */
    ConnectionInfo *udp_lru_tail;   /* Least recently used (back) - evict this */
    /* TCP keepalive: 1 = enabled (default), 0 = disabled */
    int keepalive;
    /* Backend connect timeout in seconds (0 = OS default) */
    int connectTimeout;

    /* DNS refresh timer and state */
    uv_timer_t dns_refresh_timer;        /* Periodic refresh timer */
    int dns_refresh_period;               /* Seconds between refreshes (0 = disabled) */
    int dns_timer_initialized;            /* Track if timer created */
    int dns_timer_closing;                /* Track if timer close in progress */
    int consecutive_failures;             /* Backend connection failure counter */
    uv_getaddrinfo_t *dns_req;            /* Pending async DNS request */
    char *toHost_saved;                   /* Hostname for async resolution */
    char *toPort_saved;                   /* Port for async resolution */
    int toProtocol_saved;                 /* Protocol for async resolution */

    /* Load balancing: link to parent rule (NULL for legacy config) */
    RuleInfo *rule;
};

typedef struct _socket Socket;
struct _socket
{
    SOCKET fd;
    int family, protocol;
    /* Statistics only - no buffer management */
    uint64_t totalBytesIn, totalBytesOut;
};

/* TCP Write request data - holds buffer and connection info */
typedef struct _write_req WriteReq;
struct _write_req
{
    uv_write_t req;
    ConnectionInfo *cnx;
    char *buffer;
    size_t buffer_size;    /* Bytes being written (for statistics) */
    size_t alloc_size;     /* Allocated buffer size (for buffer pool) */
    Socket *socket;     /* Which socket this write is for (local or remote) */
};

/* UDP Send request data - holds buffer and addressing info */
typedef struct _udp_send_req UdpSendReq;
struct _udp_send_req
{
    uv_udp_send_t req;
    ConnectionInfo *cnx;
    char *buffer;
    size_t buffer_size;    /* Bytes being sent (for statistics) */
    size_t alloc_size;     /* Allocated buffer size (for buffer pool) */
    struct sockaddr_storage dest_addr;  /* Destination address for this send */
    int is_to_backend;  /* 1 if sending to backend, 0 if sending to client */
};
struct _connection_info
{
    Socket remote, local;

    /* libuv handles for active connections */
    union {
        uv_tcp_t tcp;
        uv_udp_t udp;
        uv_pipe_t pipe;  /* Unix domain socket */
    } local_uv_handle;
    uv_handle_type local_handle_type;  /* UV_TCP, UV_UDP, or UV_NAMED_PIPE */
    int local_handle_initialized;
    int local_handle_closing;  /* Set when uv_close() called, cleared in callback */

    union {
        uv_tcp_t tcp;
        uv_udp_t udp;
        uv_pipe_t pipe;  /* Unix domain socket */
    } remote_uv_handle;
    uv_handle_type remote_handle_type;  /* UV_TCP, UV_UDP, or UV_NAMED_PIPE */
    int remote_handle_initialized;
    int remote_handle_closing;  /* Set when uv_close() called, cleared in callback */

    /* Half-close state for graceful shutdown (TCP/Unix streams only) */
    int local_read_eof;         /* Received EOF reading from local (backend) */
    int remote_read_eof;        /* Received EOF reading from remote (client) */
    int local_shutdown_sent;    /* Called uv_shutdown() on local */
    int remote_shutdown_sent;   /* Called uv_shutdown() on remote */
    uv_shutdown_t local_shutdown_req;   /* Shutdown request for local */
    uv_shutdown_t remote_shutdown_req;  /* Shutdown request for remote */

    /* libuv timer for UDP timeouts */
    uv_timer_t timeout_timer;
    int timer_initialized;
    int timer_closing;  /* Set when uv_close() called, cleared in callback */

    /* libuv timer for backend TCP connect timeout */
    uv_timer_t connect_timer;
    int connect_timer_initialized;
    int connect_timer_closing;

    struct sockaddr_storage remoteAddress;
    time_t remoteTimeout;
    int coClosing;
    LogEventCode coLog;
    ServerInfo const *server; // only useful for logEvent

    /* Server info cached for logging (survives server reloads) */
    char *log_fromHost;
    uint16_t log_fromPort;
    char *log_toHost;
    uint16_t log_toPort;

    /* Doubly-linked list for tracking active connections */
    struct _connection_info *prev;
    struct _connection_info *next;

    /* UDP-specific fields for hash table and LRU */
    struct _connection_info *hash_next;     /* Next in hash bucket chain */
    struct _connection_info *lru_prev;      /* Previous in LRU list (per-server) */
    struct _connection_info *lru_next;      /* Next in LRU list (per-server) */

    /* Load balancing: selected backend for this connection (NULL for legacy) */
    BackendInfo *selected_backend;
    RuleInfo *rule;                         /* Parent rule (for stats updates) */
};

/* Option parsing */

typedef struct _rinetd_options RinetdOptions;
struct _rinetd_options
{
    char const *conf_file;
    int foreground;
    int debug;
};

