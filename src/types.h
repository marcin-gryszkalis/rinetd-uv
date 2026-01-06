/* Copyright © 1997—1999 Thomas Boutell <boutell@boutell.com>
                         and Boutell.Com, Inc.
             © 2003—2021 Sam Hocevar <sam@hocevar.net>

   This software is released for free use under the terms of
   the GNU Public License, version 2 or higher. NO WARRANTY
   IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK. */

#pragma once

#include <time.h>
#include <stdint.h>
#include <uv.h>

typedef enum _rule_type ruleType;
enum _rule_type {
	allowRule,
	denyRule,
};

typedef struct _rule Rule;
struct _rule
{
	char *pattern;
	ruleType type;
};

typedef struct _server_info ServerInfo;
struct _server_info {
	SOCKET fd;

	/* libuv handles for event-driven I/O */
	union {
		uv_tcp_t tcp;
		uv_udp_t udp;
	} uv_handle;
	uv_handle_type handle_type;  /* UV_TCP or UV_UDP */
	int handle_initialized;      /* Track if uv_*_init() called */

	/* In network order, for network purposes */
	struct addrinfo *fromAddrInfo, *toAddrInfo, *sourceAddrInfo;

	/* In ASCII, for logging purposes */
	char *fromHost, *toHost;

	/* Offset and count into list of allow and deny rules. Any rules
		prior to globalAllowRules and globalDenyRules are global rules. */
	int rulesStart, rulesCount;
	/* Timeout for UDP traffic before we consider the connection
		was dropped by the remote host. */
	int serverTimeout;
	/* Track number of active UDP connections for this forwarding rule
	   to prevent file descriptor exhaustion */
	int udp_connection_count;
};

typedef struct _socket Socket;
struct _socket
{
	SOCKET fd;
	int family, protocol;
	/* Statistics only - no buffer management */
	uint64_t totalBytesIn, totalBytesOut;
};

/* Forward declaration for write request */
typedef struct _connection_info ConnectionInfo;

/* TCP Write request data - holds buffer and connection info */
typedef struct _write_req WriteReq;
struct _write_req
{
	uv_write_t req;
	ConnectionInfo *cnx;
	char *buffer;
	int buffer_size;
	Socket *socket;  /* Which socket this write is for (local or remote) */
};

/* UDP Send request data - holds buffer and addressing info */
typedef struct _udp_send_req UdpSendReq;
struct _udp_send_req
{
	uv_udp_send_t req;
	ConnectionInfo *cnx;
	char *buffer;
	int buffer_size;
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
	} local_uv_handle;
	uv_handle_type local_handle_type;
	int local_handle_initialized;
	int local_handle_closing;  /* Set when uv_close() called, cleared in callback */

	union {
		uv_tcp_t tcp;
		uv_udp_t udp;
	} remote_uv_handle;
	uv_handle_type remote_handle_type;
	int remote_handle_initialized;
	int remote_handle_closing;  /* Set when uv_close() called, cleared in callback */

	/* libuv timer for UDP timeouts */
	uv_timer_t timeout_timer;
	int timer_initialized;
	int timer_closing;  /* Set when uv_close() called, cleared in callback */

	struct sockaddr_storage remoteAddress;
	time_t remoteTimeout;
	int coClosing;
	int coLog;
	ServerInfo const *server; // only useful for logEvent

	/* Linked list for tracking active connections */
	struct _connection_info *next;
};

/* Option parsing */

typedef struct _rinetd_options RinetdOptions;
struct _rinetd_options
{
	char const *conf_file;
	int foreground;
};

