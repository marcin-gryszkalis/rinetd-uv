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
};

typedef struct _socket Socket;
struct _socket
{
	SOCKET fd;
	int family, protocol;
	/* recv: received on this socket
		sent: sent through this socket from the other buffer */
	int recvPos, sentPos;
	uint64_t totalBytesIn, totalBytesOut;
	char *buffer;
};

typedef struct _connection_info ConnectionInfo;
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

	/* Reference counting for pending operations */
	int pending_writes;  /* Number of pending write operations */
	int local_write_in_progress;  /* Flag: write in progress on local socket */
	int remote_write_in_progress;  /* Flag: write in progress on remote socket */

	/* Flow control timing diagnostics */
	uint64_t local_read_stopped_time;   /* hrtime when local reading was stopped */
	uint64_t remote_read_stopped_time;  /* hrtime when remote reading was stopped */
	int local_read_stopped;             /* Flag: local reading is stopped */
	int remote_read_stopped;            /* Flag: remote reading is stopped */

	/* Write timing diagnostics */
	uint64_t local_write_start_time;    /* hrtime when local write started */
	uint64_t remote_write_start_time;   /* hrtime when remote write started */

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

