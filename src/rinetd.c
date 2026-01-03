/* Copyright © 1997—1999 Thomas Boutell <boutell@boutell.com>
                         and Boutell.Com, Inc.
             © 2003—2021 Sam Hocevar <sam@hocevar.net>

   This software is released for free use under the terms of
   the GNU Public License, version 2 or higher. NO WARRANTY
   IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK. */

#if HAVE_CONFIG_H
#	include <config.h>
#endif

#ifndef RETSIGTYPE
#	define RETSIGTYPE void
#endif

#ifdef _MSC_VER
#	include <malloc.h>
#endif

#if _WIN32
#	include "getopt.h"
#else
#	include <getopt.h>
#	include <unistd.h>
#	include <sys/time.h>
#	include <syslog.h>
#endif /* _WIN32 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <syslog.h>

#ifdef DEBUG
#	define PERROR perror
#else
#	define PERROR(x)
#endif /* DEBUG */

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

/* Connection management - now using dynamic allocation instead of pool */
static ConnectionInfo *connectionListHead = NULL;
static int activeConnections = 0;
static int totalConnections = 0;  /* For statistics */

/* On Windows, the maximum number of file descriptors in an fd_set
	is simply FD_SETSIZE and the first argument to select() is
	ignored, so maxfd will never change. */
#ifdef _WIN32
int const maxfd = 0;
#else
int maxfd = 0;
#endif

/* libuv event loop */
static uv_loop_t *main_loop = NULL;

/* libuv signal handlers */
static uv_signal_t sighup_handle, sigint_handle, sigterm_handle, sigpipe_handle;

char *logFileName = NULL;
char *pidLogFileName = NULL;
int logFormatCommon = 0;
FILE *logFile = NULL;

char const *logMessages[] = {
	"unknown-error",
	"done-local-closed",
	"done-remote-closed",
	"accept-failed -",
	"local-socket-failed -",
	"local-bind-failed -",
	"local-connect-failed -",
	"opened",
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
	RINETD_CONFIG_FILE,
	0,
};

static int forked = 0;

static void handleUdpRead(ConnectionInfo *cnx, char const *buffer, int bytes);
static void handleClose(ConnectionInfo *cnx, Socket *socket, Socket *other_socket);
static ConnectionInfo *allocateConnection(void);
static int checkConnectionAllowed(ConnectionInfo const *cnx);

static int readArgs (int argc, char **argv, RinetdOptions *options);
static void clearConfiguration(void);
static void readConfiguration(char const *file);

static void registerPID(char const *pid_file_name);
static void logEvent(ConnectionInfo const *cnx, ServerInfo const *srv, int result);
static struct tm *get_gmtoff(int *tz);

/* Signal handlers */
#if !HAVE_SIGACTION && !_WIN32
static RETSIGTYPE plumber(int s);
#endif
#if !_WIN32
static RETSIGTYPE hup(int s);
#endif
static RETSIGTYPE quit(int s);

/* libuv functions */
static void signal_cb(uv_signal_t *handle, int signum);
static void startServerListening(ServerInfo *srv);
static void server_handle_close_cb(uv_handle_t *handle);


int main(int argc, char *argv[])
{
#ifdef _WIN32
	WSADATA wsaData;
	int result = WSAStartup(MAKEWORD(1, 1), &wsaData);
	if (result != 0) {
		fprintf(stderr, "Your computer was not connected "
			"to the Internet at the time that "
			"this program was launched, or you "
			"do not have a 32-bit "
			"connection to the Internet.");
		exit(1);
	}
#else
	openlog("rinetd", LOG_PID, LOG_DAEMON);
#endif

	readArgs(argc, argv, &options);

	if (!options.foreground) {
#if HAVE_DAEMON && !DEBUG
		if (daemon(0, 0) != 0) {
			exit(0);
		}
		forked = 1;
#elif HAVE_FORK && !DEBUG
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
	/* SIGPIPE - ignore */
	uv_signal_init(main_loop, &sigpipe_handle);
	/* Note: libuv doesn't have SIG_IGN equivalent, so we use callback that does nothing */

	/* SIGHUP - reload configuration */
	uv_signal_init(main_loop, &sighup_handle);
	uv_signal_start(&sighup_handle, signal_cb, SIGHUP);
#endif

	/* SIGINT and SIGTERM - graceful shutdown */
	uv_signal_init(main_loop, &sigint_handle);
	uv_signal_start(&sigint_handle, signal_cb, SIGINT);

	uv_signal_init(main_loop, &sigterm_handle);
	uv_signal_start(&sigterm_handle, signal_cb, SIGTERM);

	/* Start libuv event handling for all servers */
	for (int i = 0; i < seTotal; ++i) {
		startServerListening(&seInfo[i]);
	}

	logInfo("starting redirections...\n");

	/* Run the event loop */
	while (1) {
		int ret = uv_run(main_loop, UV_RUN_DEFAULT);
		if (ret == 0) {
			/* No more active handles/requests, but we want to keep running */
			/* This shouldn't normally happen since servers are always listening */
			logError("event loop finished unexpectedly\n");
			break;
		}
	}

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
		fprintf(stderr, "rinetd error: ");
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
		fprintf(stderr, "rinetd: ");
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
			freeaddrinfo(srv->fromAddrInfo);
			freeaddrinfo(srv->toAddrInfo);
			if (srv->sourceAddrInfo) {
				freeaddrinfo(srv->sourceAddrInfo);
			}
		}
	}
	/* If no handles to close, free seInfo immediately */
	if (!any_handles_to_close) {
		free(seInfo);
		seInfo = NULL;
		seTotal = 0;
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
	if (logFile) {
		fclose(logFile);
		logFile = NULL;
	}
	if (logFileName) {
		logFile = fopen(logFileName, "a+");
		if (logFile) {
			setvbuf(logFile, NULL, _IONBF, 0);
		} else {
			logError("could not open %s to append (%m).\n",
				logFileName);
		}
	}
}

void addServer(char *bindAddress, char *bindPort, int bindProtocol,
               char *connectAddress, char *connectPort, int connectProtocol,
               int serverTimeout, char *sourceAddress)
{
	ServerInfo si = {
		.fromHost = strdup(bindAddress),
		.toHost = strdup(connectAddress),
		.serverTimeout = serverTimeout,
	};

	/* Make a server socket */
	struct addrinfo *ai;
	int ret = getAddrInfoWithProto(bindAddress, bindPort, bindProtocol, &ai);
	if (ret != 0) {
		exit(1);
	}

	si.fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (si.fd == INVALID_SOCKET) {
		logError("couldn't create server socket! (%m)\n");
		freeaddrinfo(ai);
		exit(1);
	}

	int tmp = 1;
	setsockopt(si.fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&tmp, sizeof(tmp));

	if (bind(si.fd, ai->ai_addr, ai->ai_addrlen) == SOCKET_ERROR) {
		logError("couldn't bind to address %s port %s (%m)\n",
			bindAddress, bindPort);
		closesocket(si.fd);
		freeaddrinfo(ai);
		exit(1);
	}

	if (bindProtocol == IPPROTO_TCP) {
		if (listen(si.fd, RINETD_LISTEN_BACKLOG) == SOCKET_ERROR) {
			/* Warn -- don't exit. */
			logError("couldn't listen to address %s port %s (%m)\n",
				bindAddress, bindPort);
			/* XXX: check whether this is correct */
			closesocket(si.fd);
		}

		/* Make socket nonblocking in TCP mode only, otherwise
			we may miss some data. */
		setSocketDefaults(si.fd);
	}
	si.fromAddrInfo = ai;

	/* Resolve destination address. */
	ret = getAddrInfoWithProto(connectAddress, connectPort, connectProtocol, &ai);
	if (ret != 0) {
		freeaddrinfo(si.fromAddrInfo);
		closesocket(si.fd);
		exit(1);
	}
	si.toAddrInfo = ai;

	/* Resolve source address if applicable. */
	if (sourceAddress) {
		ret = getAddrInfoWithProto(sourceAddress, NULL, connectProtocol, &ai);
		if (ret != 0) {
			freeaddrinfo(si.fromAddrInfo);
			freeaddrinfo(si.toAddrInfo);
			exit(1);
		}
		si.sourceAddrInfo = ai;
	}

	/* Set up libuv handle type (actual initialization happens later) */
	si.handle_type = (bindProtocol == IPPROTO_TCP) ? UV_TCP : UV_UDP;
	si.handle_initialized = 0;

#ifndef _WIN32
	if (si.fd > maxfd) {
		maxfd = si.fd;
	}
#endif

	/* Allocate server info */
	seInfo = (ServerInfo *)realloc(seInfo, sizeof(ServerInfo) * (seTotal + 1));
	if (!seInfo) {
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

	/* Initialize all fields */
	memset(cnx, 0, sizeof(*cnx));

	/* Allocate buffers for both sockets */
	cnx->local.buffer = (char*)malloc(sizeof(char) * 2 * RINETD_BUFFER_SIZE);
	if (!cnx->local.buffer) {
		logError("malloc failed for connection buffers\n");
		free(cnx);
		return NULL;
	}
	cnx->remote.buffer = cnx->local.buffer + RINETD_BUFFER_SIZE;

	/* Initialize socket state */
	cnx->local.fd = INVALID_SOCKET;
	cnx->remote.fd = INVALID_SOCKET;
	cnx->local.recvPos = cnx->local.sentPos = 0;
	cnx->remote.recvPos = cnx->remote.sentPos = 0;
	cnx->local.totalBytesIn = cnx->local.totalBytesOut = 0;
	cnx->remote.totalBytesIn = cnx->remote.totalBytesOut = 0;

	/* Initialize handle state */
	cnx->local_handle_initialized = 0;
	cnx->remote_handle_initialized = 0;
	cnx->timer_initialized = 0;
	cnx->local_handle_closing = 0;
	cnx->remote_handle_closing = 0;
	cnx->timer_closing = 0;

	cnx->coClosing = 0;
	cnx->coLog = logUnknownError;

	/* Add to linked list */
	cnx->next = connectionListHead;
	connectionListHead = cnx;

	activeConnections++;
	totalConnections++;

	return cnx;
}

/* libuv callback forward declarations */
static void tcp_server_accept_cb(uv_stream_t *server, int status);
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
	}
	/* SIGPIPE is ignored (like SIG_IGN) */
}

/* Initialize and start libuv event handling for a server */
static void startServerListening(ServerInfo *srv)
{
	if (srv->handle_initialized) {
		return;  /* Already initialized */
	}

	/* Set data pointer to server info for callbacks */
	srv->uv_handle.tcp.data = srv;

	if (srv->handle_type == UV_TCP) {
		/* Initialize TCP handle and attach to existing socket */
		uv_tcp_init(main_loop, &srv->uv_handle.tcp);
		uv_tcp_open(&srv->uv_handle.tcp, srv->fd);

		/* Start listening for connections */
		int ret = uv_listen((uv_stream_t*)&srv->uv_handle.tcp,
		                    RINETD_LISTEN_BACKLOG, tcp_server_accept_cb);
		if (ret != 0) {
			logError("uv_listen() failed: %s\n", uv_strerror(ret));
			exit(1);
		}
	} else {  /* UV_UDP */
		/* Initialize UDP handle and attach to existing socket */
		uv_udp_init(main_loop, &srv->uv_handle.udp);
		uv_udp_open(&srv->uv_handle.udp, srv->fd);

		/* Start receiving datagrams */
		int ret = uv_udp_recv_start(&srv->uv_handle.udp,
		                            alloc_buffer_udp_server_cb, udp_server_recv_cb);
		if (ret != 0) {
			logError("uv_udp_recv_start() failed: %s\n", uv_strerror(ret));
			exit(1);
		}
	}

	srv->handle_initialized = 1;
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
	
	/* Close the underlying socket */
	if (srv->fd != INVALID_SOCKET) {
		closesocket(srv->fd);
		srv->fd = INVALID_SOCKET;
	}

	/* Free server resources */
	free(srv->fromHost);
	srv->fromHost = NULL;
	free(srv->toHost);
	srv->toHost = NULL;
	freeaddrinfo(srv->fromAddrInfo);
	srv->fromAddrInfo = NULL;
	freeaddrinfo(srv->toAddrInfo);
	srv->toAddrInfo = NULL;
	if (srv->sourceAddrInfo) {
		freeaddrinfo(srv->sourceAddrInfo);
		srv->sourceAddrInfo = NULL;
	}

	/* Check if all server handles are closed - if so, free seInfo */
	/* Note: This is called for each handle, so we need to check if all are done */
	if (!seInfo) {
		return;  /* Already freed */
	}
	
	int all_closed = 1;
	for (int i = 0; i < seTotal; ++i) {
		if (seInfo[i].handle_initialized || 
		    uv_is_closing((uv_handle_t*)&seInfo[i].uv_handle.tcp) ||
		    uv_is_closing((uv_handle_t*)&seInfo[i].uv_handle.udp)) {
			all_closed = 0;
			break;
		}
	}
	
	if (all_closed) {
		free(seInfo);
		seInfo = NULL;
		seTotal = 0;
	}
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
		/* Close local handle that was initialized but failed to connect */
		uv_close((uv_handle_t*)&cnx->local_uv_handle.tcp, handle_close_cb);
		/* Close remote handle */
		if (cnx->remote_handle_initialized) {
			uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
		}
		return;
	}

	/* Mark local handle as initialized now that connection succeeded */
	cnx->local_handle_initialized = 1;

	/* Extract fd for Socket struct */
	uv_os_fd_t fd;
	uv_fileno((uv_handle_t*)&cnx->local_uv_handle.tcp, &fd);
	cnx->local.fd = fd;

	/* Start reading from local (backend) */
	int ret = uv_read_start((uv_stream_t*)&cnx->local_uv_handle.tcp,
	                        alloc_buffer_cb, tcp_read_cb);
	if (ret != 0) {
		logError("uv_read_start (local) error: %s\n", uv_strerror(ret));
		handleClose(cnx, &cnx->local, &cnx->remote);
		return;
	}

	/* NOW start reading from remote (client) - backend is connected */
	ret = uv_read_start((uv_stream_t*)&cnx->remote_uv_handle.tcp,
	                    alloc_buffer_cb, tcp_read_cb);
	if (ret != 0) {
		logError("uv_read_start (remote) error: %s\n", uv_strerror(ret));
		handleClose(cnx, &cnx->local, &cnx->remote);
		return;
	}

	logEvent(cnx, cnx->server, logOpened);
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
		uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
		return;
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
	cnx->remote.recvPos = cnx->remote.sentPos = 0;
	cnx->remote.totalBytesIn = cnx->remote.totalBytesOut = 0;

	cnx->local.fd = INVALID_SOCKET;
	cnx->local.family = srv->toAddrInfo->ai_family;
	cnx->local.protocol = IPPROTO_TCP;
	cnx->local.recvPos = cnx->local.sentPos = 0;
	cnx->local.totalBytesIn = cnx->local.totalBytesOut = 0;

	cnx->coClosing = 0;
	cnx->coLog = logUnknownError;
	cnx->server = srv;
	cnx->timer_initialized = 0;

	/* Check access rules */
	int logCode = checkConnectionAllowed(cnx);
	if (logCode != logAllowed) {
		uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
		logEvent(cnx, srv, logCode);
		return;
	}

	/* Initialize local handle (backend connection) */
	uv_tcp_init(main_loop, &cnx->local_uv_handle.tcp);
	cnx->local_handle_type = UV_TCP;
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
		/* Close both handles - local was initialized but never connected */
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
		/* Close both handles - local was initialized but never connected */
		uv_close((uv_handle_t*)&cnx->local_uv_handle.tcp, handle_close_cb);
		uv_close((uv_handle_t*)&cnx->remote_uv_handle.tcp, handle_close_cb);
		return;
	}

	/* DON'T start reading from remote yet - wait for backend connection to complete */
	/* This will be done in tcp_connect_cb */
}

/* Buffer allocation callback for UDP server sockets */
static void alloc_buffer_udp_server_cb(uv_handle_t *handle, size_t suggested_size,
                                       uv_buf_t *buf)
{
	(void)handle;
	(void)suggested_size;

	/* Allocate a temporary buffer for UDP datagrams */
	buf->base = malloc(65536);
	if (!buf->base) {
		buf->len = 0;
	} else {
		buf->len = 65536;
	}
}

/* Buffer allocation callback for libuv reads (connections) */
static void alloc_buffer_cb(uv_handle_t *handle, size_t suggested_size,
                            uv_buf_t *buf)
{
	(void)suggested_size;

	ConnectionInfo *cnx = (ConnectionInfo*)handle->data;
	if (!cnx) {
		/* Should not happen for connection sockets */
		buf->base = NULL;
		buf->len = 0;
		return;
	}

	/* Determine which socket (local or remote) */
	Socket *socket;
	if ((uv_handle_t*)&cnx->local_uv_handle == handle) {
		socket = &cnx->local;
	} else {
		socket = &cnx->remote;
	}

	int available = RINETD_BUFFER_SIZE - socket->recvPos;
	if (available <= 0) {
		/* Buffer full - shouldn't happen if we stop reading */
		buf->base = NULL;
		buf->len = 0;
		return;
	}

	buf->base = socket->buffer + socket->recvPos;
	buf->len = available;
}

/* Forward declaration for write callback */
static void tcp_write_cb(uv_write_t *req, int status);

/* Trigger TCP write when data is available */
static void tcp_trigger_write(ConnectionInfo *cnx, Socket *socket,
                              Socket *other_socket, uv_stream_t *stream)
{
	if (socket->sentPos >= other_socket->recvPos && !cnx->coClosing) {
		return;  /* Nothing to send */
	}

	/* Check if the handle we're writing to is closing */
	int is_closing = 0;
	if (socket == &cnx->local) {
		is_closing = cnx->local_handle_closing;
	} else {
		is_closing = cnx->remote_handle_closing;
	}

	if (is_closing || uv_is_closing((uv_handle_t*)stream)) {
		/* Handle is closing, don't try to write */
		return;
	}

	uv_write_t *req = malloc(sizeof(uv_write_t));
	if (!req) {
		logError("malloc failed for write request\n");
		handleClose(cnx, socket, other_socket);
		return;
	}

	/* Store connection info for callback */
	req->data = cnx;

	int to_send = other_socket->recvPos - socket->sentPos;
	uv_buf_t wrbuf = uv_buf_init(other_socket->buffer + socket->sentPos, to_send);

	int ret = uv_write(req, stream, &wrbuf, 1, tcp_write_cb);
	if (ret != 0) {
		logError("uv_write error: %s\n", uv_strerror(ret));
		free(req);
		handleClose(cnx, socket, other_socket);
	}
}

/* TCP read callback */
static void tcp_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
	(void)buf;  /* Unused parameter - data already in socket buffer */
	ConnectionInfo *cnx = (ConnectionInfo*)stream->data;

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
		if (nread != UV_EOF) {
			logError("read error: %s\n", uv_strerror((int)nread));
		}
		handleClose(cnx, socket, other_socket);
		return;
	}

	if (nread == 0) {
		return;  /* EAGAIN, try again later */
	}

	/* Update buffer position and statistics */
	socket->recvPos += nread;
	socket->totalBytesIn += nread;

	/* Trigger write to other socket */
	tcp_trigger_write(cnx, other_socket, socket, other_stream);
}

/* TCP write completion callback */
static void tcp_write_cb(uv_write_t *req, int status)
{
	ConnectionInfo *cnx = (ConnectionInfo*)req->data;

	/* Check if connection was already freed (shouldn't happen, but defensive) */
	if (!cnx) {
		free(req);
		return;
	}

	/* Decrement pending writes counter */
	cnx->pending_writes--;

	/* Determine which socket based on the handle */
	Socket *socket, *other_socket;
	uv_stream_t *stream = req->handle;

	if (stream == (uv_stream_t*)&cnx->local_uv_handle.tcp) {
		socket = &cnx->local;
		other_socket = &cnx->remote;
	} else {
		socket = &cnx->remote;
		other_socket = &cnx->local;
	}

	free(req);

	if (status < 0) {
		logError("write error: %s\n", uv_strerror(status));
		handleClose(cnx, socket, other_socket);
		return;
	}

	/* Update position (uv_write sends all or fails) */
	int bytes_written = other_socket->recvPos - socket->sentPos;
	socket->sentPos = other_socket->recvPos;
	socket->totalBytesOut += bytes_written;

	/* Reset buffers if all sent */
	if (socket->sentPos == other_socket->recvPos) {
		socket->sentPos = other_socket->recvPos = 0;
	}

	/* Close if pending and buffer flushed */
	if (cnx->coClosing && socket->sentPos == other_socket->recvPos) {
		/* Determine which handle's closing flag to check/set */
		int *closing_flag = NULL;
		if (socket == &cnx->local) {
			closing_flag = &cnx->local_handle_closing;
		} else {
			closing_flag = &cnx->remote_handle_closing;
		}

		/* Only close if not already closing */
		if (closing_flag && !(*closing_flag) && !uv_is_closing((uv_handle_t*)stream)) {
			*closing_flag = 1;  /* Set BEFORE calling uv_close() */
			uv_close((uv_handle_t*)stream, handle_close_cb);
		}
	}
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

	/* Check if all handles are closed AND no pending writes - if so, free the connection */
	/* IMPORTANT: Check all handles are closed AND no pending operations BEFORE clearing data pointers.
	   This prevents race conditions where write callbacks might access freed connections. */
	if (!cnx->local_handle_initialized && !cnx->local_handle_closing &&
	    !cnx->remote_handle_initialized && !cnx->remote_handle_closing &&
	    !cnx->timer_initialized && !cnx->timer_closing &&
	    cnx->pending_writes == 0) {
		/* All handles are closed - safe to free the connection */

		/* Remove from linked list first */
		ConnectionInfo **ptr = &connectionListHead;
		while (*ptr) {
			if (*ptr == cnx) {
				*ptr = cnx->next;
				break;
			}
			ptr = &(*ptr)->next;
		}

		activeConnections--;

		/* Clear all handle->data pointers AFTER removing from list but BEFORE freeing.
		   This ensures any subsequent callbacks will see NULL and return early. */
		cnx->local_uv_handle.tcp.data = NULL;   /* Union - sets both tcp.data and udp.data */
		cnx->remote_uv_handle.tcp.data = NULL;  /* Union - sets both tcp.data and udp.data */
		cnx->timeout_timer.data = NULL;

		/* Now safe to free the connection */
		free(cnx->local.buffer);  /* This also frees remote.buffer */
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

/* Helper to trigger UDP write from remote buffer to local (backend) */
static void udp_trigger_write_to_local(ConnectionInfo *cnx)
{
	if (cnx->local.sentPos >= cnx->remote.recvPos) {
		return;  /* Nothing to send */
	}

	/* Check if local handle is closing */
	if (cnx->local_handle_closing || !cnx->local_handle_initialized ||
	    uv_is_closing((uv_handle_t*)&cnx->local_uv_handle.udp)) {
		return;  /* Handle is closing, don't try to send */
	}

	int to_send = cnx->remote.recvPos - cnx->local.sentPos;
	uv_buf_t wrbuf = uv_buf_init(cnx->remote.buffer + cnx->local.sentPos, to_send);

	uv_udp_send_t *req = malloc(sizeof(uv_udp_send_t));
	if (!req) {
		logError("malloc failed for UDP send request\n");
		return;
	}

	req->data = cnx;

	/* Increment pending writes counter */
	cnx->pending_writes++;

	int ret = uv_udp_send(req, &cnx->local_uv_handle.udp, &wrbuf, 1,
	                      cnx->server->toAddrInfo->ai_addr, udp_send_cb);
	if (ret != 0) {
		logError("uv_udp_send (to local) error: %s\n", uv_strerror(ret));
		/* Decrement counter since send failed immediately */
		cnx->pending_writes--;
		free(req);
	}
}

/* Helper to trigger UDP write from local buffer to remote (client) */
static void udp_trigger_write_to_remote(ConnectionInfo *cnx)
{
	if (cnx->remote.sentPos >= cnx->local.recvPos) {
		return;  /* Nothing to send */
	}

	/* Cast away const - we're not modifying ServerInfo, just using its handle for I/O */
	ServerInfo *srv = (ServerInfo *)cnx->server;
	if (!srv) {
		return;  /* Server may have been cleared during config reload */
	}

	/* Check if server UDP handle is closing */
	if (!srv->handle_initialized || uv_is_closing((uv_handle_t*)&srv->uv_handle.udp)) {
		return;  /* Handle is closing, don't try to send */
	}

	int to_send = cnx->local.recvPos - cnx->remote.sentPos;
	uv_buf_t wrbuf = uv_buf_init(cnx->local.buffer + cnx->remote.sentPos, to_send);

	uv_udp_send_t *req = malloc(sizeof(uv_udp_send_t));
	if (!req) {
		logError("malloc failed for UDP send request\n");
		return;
	}

	req->data = cnx;

	int ret = uv_udp_send(req, &srv->uv_handle.udp, &wrbuf, 1,
	                      (struct sockaddr*)&cnx->remoteAddress, udp_send_cb);
	if (ret != 0) {
		logError("uv_udp_send (to remote) error: %s\n", uv_strerror(ret));
		free(req);
	}
}

/* UDP send completion callback */
static void udp_send_cb(uv_udp_send_t *req, int status)
{
	ConnectionInfo *cnx = (ConnectionInfo*)req->data;

	/* Check if connection was already freed (shouldn't happen, but defensive) */
	if (!cnx) {
		free(req);
		return;
	}

	/* Decrement pending writes counter */
	cnx->pending_writes--;

	if (status < 0) {
		logError("UDP send error: %s\n", uv_strerror(status));
		/* For UDP, we don't close on send errors - just log */
		free(req);
		return;
	}

	free(req);

	/* Check if connection should be freed now (all handles closed and no pending writes) */
	if (!cnx->local_handle_initialized && !cnx->local_handle_closing &&
	    !cnx->remote_handle_initialized && !cnx->remote_handle_closing &&
	    !cnx->timer_initialized && !cnx->timer_closing &&
	    cnx->pending_writes == 0) {
		/* Connection can be freed - trigger cleanup */
		/* Note: This will be handled by handle_close_cb, but we check here
		   in case this was the last pending write */
		handle_close_cb((uv_handle_t*)&cnx->local_uv_handle.tcp);
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

	/* Copy to buffer */
	int to_copy = (int)nread;
	if (cnx->local.recvPos + to_copy > RINETD_BUFFER_SIZE) {
		to_copy = RINETD_BUFFER_SIZE - cnx->local.recvPos;
	}

	if (to_copy > 0) {
		memcpy(cnx->local.buffer + cnx->local.recvPos, buf->base, to_copy);
		cnx->local.recvPos += to_copy;
		cnx->local.totalBytesIn += to_copy;

		/* Trigger write to remote client */
		udp_trigger_write_to_remote(cnx);
	}

	free(buf->base);
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

	/* Look for existing connection from this address */
	ConnectionInfo *cnx = NULL;
	for (ConnectionInfo *c = connectionListHead; c; c = c->next) {
		if (c->remote.fd == (SOCKET)server_fd &&
		    c->remote.protocol == IPPROTO_UDP &&
		    sameSocketAddress(&c->remoteAddress,
		                      (struct sockaddr_storage*)addr)) {
			cnx = c;
			break;
		}
	}

	if (cnx) {
		/* Existing connection: refresh timeout */
		cnx->remoteTimeout = time(NULL) + srv->serverTimeout;
		uv_timer_again(&cnx->timeout_timer);

		/* Process data using existing handleUdpRead */
		handleUdpRead(cnx, buf->base, (int)nread);
		free(buf->base);
		return;
	}

	/* New connection */
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
		uv_close((uv_handle_t*)&cnx->timeout_timer, NULL);
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
	cnx->local.recvPos = cnx->local.sentPos = 0;
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

	/* Process initial data */
	handleUdpRead(cnx, buf->base, (int)nread);
	free(buf->base);

	/* Trigger write to backend */
	udp_trigger_write_to_local(cnx);

	logEvent(cnx, srv, logOpened);
}

static void handleUdpRead(ConnectionInfo *cnx, char const *buffer, int bytes)
{
	Socket *socket = &cnx->remote;
	int got = bytes < RINETD_BUFFER_SIZE - socket->recvPos
		? bytes : RINETD_BUFFER_SIZE - socket->recvPos;
	if (got > 0) {
		memcpy(socket->buffer + socket->recvPos, buffer, got);
		socket->totalBytesIn += got;
		socket->recvPos += got;
	}
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
	}

	/* Close the socket's libuv handle */
	if (socket->fd != INVALID_SOCKET) {
		uv_handle_t *handle = NULL;
		int *closing_flag = NULL;

		if (socket == &cnx->local && cnx->local_handle_initialized) {
			if (cnx->local_handle_type == UV_TCP) {
				handle = (uv_handle_t*)&cnx->local_uv_handle.tcp;
			} else {
				handle = (uv_handle_t*)&cnx->local_uv_handle.udp;
			}
			closing_flag = &cnx->local_handle_closing;
		} else if (socket == &cnx->remote && cnx->remote_handle_initialized) {
			if (cnx->remote_handle_type == UV_TCP) {
				handle = (uv_handle_t*)&cnx->remote_uv_handle.tcp;
			} else {
				handle = (uv_handle_t*)&cnx->remote_uv_handle.udp;
			}
			closing_flag = &cnx->remote_handle_closing;
		}

		if (handle && closing_flag && !(*closing_flag) && !uv_is_closing(handle)) {
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

	/* Handle the other socket */
	if (other_socket->fd != INVALID_SOCKET) {
		/* For UDP, immediately close the local socket */
		if (other_socket->protocol == IPPROTO_UDP && other_socket == &cnx->local) {
			uv_handle_t *handle = NULL;
			if (cnx->local_handle_initialized) {
				handle = (uv_handle_t*)&cnx->local_uv_handle.udp;
			}
			if (handle && !cnx->local_handle_closing && !uv_is_closing(handle)) {
				cnx->local_handle_closing = 1;  /* Set BEFORE calling uv_close() */
				uv_close(handle, handle_close_cb);
			}
			other_socket->fd = INVALID_SOCKET;
		}
		/* For TCP, the connection will close gracefully after pending writes complete */
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

#if !HAVE_SIGACTION && !_WIN32
RETSIGTYPE plumber(int s)
{
	/* Just reinstall */
	signal(SIGPIPE, plumber);
}
#endif

#if !_WIN32
RETSIGTYPE hup(int s)
{
	(void)s;
	logInfo("received SIGHUP, reloading configuration...\n");
	/* Learn the new rules */
	clearConfiguration();
	readConfiguration(options.conf_file);
#if !HAVE_SIGACTION
	/* And reinstall the signal handler */
	signal(SIGHUP, hup);
#endif
}
#endif /* _WIN32 */

RETSIGTYPE quit(int s)
{
	(void)s;
	/* Obey the request, but first flush the log */
	if (logFile) {
		fclose(logFile);
	}
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
	logError("couldn't write to %s. PID was not logged (%m).\n",
		pid_file_name);
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
	strftime(tstr, sizeof(tstr), "%Y-%m-%d %H:%M:%S ", t);

	int64_t bytesOut = 0, bytesIn = 0;
	if (cnx != NULL) {
		getnameinfo((struct sockaddr *)&cnx->remoteAddress, sizeof(cnx->remoteAddress),
			addressText, sizeof(addressText), NULL, 0, NI_NUMERICHOST);
		bytesOut = cnx->remote.totalBytesOut;
		bytesIn = cnx->remote.totalBytesIn;
	}

	char const *fromHost = "?", *toHost = "?";
	uint16_t fromPort = 0, toPort = 0;
	if (srv != NULL) {
		fromHost = srv->fromHost;
		fromPort = getPort(srv->fromAddrInfo);
		toHost = srv->toHost;
		toPort = getPort(srv->toAddrInfo);
	}

	if (result==logNotAllowed || result==logDenied)
		logInfo("%s %s\n"
			, addressText
			, logMessages[result]);
	if (logFile) {
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
			fprintf(logFile, "%s - - "
				"[%s %c%.2d%.2d] "
				"\"GET /rinetd-services/%s/%d/%s/%d/%s HTTP/1.0\" "
				"200 %llu - - - %llu\n",
				addressText,
				tstr,
				sign,
				timz / 60,
				timz % 60,
				fromHost, (int)fromPort,
				toHost, (int)toPort,
				logMessages[result],
				(unsigned long long int)bytesOut,
				(unsigned long long int)bytesIn);
		} else {
			/* Write an rinetd-specific log entry with a
				less goofy format. */
			fprintf(logFile, "%s\t%s\t%s\t%d\t%s\t%d\t%llu"
					"\t%llu\t%s\n",
				tstr,
				addressText,
				fromHost, (int)fromPort,
				toHost, (int)toPort,
				(unsigned long long int)bytesIn,
				(unsigned long long int)bytesOut,
				logMessages[result]);
		}
	}
}

static int readArgs (int argc, char **argv, RinetdOptions *options)
{
	for (;;) {
		int option_index = 0;
		static struct option long_options[] = {
			{"conf-file",  1, 0, 'c'},
			{"foreground", 0, 0, 'f'},
			{"help",       0, 0, 'h'},
			{"version",    0, 0, 'v'},
			{0, 0, 0, 0}
		};
		int c = getopt_long (argc, argv, "c:fshv",
			long_options, &option_index);
		if (c == -1) {
			break;
		}
		switch (c) {
			case 'c':
				options->conf_file = optarg;
				if (!options->conf_file) {
					fprintf(stderr, "Not enough memory to "
						"launch rinetd.\n");
					exit(1);
				}
				break;
			case 'f':
				options->foreground = 1;
				break;
			case 'h':
				printf("Usage: rinetd [OPTION]\n"
					"  -c, --conf-file FILE   read configuration "
					"from FILE\n"
					"  -f, --foreground       do not run in the "
					"background\n"
					"  -h, --help             display this help\n"
					"  -v, --version          display version "
					"number\n\n");
				printf("Most options are controlled through the\n"
					"configuration file. See the rinetd(8)\n"
					"manpage for more information.\n");
				exit (0);
			case 'v':
				printf ("rinetd %s\n", PACKAGE_VERSION);
				exit (0);
			case '?':
			default:
				exit (1);
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

