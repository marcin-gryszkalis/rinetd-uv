/* Copyright © 2026 Marcin Gryszkalis <mg@fork.pl>

   This software is released for free use under the terms of
   the GNU Public License, version 2 or higher. NO WARRANTY
   IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK. */

#pragma once

#include <stdint.h>
#include <time.h>
#include <netinet/in.h>  /* For IPPROTO_TCP, IPPROTO_UDP */
#include <uv.h>

/* Status file format */
typedef enum {
    STATUS_FORMAT_JSON = 0,
    STATUS_FORMAT_TEXT = 1
} StatusFormat;

/* Status file configuration */
typedef struct _status_config StatusConfig;
struct _status_config {
    int enabled;
    char *file;
    int interval;           /* Seconds between writes */
    StatusFormat format;
};

/* Global statistics (process lifetime) */
typedef struct _global_stats GlobalStats;
struct _global_stats {
    /* Process info */
    time_t start_time;
    time_t last_reload_time;
    int config_reload_count;

    /* Connection counters (lifetime totals) */
    uint64_t total_connections_accepted;
    uint64_t total_connections_tcp;
    uint64_t total_connections_udp;
    uint64_t total_connections_unix;

    /* Active connections by type */
    int active_connections_tcp;
    int active_connections_udp;
    int active_connections_unix;

    /* Byte counters (lifetime totals) */
    uint64_t total_bytes_in;
    uint64_t total_bytes_out;

    /* Error counters */
    uint64_t accept_errors;
    uint64_t connect_errors;
    uint64_t denied_connections;
};

/* Global statistics instance */
extern GlobalStats globalStats;

/* Status configuration */
extern StatusConfig statusConfig;
extern int statsLogInterval;

/* Initialize statistics subsystem (call once at startup) */
void stats_init(void);

/* Shutdown statistics subsystem (call before exit) */
void stats_shutdown(void);

/* Start status reporting timers (call after config load) */
void stats_start_timers(void);

/* Stop status reporting timers (call before config reload or shutdown) */
void stats_stop_timers(void);

/* Check if timers need restart after config change */
void stats_restart_timers_if_needed(void);

/* Write status file immediately (also called by timer) */
void stats_write_status_file(void);

/* Log one-line statistics summary (also called by timer) */
void stats_log_summary(void);

/* Handle configuration reload */
void stats_on_config_reload(void);

/* Connection tracking - call from connection lifecycle points */

/* Called when a new connection is accepted
 * protocol: IPPROTO_TCP, IPPROTO_UDP, or 0 for Unix socket */
void stats_connection_accepted(int protocol);

/* Called when a connection is closed */
void stats_connection_closed(int protocol, uint64_t bytes_in, uint64_t bytes_out);

/* Called when a connection is denied by access rules */
void stats_connection_denied(void);

/* Called when accept() fails */
void stats_error_accept(void);

/* Called when connect() to backend fails */
void stats_error_connect(void);
