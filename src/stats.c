/* Copyright © 2026 Marcin Gryszkalis <mg@fork.pl>

   This software is released for free use under the terms of
   the GNU Public License, version 2 or higher. NO WARRANTY
   IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK. */

#if HAVE_CONFIG_H
#   include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>
#include <limits.h>

#include "stats.h"
#include "rinetd.h"
#include "log.h"
#include "buffer_pool.h"
#include "loadbalancer.h"

/* Global statistics instance */
GlobalStats globalStats;

/* Status configuration */
StatusConfig statusConfig = {
    .enabled = 0,
    .file = NULL,
    .interval = 30,
    .format = STATUS_FORMAT_JSON
};
int statsLogInterval = 60;

/* Timer handles */
static uv_timer_t status_file_timer;
static uv_timer_t stats_log_timer;
static int status_file_timer_initialized = 0;
static int stats_log_timer_initialized = 0;
static int status_file_timer_active = 0;
static int stats_log_timer_active = 0;

/* Async file write context */
typedef struct {
    uv_fs_t req;
    uv_buf_t buffer;
    char *content;
    char temp_path[PATH_MAX];
    char *final_path;
    uv_file fd;
    int phase;
} StatusWriteContext;

enum {
    PHASE_MKSTEMP,
    PHASE_WRITE,
    PHASE_CLOSE,
    PHASE_CHMOD,
    PHASE_RENAME
};

/* Forward declarations */
static void status_file_timer_cb(uv_timer_t *timer);
static void stats_log_timer_cb(uv_timer_t *timer);
static void status_fs_cb(uv_fs_t *req);
static char *generate_json_status(void);
static char *generate_text_status(void);
static void cleanup_status_context(StatusWriteContext *ctx);

void stats_init(void)
{
    memset(&globalStats, 0, sizeof(globalStats));
    globalStats.start_time = time(NULL);
    globalStats.last_reload_time = globalStats.start_time;
}

/* Timer close callbacks */
static int status_file_timer_closing = 0;
static int stats_log_timer_closing = 0;

static void status_file_timer_close_cb(uv_handle_t *handle)
{
    (void)handle;
    status_file_timer_initialized = 0;
    status_file_timer_closing = 0;
}

static void stats_log_timer_close_cb(uv_handle_t *handle)
{
    (void)handle;
    stats_log_timer_initialized = 0;
    stats_log_timer_closing = 0;
}

void stats_shutdown(void)
{
    /* Stop and close status file timer */
    if (status_file_timer_initialized && !status_file_timer_closing) {
        if (status_file_timer_active) {
            uv_timer_stop(&status_file_timer);
            status_file_timer_active = 0;
        }
        status_file_timer_closing = 1;
        uv_close((uv_handle_t*)&status_file_timer, status_file_timer_close_cb);
    }

    /* Stop and close stats log timer */
    if (stats_log_timer_initialized && !stats_log_timer_closing) {
        if (stats_log_timer_active) {
            uv_timer_stop(&stats_log_timer);
            stats_log_timer_active = 0;
        }
        stats_log_timer_closing = 1;
        uv_close((uv_handle_t*)&stats_log_timer, stats_log_timer_close_cb);
    }
}

void stats_start_timers(void)
{
    /* Start status file timer if enabled */
    if (statusConfig.enabled && statusConfig.file && statusConfig.interval > 0) {
        if (!status_file_timer_initialized) {
            uv_timer_init(main_loop, &status_file_timer);
            status_file_timer_initialized = 1;
        }
        if (!status_file_timer_active) {
            int ret = uv_timer_start(&status_file_timer, status_file_timer_cb, statusConfig.interval * 1000, statusConfig.interval * 1000);
            if (ret != 0)
                logError("uv_timer_start(status_file_timer) error: %s\n", uv_strerror(ret));
            else
            {
                status_file_timer_active = 1;
                logDebug("Status file timer started (interval: %ds)\n", statusConfig.interval);
            }
        }
    }

    /* Start stats log timer if enabled */
    if (statsLogInterval > 0) {
        if (!stats_log_timer_initialized) {
            uv_timer_init(main_loop, &stats_log_timer);
            stats_log_timer_initialized = 1;
        }
        if (!stats_log_timer_active) {
            int ret = uv_timer_start(&stats_log_timer, stats_log_timer_cb, statsLogInterval * 1000, statsLogInterval * 1000);
            if (ret != 0)
                logError("uv_timer_start(stats_log_timer) error: %s\n", uv_strerror(ret));
            else
            {
                stats_log_timer_active = 1;
                logDebug("Stats log timer started (interval: %ds)\n", statsLogInterval);
            }
        }
    }
}

void stats_stop_timers(void)
{
    if (status_file_timer_active) {
        uv_timer_stop(&status_file_timer);
        status_file_timer_active = 0;
    }
    if (stats_log_timer_active) {
        uv_timer_stop(&stats_log_timer);
        stats_log_timer_active = 0;
    }
}

void stats_restart_timers_if_needed(void)
{
    stats_stop_timers();
    stats_start_timers();
}

void stats_on_config_reload(void)
{
    globalStats.config_reload_count++;
    globalStats.last_reload_time = time(NULL);
}

static void status_file_timer_cb(uv_timer_t *timer)
{
    (void)timer;
    stats_write_status_file();
}

static void stats_log_timer_cb(uv_timer_t *timer)
{
    (void)timer;
    stats_log_summary();
}

/* Format bytes as human-readable string (e.g., "1.5G", "256M", "128K") */
static void format_bytes(uint64_t bytes, char *buf, size_t buf_size)
{
    if (bytes >= 1099511627776ULL)  /* 1 TB */
        snprintf(buf, buf_size, "%.1fT", (double)bytes / 1099511627776.0);
    else if (bytes >= 1073741824ULL)  /* 1 GB */
        snprintf(buf, buf_size, "%.1fG", (double)bytes / 1073741824.0);
    else if (bytes >= 1048576ULL)  /* 1 MB */
        snprintf(buf, buf_size, "%.1fM", (double)bytes / 1048576.0);
    else if (bytes >= 1024ULL)  /* 1 KB */
        snprintf(buf, buf_size, "%.1fK", (double)bytes / 1024.0);
    else
        snprintf(buf, buf_size, "%lluB", (unsigned long long)bytes);
}

/* Format uptime as human-readable string */
static void format_uptime(time_t seconds, char *buf, size_t buf_size)
{
    int days = seconds / 86400;
    int hours = (seconds % 86400) / 3600;
    int mins = (seconds % 3600) / 60;
    int secs = seconds % 60;

    if (days > 0)
        snprintf(buf, buf_size, "%d day%s, %d:%02d:%02d", days, days == 1 ? "" : "s", hours, mins, secs);
    else
        snprintf(buf, buf_size, "%d:%02d:%02d", hours, mins, secs);
}

void stats_log_summary(void)
{
    time_t uptime = time(NULL) - globalStats.start_time;
    uint64_t active = globalStats.active_connections_tcp +
                      globalStats.active_connections_udp +
                      globalStats.active_connections_unix;
    char bytes_in[32], bytes_out[32];

    format_bytes(globalStats.total_bytes_in, bytes_in, sizeof(bytes_in));
    format_bytes(globalStats.total_bytes_out, bytes_out, sizeof(bytes_out));

    logInfo("STATS: uptime=%lds conns=%llu/%llu tcp=%llu/%llu udp=%llu/%llu unix=%llu/%llu traffic=%s/%s errors=%llu/%llu/%llu\n",
            (long)uptime,
            (unsigned long long)active, (unsigned long long)globalStats.total_connections_accepted,
            (unsigned long long)globalStats.active_connections_tcp, (unsigned long long)globalStats.total_connections_tcp,
            (unsigned long long)globalStats.active_connections_udp, (unsigned long long)globalStats.total_connections_udp,
            (unsigned long long)globalStats.active_connections_unix, (unsigned long long)globalStats.total_connections_unix,
            bytes_in, bytes_out,
            (unsigned long long)globalStats.accept_errors,
            (unsigned long long)globalStats.connect_errors,
            (unsigned long long)globalStats.denied_connections);
}

/* JSON string escaping (minimal - handles common cases) */
static void json_escape_string(const char *src, char *dest, size_t dest_size)
{
    size_t i = 0;
    while (*src && i < dest_size - 2) {
        switch (*src) {
        case '"':
        case '\\':
            if (i < dest_size - 3) {
                dest[i++] = '\\';
                dest[i++] = *src;
            }
            break;
        case '\n':
            if (i < dest_size - 3) {
                dest[i++] = '\\';
                dest[i++] = 'n';
            }
            break;
        case '\r':
            if (i < dest_size - 3) {
                dest[i++] = '\\';
                dest[i++] = 'r';
            }
            break;
        case '\t':
            if (i < dest_size - 3) {
                dest[i++] = '\\';
                dest[i++] = 't';
            }
            break;
        default:
            dest[i++] = *src;
            break;
        }
        src++;
    }
    dest[i] = '\0';
}

#define STATS_BUF_INITIAL_SIZE 8192

/*
 * Grow buffer if remaining space is less than `need` bytes.
 * On allocation failure: frees buf, sets it to NULL.
 */
static int ensure_buf_space(char **buf, size_t *buf_size, size_t pos, size_t need)
{
    while (*buf_size - pos < need) {
        size_t new_size = *buf_size * 2;
        char *new_buf = realloc(*buf, new_size);
        if (!new_buf) {
            free(*buf);
            *buf = NULL;
            return -1;
        }
        *buf = new_buf;
        *buf_size = new_size;
    }
    return 0;
}

/*
 * Safe snprintf into a growable buffer.
 * Ensures enough space, writes, and advances pos.
 * Jumps to `fail_label` on allocation failure.
 */
#define BUF_PRINTF(fail_label, fmt, ...) \
    do { \
        int _n = snprintf(buf + pos, buf_size - pos, fmt, ##__VA_ARGS__); \
        if (_n < 0) goto fail_label; \
        if ((size_t)_n >= buf_size - pos) { \
            if (ensure_buf_space(&buf, &buf_size, pos, (size_t)_n + 1) != 0) \
                goto fail_label; \
            _n = snprintf(buf + pos, buf_size - pos, fmt, ##__VA_ARGS__); \
            if (_n < 0 || (size_t)_n >= buf_size - pos) goto fail_label; \
        } \
        pos += (size_t)_n; \
    } while (0)


static size_t json_buf_highwater = STATS_BUF_INITIAL_SIZE;

static char *generate_json_status(void)
{
    size_t buf_size = json_buf_highwater;
    char *buf = malloc(buf_size);
    if (!buf)
        return NULL;

    time_t now = time(NULL);
    time_t uptime = now - globalStats.start_time;
    uint64_t active = globalStats.active_connections_tcp +
                      globalStats.active_connections_udp +
                      globalStats.active_connections_unix;

    /* Format timestamps */
    char timestamp[64], reload_time[64];
    struct tm *tm_info = gmtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", tm_info);
    tm_info = gmtime(&globalStats.last_reload_time);
    strftime(reload_time, sizeof(reload_time), "%Y-%m-%dT%H:%M:%SZ", tm_info);

    /* Get buffer pool stats */
    BufferPoolStats pool_stats;
    buffer_pool_get_stats(&pool_stats);

    size_t pos = 0;
    BUF_PRINTF(json_fail,
        "{\n"
        "  \"timestamp\": \"%s\",\n"
#ifdef PACKAGE_VERSION
        "  \"version\": \"%s\",\n"
#endif
        "  \"uptime_seconds\": %ld,\n"
        "  \"config_reloads\": %d,\n"
        "  \"stats_since_reload\": \"%s\",\n"
        "  \"connections\": {\n"
        "    \"active\": %llu,\n"
        "    \"active_tcp\": %llu,\n"
        "    \"active_udp\": %llu,\n"
        "    \"active_unix\": %llu,\n"
        "    \"total\": %llu,\n"
        "    \"total_tcp\": %llu,\n"
        "    \"total_udp\": %llu,\n"
        "    \"total_unix\": %llu\n"
        "  },\n"
        "  \"traffic\": {\n"
        "    \"bytes_in\": %llu,\n"
        "    \"bytes_out\": %llu\n"
        "  },\n"
        "  \"errors\": {\n"
        "    \"accept\": %llu,\n"
        "    \"connect\": %llu,\n"
        "    \"denied\": %llu\n"
        "  },\n"
        "  \"buffer_pool\": {\n"
        "    \"buffer_size\": %d,\n"
        "    \"free\": %d,\n"
        "    \"allocs_from_pool\": %llu,\n"
        "    \"allocs_from_malloc\": %llu\n"
        "  },\n"
        "  \"servers\": %d",
        timestamp,
#ifdef PACKAGE_VERSION
        PACKAGE_VERSION,
#endif
        (long)uptime,
        globalStats.config_reload_count,
        reload_time,
        (unsigned long long)active,
        (unsigned long long)globalStats.active_connections_tcp,
        (unsigned long long)globalStats.active_connections_udp,
        (unsigned long long)globalStats.active_connections_unix,
        (unsigned long long)globalStats.total_connections_accepted,
        (unsigned long long)globalStats.total_connections_tcp,
        (unsigned long long)globalStats.total_connections_udp,
        (unsigned long long)globalStats.total_connections_unix,
        (unsigned long long)globalStats.total_bytes_in,
        (unsigned long long)globalStats.total_bytes_out,
        (unsigned long long)globalStats.accept_errors,
        (unsigned long long)globalStats.connect_errors,
        (unsigned long long)globalStats.denied_connections,
        pool_stats.buffer_size,
        pool_stats.current_free,
        (unsigned long long)pool_stats.allocs_from_pool,
        (unsigned long long)pool_stats.allocs_from_malloc,
        seTotal);

    /* Add per-rule statistics if using YAML config */
    if (usingYamlConfig && yamlRulesCount > 0) {
        BUF_PRINTF(json_fail, ",\n  \"rules\": [\n");

        for (int i = 0; i < yamlRulesCount; i++) {
            RuleInfo *rule = &yamlRules[i];
            char name_escaped[256];
            json_escape_string(rule->name ? rule->name : "unnamed", name_escaped, sizeof(name_escaped));

            /* Calculate rule totals */
            uint64_t rule_bytes_in = 0, rule_bytes_out = 0;
            uint64_t rule_total_conns = 0;
            int rule_active_conns = 0;

            for (int j = 0; j < rule->backend_count; j++) {
                BackendInfo *be = &rule->backends[j];
                rule_bytes_in += be->total_bytes_in;
                rule_bytes_out += be->total_bytes_out;
                rule_total_conns += be->total_connections;
                rule_active_conns += be->active_connections;
            }

            BUF_PRINTF(json_fail,
                "    {\n"
                "      \"name\": \"%s\",\n"
                "      \"algorithm\": \"%s\",\n"
                "      \"connections_active\": %d,\n"
                "      \"connections_total\": %llu,\n"
                "      \"bytes_in\": %llu,\n"
                "      \"bytes_out\": %llu,\n"
                "      \"backends\": [\n",
                name_escaped,
                lb_algorithm_name(rule->algorithm),
                rule_active_conns,
                (unsigned long long)rule_total_conns,
                (unsigned long long)rule_bytes_in,
                (unsigned long long)rule_bytes_out);

            for (int j = 0; j < rule->backend_count; j++) {
                BackendInfo *be = &rule->backends[j];
                char be_name_escaped[256];
                json_escape_string(be->name ? be->name : "unnamed", be_name_escaped, sizeof(be_name_escaped));

                BUF_PRINTF(json_fail,
                    "        {\n"
                    "          \"name\": \"%s\",\n"
                    "          \"healthy\": %s,\n"
                    "          \"connections_active\": %llu,\n"
                    "          \"connections_total\": %llu,\n"
                    "          \"bytes_in\": %llu,\n"
                    "          \"bytes_out\": %llu\n"
                    "        }%s\n",
                    be_name_escaped,
                    be->healthy ? "true" : "false",
                    (unsigned long long)be->active_connections,
                    (unsigned long long)be->total_connections,
                    (unsigned long long)be->total_bytes_in,
                    (unsigned long long)be->total_bytes_out,
                    (j < rule->backend_count - 1) ? "," : "");
            }

            BUF_PRINTF(json_fail,
                "      ]\n"
                "    }%s\n",
                (i < yamlRulesCount - 1) ? "," : "");
        }

        BUF_PRINTF(json_fail, "  ]\n");
    } else {
        BUF_PRINTF(json_fail, "\n");
    }

    BUF_PRINTF(json_fail, "}\n");

    if (buf_size > json_buf_highwater)
        json_buf_highwater = buf_size;
    return buf;

json_fail:
    free(buf);
    return NULL;
}

static size_t text_buf_highwater = STATS_BUF_INITIAL_SIZE;

static char *generate_text_status(void)
{
    size_t buf_size = text_buf_highwater;
    char *buf = malloc(buf_size);
    if (!buf)
        return NULL;

    time_t now = time(NULL);
    time_t uptime = now - globalStats.start_time;
    uint64_t active = globalStats.active_connections_tcp +
                      globalStats.active_connections_udp +
                      globalStats.active_connections_unix;

    /* Format timestamp and uptime */
    char timestamp[64], uptime_str[64];
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    format_uptime(uptime, uptime_str, sizeof(uptime_str));

    /* Format bytes */
    char bytes_in[32], bytes_out[32];
    format_bytes(globalStats.total_bytes_in, bytes_in, sizeof(bytes_in));
    format_bytes(globalStats.total_bytes_out, bytes_out, sizeof(bytes_out));

    /* Get buffer pool stats */
    BufferPoolStats pool_stats;
    buffer_pool_get_stats(&pool_stats);

    size_t pos = 0;
    BUF_PRINTF(text_fail,
        "rinetd-uv Status Report\n"
        "Updated: %s\n"
#ifdef PACKAGE_VERSION
        "Version: %s\n"
#endif
        "Uptime: %s\n"
        "Config reloads: %d\n"
        "\n"
        "CONNECTIONS\n"
        "Active: %llu (TCP: %llu, UDP: %llu, Unix: %llu)\n"
        "Total: %llu (TCP: %llu, UDP: %llu, Unix: %llu)\n"
        "\n"
        "TRAFFIC\n"
        "Bytes in: %s\n"
        "Bytes out: %s\n"
        "\n"
        "ERRORS\n"
        "Accept: %llu\n"
        "Connect: %llu\n"
        "Denied: %llu\n"
        "\n"
        "BUFFER POOL\n"
        "Buffer size: %d\n"
        "Free buffers: %d\n"
        "\n"
        "SERVERS\n"
        "Count: %d\n",
        timestamp,
#ifdef PACKAGE_VERSION
        PACKAGE_VERSION,
#endif
        uptime_str,
        globalStats.config_reload_count,
        (unsigned long long)active,
        (unsigned long long)globalStats.active_connections_tcp,
        (unsigned long long)globalStats.active_connections_udp,
        (unsigned long long)globalStats.active_connections_unix,
        (unsigned long long)globalStats.total_connections_accepted,
        (unsigned long long)globalStats.total_connections_tcp,
        (unsigned long long)globalStats.total_connections_udp,
        (unsigned long long)globalStats.total_connections_unix,
        bytes_in, bytes_out,
        (unsigned long long)globalStats.accept_errors,
        (unsigned long long)globalStats.connect_errors,
        (unsigned long long)globalStats.denied_connections,
        pool_stats.buffer_size,
        pool_stats.current_free,
        seTotal);

    /* Add per-rule statistics if using YAML config */
    if (usingYamlConfig && yamlRulesCount > 0) {
        BUF_PRINTF(text_fail, "\nRULES\n");

        for (int i = 0; i < yamlRulesCount; i++) {
            RuleInfo *rule = &yamlRules[i];

            /* Calculate rule totals */
            uint64_t rule_bytes_in = 0, rule_bytes_out = 0;
            uint64_t rule_total_conns = 0;
            int rule_active_conns = 0;

            for (int j = 0; j < rule->backend_count; j++) {
                BackendInfo *be = &rule->backends[j];
                rule_bytes_in += be->total_bytes_in;
                rule_bytes_out += be->total_bytes_out;
                rule_total_conns += be->total_connections;
                rule_active_conns += be->active_connections;
            }

            char rule_bytes_in_str[32], rule_bytes_out_str[32];
            format_bytes(rule_bytes_in, rule_bytes_in_str, sizeof(rule_bytes_in_str));
            format_bytes(rule_bytes_out, rule_bytes_out_str, sizeof(rule_bytes_out_str));

            BUF_PRINTF(text_fail,
                "  %s (%s):\n"
                "    Active: %d, Total: %llu, Traffic: %s/%s\n"
                "    Backends:\n",
                rule->name ? rule->name : "unnamed",
                lb_algorithm_name(rule->algorithm),
                rule_active_conns,
                (unsigned long long)rule_total_conns,
                rule_bytes_in_str, rule_bytes_out_str);

            for (int j = 0; j < rule->backend_count; j++) {
                BackendInfo *be = &rule->backends[j];
                BUF_PRINTF(text_fail,
                    "      %s: %s, active=%llu, total=%llu\n",
                    be->name ? be->name : "unnamed",
                    be->healthy ? "healthy" : "unhealthy",
                    (unsigned long long)be->active_connections,
                    (unsigned long long)be->total_connections);
            }
        }
    }

    if (buf_size > text_buf_highwater)
        text_buf_highwater = buf_size;
    return buf;

text_fail:
    free(buf);
    return NULL;
}

static void cleanup_status_context(StatusWriteContext *ctx)
{
    uv_fs_req_cleanup(&ctx->req);
    free(ctx->content);
    free(ctx->final_path);
    free(ctx);
}

static void status_fs_cb(uv_fs_t *req)
{
    StatusWriteContext *ctx = req->data;

    if (req->result < 0) {
        logWarning("Status file operation failed (phase %d): %s\n", ctx->phase, uv_strerror(req->result));
        /* Try to clean up temp file if it was created */
        if (ctx->phase > PHASE_MKSTEMP && ctx->temp_path[0]) {
            uv_fs_t unlink_req;
            uv_fs_unlink(NULL, &unlink_req, ctx->temp_path, NULL);
            uv_fs_req_cleanup(&unlink_req);
        }
        cleanup_status_context(ctx);
        return;
    }

    /* Copy temp path from mkstemp BEFORE cleanup frees req->path */
    if (ctx->phase == PHASE_MKSTEMP && req->path)
        strncpy(ctx->temp_path, req->path, sizeof(ctx->temp_path) - 1);

    uv_fs_req_cleanup(req);

    switch (ctx->phase) {
    case PHASE_MKSTEMP:
        ctx->fd = req->result;

        ctx->phase = PHASE_WRITE;
        ctx->req.data = ctx;
        int r = uv_fs_write(main_loop, &ctx->req, ctx->fd, &ctx->buffer, 1, 0, status_fs_cb);
        if (r < 0) {
            logWarning("uv_fs_write failed synchronously: %s\n", uv_strerror(r));
            cleanup_status_context(ctx);
        }
        break;

    case PHASE_WRITE:
        ctx->phase = PHASE_CLOSE;
        ctx->req.data = ctx;
        r = uv_fs_close(main_loop, &ctx->req, ctx->fd, status_fs_cb);
        if (r < 0) {
            logWarning("uv_fs_close failed synchronously: %s\n", uv_strerror(r));
            cleanup_status_context(ctx);
        }
        break;

    case PHASE_CLOSE:
        /* Apply permissions: 0666 & ~umask */
        ctx->phase = PHASE_CHMOD;
        ctx->req.data = ctx;
        r = uv_fs_chmod(main_loop, &ctx->req, ctx->temp_path, 0666, status_fs_cb);
        if (r < 0) {
            logWarning("uv_fs_chmod failed synchronously: %s\n", uv_strerror(r));
            cleanup_status_context(ctx);
        }
        break;

    case PHASE_CHMOD:
        /* Rename to final location */
        ctx->phase = PHASE_RENAME;
        ctx->req.data = ctx;
        r = uv_fs_rename(main_loop, &ctx->req, ctx->temp_path, ctx->final_path, status_fs_cb);
        if (r < 0) {
            logWarning("uv_fs_rename failed synchronously: %s\n", uv_strerror(r));
            if (ctx->temp_path[0]) {
                uv_fs_t unlink_req;
                uv_fs_unlink(NULL, &unlink_req, ctx->temp_path, NULL);
                uv_fs_req_cleanup(&unlink_req);
            }
            cleanup_status_context(ctx);
        }
        break;

    case PHASE_RENAME:
        logDebug("Status file written: %s\n", ctx->final_path);
        cleanup_status_context(ctx);
        break;
    }
}

void stats_write_status_file(void)
{
    if (!statusConfig.enabled || !statusConfig.file)
        return;

    StatusWriteContext *ctx = calloc(1, sizeof(StatusWriteContext));
    if (!ctx) {
        logWarning("Cannot allocate status write context\n");
        return;
    }

    /* Generate content */
    if (statusConfig.format == STATUS_FORMAT_JSON)
        ctx->content = generate_json_status();
    else
        ctx->content = generate_text_status();

    if (!ctx->content) {
        free(ctx);
        logWarning("Cannot generate status content\n");
        return;
    }

    ctx->buffer = uv_buf_init(ctx->content, strlen(ctx->content));
    ctx->final_path = strdup(statusConfig.file);
    if (!ctx->final_path) {
        free(ctx->content);
        free(ctx);
        return;
    }

    /* Build template in same directory as target for atomic rename */
    char *path_copy = strdup(statusConfig.file);
    if (!path_copy) {
        free(ctx->content);
        free(ctx->final_path);
        free(ctx);
        return;
    }
    char *dir = dirname(path_copy);
    snprintf(ctx->temp_path, sizeof(ctx->temp_path), "%s/.rinetd-status-XXXXXX", dir);
    free(path_copy);

    /* Start async chain: mkstemp -> write -> close -> chmod -> rename */
    ctx->phase = PHASE_MKSTEMP;
    ctx->req.data = ctx;

    int r = uv_fs_mkstemp(main_loop, &ctx->req, ctx->temp_path, status_fs_cb);
    if (r < 0) {
        logWarning("uv_fs_mkstemp failed: %s\n", uv_strerror(r));
        cleanup_status_context(ctx);
    }
}

/* Connection tracking functions */

void stats_connection_accepted(int protocol)
{
    globalStats.total_connections_accepted++;

    switch (protocol) {
    case IPPROTO_TCP:
        globalStats.total_connections_tcp++;
        globalStats.active_connections_tcp++;
        break;
    case IPPROTO_UDP:
        globalStats.total_connections_udp++;
        globalStats.active_connections_udp++;
        break;
    default:
        /* Unix socket or unknown - treat as Unix */
        globalStats.total_connections_unix++;
        globalStats.active_connections_unix++;
        break;
    }
}

void stats_connection_closed(int protocol, uint64_t bytes_in, uint64_t bytes_out)
{
    globalStats.total_bytes_in += bytes_in;
    globalStats.total_bytes_out += bytes_out;

    switch (protocol) {
    case IPPROTO_TCP:
        if (globalStats.active_connections_tcp > 0)
            globalStats.active_connections_tcp--;
        break;
    case IPPROTO_UDP:
        if (globalStats.active_connections_udp > 0)
            globalStats.active_connections_udp--;
        break;
    default:
        /* Unix socket or unknown */
        if (globalStats.active_connections_unix > 0)
            globalStats.active_connections_unix--;
        break;
    }
}

void stats_connection_denied(void)
{
    globalStats.denied_connections++;
}

void stats_error_accept(void)
{
    globalStats.accept_errors++;
}

void stats_error_connect(void)
{
    globalStats.connect_errors++;
}
