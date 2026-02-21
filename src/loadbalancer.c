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
#include <strings.h>

#include "loadbalancer.h"
#include "affinity.h"
#include "log.h"

/* Hash function for IP addresses (for IP-hash algorithm) */
static uint32_t hash_ip_address(struct sockaddr_storage *addr)
{
    uint32_t hash = 0;

    if (addr->ss_family == AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
        hash = addr4->sin_addr.s_addr;
    } else if (addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        /* XOR all 32-bit words of the IPv6 address */
        uint32_t *words = (uint32_t *)&addr6->sin6_addr;
        hash = words[0] ^ words[1] ^ words[2] ^ words[3];
    }

    /* Mix the hash a bit for better distribution */
    hash ^= (hash >> 16);
    hash *= 0x85ebca6b;
    hash ^= (hash >> 13);
    hash *= 0xc2b2ae35;
    hash ^= (hash >> 16);

    return hash;
}

/* Select backend using round-robin algorithm */
static BackendInfo *select_round_robin(RuleInfo *rule)
{
    if (rule->backend_count == 0)
        return NULL;

    int attempts = rule->backend_count;
    while (attempts-- > 0) {
        int idx = rule->rr_index % rule->backend_count;
        rule->rr_index++;

        BackendInfo *backend = &rule->backends[idx];
        if (lb_backend_should_retry(backend, rule))
            return backend;
    }

    /* All backends unhealthy - return first one anyway */
    return &rule->backends[0];
}

/* Select backend using weighted round-robin algorithm (Nginx smooth WRR) */
static BackendInfo *select_weighted_round_robin(RuleInfo *rule)
{
    if (rule->backend_count == 0)
        return NULL;

    BackendInfo *best = NULL;
    int best_weight = -1;

    /* Find backend with highest current_weight */
    for (int i = 0; i < rule->backend_count; i++) {
        BackendInfo *b = &rule->backends[i];
        if (!lb_backend_should_retry(b, rule))
            continue;

        b->current_weight += b->effective_weight;
        if (b->current_weight > best_weight) {
            best_weight = b->current_weight;
            best = b;
        }
    }

    if (best) {
        best->current_weight -= rule->total_weight;
        return best;
    }

    /* All backends unhealthy - try first one */
    return &rule->backends[0];
}

/* Select backend using least connections algorithm with round-robin tie-breaking */
static BackendInfo *select_least_conn(RuleInfo *rule)
{
    if (rule->backend_count == 0)
        return NULL;

    uint64_t min_conn = UINT64_MAX;
    int tied_count = 0;

    /* First pass: find minimum weighted connection count */
    for (int i = 0; i < rule->backend_count; i++) {
        BackendInfo *b = &rule->backends[i];
        if (!lb_backend_should_retry(b, rule))
            continue;

        /* Weight-adjusted connection count: connections / weight */
        uint64_t weighted_conn = b->active_connections * 1000 / (b->weight > 0 ? b->weight : 1);

        if (weighted_conn < min_conn) {
            min_conn = weighted_conn;
            tied_count = 1;
        } else if (weighted_conn == min_conn) {
            tied_count++;
        }
    }

    if (tied_count == 0) {
        /* All backends unhealthy - return first one */
        return &rule->backends[0];
    }

    /* Second pass: select the (rr_index % tied_count)-th backend with min connections */
    uint64_t selection = rule->rr_index % tied_count;
    uint64_t current = 0;

    for (int i = 0; i < rule->backend_count; i++) {
        BackendInfo *b = &rule->backends[i];
        if (!lb_backend_should_retry(b, rule))
            continue;

        uint64_t weighted_conn = b->active_connections * 1000 / (b->weight > 0 ? b->weight : 1);

        if (weighted_conn == min_conn) {
            if (current == selection) {
                rule->rr_index++;
                return b;
            }
            current++;
        }
    }

    /* Fallback - should not reach here */
    return &rule->backends[0];
}

/* Select backend using random algorithm */
static BackendInfo *select_random(RuleInfo *rule)
{
    if (rule->backend_count == 0)
        return NULL;

    /* Count healthy backends */
    int healthy_count = 0;
    for (int i = 0; i < rule->backend_count; i++) {
        if (lb_backend_should_retry(&rule->backends[i], rule))
            healthy_count++;
    }

    if (healthy_count == 0) {
        /* All unhealthy - pick random from all */
        return &rule->backends[rand() % rule->backend_count];
    }

    /* Pick random from healthy */
    int pick = rand() % healthy_count;
    for (int i = 0; i < rule->backend_count; i++) {
        if (lb_backend_should_retry(&rule->backends[i], rule)) {
            if (pick == 0)
                return &rule->backends[i];
            pick--;
        }
    }

    return &rule->backends[0];
}

/* Select backend using IP hash algorithm */
static BackendInfo *select_ip_hash(RuleInfo *rule, struct sockaddr_storage *client_addr)
{
    if (rule->backend_count == 0)
        return NULL;

    uint32_t hash = hash_ip_address(client_addr);

    /* Try hash-selected backend first */
    int idx = hash % rule->backend_count;
    BackendInfo *backend = &rule->backends[idx];

    if (lb_backend_should_retry(backend, rule))
        return backend;

    /* If unhealthy, fall back to next healthy backend */
    for (int i = 1; i < rule->backend_count; i++) {
        idx = (hash + i) % rule->backend_count;
        backend = &rule->backends[idx];
        if (lb_backend_should_retry(backend, rule))
            return backend;
    }

    /* All unhealthy - return originally hashed backend */
    return &rule->backends[hash % rule->backend_count];
}

BackendInfo *lb_select_backend(RuleInfo *rule, struct sockaddr_storage *client_addr)
{
    if (!rule || rule->backend_count == 0)
        return NULL;

    /* Single backend - no load balancing needed */
    if (rule->backend_count == 1)
        return &rule->backends[0];

    /* Check affinity table first */
    if (rule->affinity_table && client_addr) {
        int backend_idx = affinity_lookup(rule->affinity_table, client_addr);
        if (backend_idx >= 0 && backend_idx < rule->backend_count) {
            BackendInfo *backend = &rule->backends[backend_idx];
            if (lb_backend_should_retry(backend, rule)) {
                affinity_touch(rule->affinity_table, client_addr);
                return backend;
            }
            /* Affinity backend unhealthy - remove stale entry */
            affinity_remove(rule->affinity_table, client_addr);
        }
    }

    /* Select using algorithm */
    BackendInfo *selected = NULL;

    switch (rule->algorithm) {
        case LB_ROUND_ROBIN:
            if (rule->total_weight == (uint64_t)rule->backend_count) {
                /* All weights equal - use simple round-robin */
                selected = select_round_robin(rule);
            } else {
                /* Weighted round-robin */
                selected = select_weighted_round_robin(rule);
            }
            break;

        case LB_LEAST_CONN:
            selected = select_least_conn(rule);
            break;

        case LB_RANDOM:
            selected = select_random(rule);
            break;

        case LB_IP_HASH:
            selected = select_ip_hash(rule, client_addr);
            break;

        case LB_NONE:
        default:
            /* No LB configured - use first backend */
            selected = &rule->backends[0];
            break;
    }

    /* Store in affinity table if enabled */
    if (selected && rule->affinity_table && client_addr) {
        int idx = (int)(selected - rule->backends);
        affinity_insert(rule->affinity_table, client_addr, idx);
    }

    return selected;
}

void lb_backend_mark_success(BackendInfo *backend, RuleInfo *rule)
{
    if (!backend)
        return;

    int was_unhealthy = !backend->healthy;

    backend->consecutive_failures = 0;
    backend->healthy = 1;

    if (was_unhealthy && rule) {
        rule->healthy_count++;
        logDebug("Backend %s:%s marked healthy (rule: %s, healthy: %d/%d)\n",
                 backend->host ? backend->host : backend->unixPath,
                 backend->port ? backend->port : "",
                 rule->name ? rule->name : "unnamed",
                 rule->healthy_count, rule->backend_count);
    }
}

void lb_backend_mark_failure(BackendInfo *backend, RuleInfo *rule)
{
    if (!backend)
        return;

    backend->consecutive_failures++;
    backend->last_failure_time = time(NULL);

    int threshold = rule ? rule->health_threshold : LB_DEFAULT_HEALTH_THRESHOLD;

    if (backend->healthy && backend->consecutive_failures >= threshold) {
        backend->healthy = 0;
        int recovery = rule ? rule->recovery_timeout : LB_DEFAULT_RECOVERY_TIMEOUT;
        backend->next_retry_time = backend->last_failure_time + recovery;

        if (rule) {
            rule->healthy_count--;
            logWarning("Backend %s:%s marked unhealthy after %d failures (rule: %s, healthy: %d/%d, retry in %ds)\n",
                       backend->host ? backend->host : backend->unixPath,
                       backend->port ? backend->port : "",
                       backend->consecutive_failures,
                       rule->name ? rule->name : "unnamed",
                       rule->healthy_count, rule->backend_count,
                       recovery);
        }
    }
}

int lb_backend_should_retry(BackendInfo *backend, RuleInfo *rule)
{
    if (!backend)
        return 0;

    /* Healthy backends are always available */
    if (backend->healthy)
        return 1;

    /* If all backends unhealthy, try anyway */
    if (rule && rule->healthy_count == 0)
        return 1;

    /* Check if recovery timeout has passed */
    return (time(NULL) >= backend->next_retry_time);
}

void lb_backend_connection_start(BackendInfo *backend)
{
    if (!backend)
        return;

    backend->active_connections++;
    backend->total_connections++;
}

void lb_backend_connection_end(BackendInfo *backend, uint64_t bytes_in, uint64_t bytes_out)
{
    if (!backend)
        return;

    if (backend->active_connections > 0)
        backend->active_connections--;

    backend->total_bytes_in += bytes_in;
    backend->total_bytes_out += bytes_out;
}

void lb_rule_init(RuleInfo *rule)
{
    if (!rule)
        return;

    memset(rule, 0, sizeof(*rule));
    rule->algorithm = LB_NONE;  /* Will be set to LB_ROUND_ROBIN if multiple backends */
    rule->health_threshold = LB_DEFAULT_HEALTH_THRESHOLD;
    rule->recovery_timeout = LB_DEFAULT_RECOVERY_TIMEOUT;
    rule->affinity_ttl = LB_DEFAULT_AFFINITY_TTL;
    rule->affinity_max_entries = LB_DEFAULT_AFFINITY_MAX_ENTRIES;
    rule->keepalive = 1;
}

void lb_backend_init(BackendInfo *backend)
{
    if (!backend)
        return;

    memset(backend, 0, sizeof(*backend));
    backend->healthy = 1;
    backend->weight = LB_DEFAULT_WEIGHT;
    backend->effective_weight = LB_DEFAULT_WEIGHT;

    /* DNS multi-IP tracking */
    backend->dns_parent_name = NULL;
    backend->is_implicit = 0;
    backend->dns_ip_index = 0;
}

void lb_rule_cleanup(RuleInfo *rule)
{
    if (!rule)
        return;

    free(rule->name);

    /* Cleanup backends */
    if (rule->backends) {
        for (int i = 0; i < rule->backend_count; i++)
            lb_backend_cleanup(&rule->backends[i]);
        free(rule->backends);
    }

    /* Cleanup listeners array (but not the listeners themselves - they're managed elsewhere) */
    free(rule->listeners);

    /* Cleanup affinity table */
    if (rule->affinity_table)
        affinity_table_free(rule->affinity_table);

    memset(rule, 0, sizeof(*rule));
}

void lb_free_dup_addrinfo(struct addrinfo *ai)
{
    if (!ai) return;
    free(ai->ai_canonname);
    free(ai->ai_addr);
    free(ai);
}

void lb_backend_cleanup(BackendInfo *backend)
{
    if (!backend)
        return;

    free(backend->name);
    free(backend->host);
    free(backend->port);
    free(backend->unixPath);
    free(backend->host_saved);
    free(backend->port_saved);

    if (backend->addrInfo) {
        if (backend->addrInfo_is_dup)
            lb_free_dup_addrinfo(backend->addrInfo);
        else
            freeaddrinfo(backend->addrInfo);
    }
    if (backend->sourceAddrInfo)
        freeaddrinfo(backend->sourceAddrInfo);

    /* DNS multi-IP tracking cleanup */
    free(backend->dns_parent_name);
    backend->dns_parent_name = NULL;

    /* Note: dns_timer cleanup is handled by the caller (libuv async close) */

    memset(backend, 0, sizeof(*backend));
}

void lb_rule_update_stats(RuleInfo *rule)
{
    if (!rule)
        return;

    rule->total_weight = 0;
    rule->healthy_count = 0;

    for (int i = 0; i < rule->backend_count; i++) {
        BackendInfo *b = &rule->backends[i];
        rule->total_weight += b->weight;
        b->effective_weight = b->healthy ? b->weight : 0;
        if (b->healthy)
            rule->healthy_count++;
    }
}

LbAlgorithm lb_parse_algorithm(const char *name)
{
    if (!name)
        return LB_ROUND_ROBIN;

    if (strcasecmp(name, "roundrobin") == 0 || strcasecmp(name, "round-robin") == 0)
        return LB_ROUND_ROBIN;
    if (strcasecmp(name, "leastconn") == 0 || strcasecmp(name, "least-conn") == 0)
        return LB_LEAST_CONN;
    if (strcasecmp(name, "random") == 0)
        return LB_RANDOM;
    if (strcasecmp(name, "iphash") == 0 || strcasecmp(name, "ip-hash") == 0)
        return LB_IP_HASH;

    logError("Unknown load balancing algorithm: %s\n", name);
    return LB_INVALID;
}

const char *lb_algorithm_name(LbAlgorithm algo)
{
    switch (algo) {
        case LB_ROUND_ROBIN: return "roundrobin";
        case LB_LEAST_CONN: return "leastconn";
        case LB_RANDOM: return "random";
        case LB_IP_HASH: return "iphash";
        case LB_NONE:
        default: return "none";
    }
}
