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
#include <strings.h>
#include <arpa/inet.h>
#include <yaml.h>

#include "yaml_config.h"
#include "loadbalancer.h"
#include "affinity.h"
#include "net.h"
#include "rinetd.h"
#include "log.h"
#include "stats.h"

/* Parser state */
typedef enum {
    STATE_INITIAL,
    STATE_ROOT,
    STATE_GLOBAL,
    STATE_GLOBAL_KEY,
    STATE_STATUS,
    STATE_STATUS_KEY,
    STATE_RULES,
    STATE_RULE,
    STATE_RULE_KEY,
    STATE_BACKENDS,
    STATE_BACKEND,
    STATE_BACKEND_KEY,
    STATE_BIND_LIST,
    STATE_LOAD_BALANCING,
    STATE_LB_KEY,
    STATE_ACCESS,
    STATE_ACCESS_KEY,
    STATE_ACCESS_LIST
} ParserState;

typedef struct {
    YamlConfig *config;
    ParserState state;
    ParserState prev_state;
    char *current_key;

    /* Current rule being parsed */
    RuleInfo *current_rule;

    /* Current backend being parsed */
    BackendInfo *current_backend;

    /* Access control context */
    ruleType current_rule_type;

    /* Error tracking */
    int error;
    char error_msg[256];
} ParserContext;

/* Helper: duplicate string with length limit */
static char *safe_strdup(const char *s, size_t max_len)
{
    if (!s)
        return NULL;
    size_t len = strlen(s);
    if (len > max_len)
        len = max_len;
    char *dup = malloc(len + 1);
    if (dup) {
        memcpy(dup, s, len);
        dup[len] = '\0';
    }
    return dup;
}

/* Helper: parse integer with range check */
static int parse_int(const char *s, int min_val, int max_val, int default_val)
{
    if (!s)
        return default_val;
    char *end;
    long val = strtol(s, &end, 10);
    if (*end != '\0' || val < min_val || val > max_val)
        return default_val;
    return (int)val;
}

/* Helper: parse integer with strict validation - returns -1 on error, sets error message */
static int parse_int_strict(const char *s, int min_val, int max_val, const char *field_name, char *error_msg, size_t error_msg_size)
{
    if (!s || *s == '\0') {
        snprintf(error_msg, error_msg_size, "Missing value for %s", field_name);
        return -1;
    }
    char *end;
    long val = strtol(s, &end, 10);
    if (*end != '\0') {
        snprintf(error_msg, error_msg_size, "Invalid value for %s: '%s' (not a number)", field_name, s);
        return -1;
    }
    if (val < min_val || val > max_val) {
        snprintf(error_msg, error_msg_size, "Value for %s out of range: %ld (must be %d-%d)", field_name, val, min_val, max_val);
        return -1;
    }
    return (int)val;
}

/* Helper: parse boolean */
static int parse_bool(const char *s, int default_val)
{
    if (!s)
        return default_val;
    if (strcasecmp(s, "true") == 0 || strcasecmp(s, "yes") == 0 ||
        strcasecmp(s, "on") == 0 || strcmp(s, "1") == 0)
        return 1;
    if (strcasecmp(s, "false") == 0 || strcasecmp(s, "no") == 0 ||
        strcasecmp(s, "off") == 0 || strcmp(s, "0") == 0)
        return 0;
    return default_val;
}

/* Helper: parse DNS protocol filter (case-insensitive) */
static DnsProtoFilter parse_dns_proto_filter(const char *s, DnsProtoFilter default_val)
{
    if (!s)
        return default_val;
    if (strcasecmp(s, "ipv4") == 0)
        return DNS_PROTO_IPV4;
    if (strcasecmp(s, "ipv6") == 0)
        return DNS_PROTO_IPV6;
    if (strcasecmp(s, "any") == 0)
        return DNS_PROTO_ANY;
    logWarning("Invalid dns_multi_ip_proto value '%s', using default\n", s);
    return default_val;
}

/* Parse address string: "host:port/proto" or "unix:path"
 * Used for both bind addresses and connect destinations */
static int parse_address_string(const char *addr_str, char **host, char **port, int *protocol)
{
    *host = NULL;
    *port = NULL;
    *protocol = IPPROTO_TCP;

    if (!addr_str || strlen(addr_str) == 0)
        return -1;

    /* Check for Unix socket */
    if (strncmp(addr_str, "unix:", 5) == 0) {
        *host = strdup(addr_str);
        *port = NULL;
        *protocol = 0;
        return 0;
    }

    /* Copy for parsing */
    char *copy = strdup(addr_str);
    if (!copy)
        return -1;

    /* Find protocol suffix */
    char *proto_sep = strrchr(copy, '/');
    if (proto_sep) {
        *proto_sep = '\0';
        const char *proto_str = proto_sep + 1;
        if (strcasecmp(proto_str, "tcp") == 0)
            *protocol = IPPROTO_TCP;
        else if (strcasecmp(proto_str, "udp") == 0)
            *protocol = IPPROTO_UDP;
        else {
            logError("Unknown protocol '%s' (must be 'tcp' or 'udp')\n", proto_str);
            free(copy);
            return -1;
        }
    }

    /* Parse host:port or [host]:port */
    char *port_sep;
    if (copy[0] == '[') {
        /* IPv6 address: [::]:port */
        char *bracket = strchr(copy, ']');
        if (!bracket) {
            free(copy);
            return -1;
        }
        *bracket = '\0';
        *host = strdup(copy + 1);
        port_sep = bracket + 1;
        if (*port_sep == ':')
            *port = strdup(port_sep + 1);
        else
            *port = NULL;
    } else {
        /* IPv4 or hostname: host:port */
        port_sep = strrchr(copy, ':');
        if (port_sep) {
            *port_sep = '\0';
            *host = strdup(copy);
            *port = strdup(port_sep + 1);
        } else {
            *host = strdup(copy);
            *port = NULL;
        }
    }

    free(copy);

    /* Validate: port is required for network addresses */
    if (*host && !*port) {
        logError("Missing port in address: %s\n", addr_str);
        free(*host);
        *host = NULL;
        return -1;
    }

    /* Validate port if provided - allow both numbers and service names */
    if (*port) {
        char *end;
        long port_num = strtol(*port, &end, 10);
        /* If it's a valid number, check range */
        if (*end == '\0') {
            if (port_num < 1 || port_num > 65535) {
                logError("Invalid port number in address '%s': %ld (must be 1-65535)\n", addr_str, port_num);
                free(*host);
                free(*port);
                *host = NULL;
                *port = NULL;
                return -1;
            }
        }
        /* Otherwise, assume it's a service name (will be validated by getaddrinfo) */
    }

    return (*host != NULL) ? 0 : -1;
}

/* Backward compatibility alias */
#define parse_bind_address parse_address_string

/* Add a listener to current rule */
static int add_listener_to_rule(ParserContext *ctx, const char *bind_str)
{
    if (!ctx->current_rule || !bind_str)
        return -1;

    RuleInfo *rule = ctx->current_rule;

    /* Parse bind address */
    char *host = NULL, *port = NULL;
    int protocol = IPPROTO_TCP;

    if (parse_bind_address(bind_str, &host, &port, &protocol) != 0) {
        logError("Invalid bind address: %s\n", bind_str);
        return -1;
    }

    /* Create ServerInfo for this listener */
    ServerInfo *srv = calloc(1, sizeof(ServerInfo));
    if (!srv) {
        free(host);
        free(port);
        return -1;
    }

    srv->fromHost = host;
    srv->rule = rule;
    srv->keepalive = rule->keepalive;
    srv->serverTimeout = rule->timeout > 0 ? rule->timeout : RINETD_DEFAULT_UDP_TIMEOUT;
    srv->dns_refresh_period = rule->dns_refresh_period;
    srv->fd = -1;

    /* Check for Unix socket */
    if (isUnixSocketPath(host)) {
        char *path = NULL;
        int is_abstract = 0;
        if (parseUnixSocketPath(host, &path, &is_abstract) != 0) {
            free(srv);
            return -1;
        }
        srv->fromUnixPath = path;
        srv->fromIsAbstract = is_abstract;
        srv->handle_type = UV_NAMED_PIPE;
    } else {
        /* Resolve bind address */
        struct addrinfo *ai = NULL;
        int ret = getAddrInfoWithProto(host, port, protocol, &ai);
        if (ret != 0) {
            free(srv);
            free(port);
            return -1;
        }
        srv->fromAddrInfo = ai;
        srv->handle_type = (protocol == IPPROTO_TCP) ? UV_TCP : UV_UDP;
    }

    free(port);

    /* Add to rule's listeners array */
    if (rule->listener_count >= rule->listener_capacity) {
        int new_cap = rule->listener_capacity ? rule->listener_capacity * 2 : 4;
        ServerInfo **new_listeners = realloc(rule->listeners, new_cap * sizeof(ServerInfo *));
        if (!new_listeners) {
            free(srv->fromUnixPath);
            if (srv->fromAddrInfo) freeaddrinfo(srv->fromAddrInfo);
            free(srv);
            return -1;
        }
        rule->listeners = new_listeners;
        rule->listener_capacity = new_cap;
    }

    rule->listeners[rule->listener_count++] = srv;
    return 0;
}

/* Add a backend from destination string (connect: "host:port/proto") */
static int add_backend_from_dest(ParserContext *ctx, const char *dest_str)
{
    if (!ctx->current_rule || !dest_str)
        return -1;

    char *host = NULL, *port = NULL;
    int protocol = IPPROTO_TCP;

    if (parse_address_string(dest_str, &host, &port, &protocol) != 0) {
        logError("Invalid connect destination: %s\n", dest_str);
        return -1;
    }

    /* Create and initialize backend */
    BackendInfo *backend = calloc(1, sizeof(BackendInfo));
    if (!backend) {
        free(host);
        free(port);
        return -1;
    }
    lb_backend_init(backend);

    /* Check for Unix socket */
    if (isUnixSocketPath(host)) {
        char *path = NULL;
        int is_abstract = 0;
        if (parseUnixSocketPath(host, &path, &is_abstract) != 0) {
            free(host);
            free(port);
            free(backend);
            return -1;
        }
        backend->unixPath = path;
        backend->isAbstract = is_abstract;
        free(host);
    } else {
        backend->host = host;
        backend->port = port;
        backend->protocol = protocol;
    }

    backend->weight = LB_DEFAULT_WEIGHT;
    backend->effective_weight = backend->weight;
    backend->healthy = 1;

    /* Set as current backend for potential additional options */
    ctx->current_backend = backend;

    return 0;
}

/* Duplicate a single addrinfo node (not the chain) */
static struct addrinfo *dup_single_addrinfo(struct addrinfo *src)
{
    struct addrinfo *dst = calloc(1, sizeof(struct addrinfo));
    if (!dst) return NULL;

    dst->ai_flags = src->ai_flags;
    dst->ai_family = src->ai_family;
    dst->ai_socktype = src->ai_socktype;
    dst->ai_protocol = src->ai_protocol;
    dst->ai_addrlen = src->ai_addrlen;
    dst->ai_next = NULL;  /* Break chain */

    if (src->ai_addr) {
        dst->ai_addr = malloc(src->ai_addrlen);
        if (dst->ai_addr)
            memcpy(dst->ai_addr, src->ai_addr, src->ai_addrlen);
    }

    if (src->ai_canonname)
        dst->ai_canonname = strdup(src->ai_canonname);

    return dst;
}

/* Note: format_addr_ip is now format_addr_ip in net.c */

/* Expand backend when DNS returns multiple IPs
 * Returns: 1 if expansion occurred, 0 if single IP or disabled, -1 on error */
static int expand_backend_multi_ip(RuleInfo *rule, BackendInfo *template_backend,
                                    struct addrinfo *ai_list, const char *hostname,
                                    int dns_multi_ip_expand, int dns_multi_ip_proto)
{
    if (!dns_multi_ip_expand)
        return 0;  /* Feature disabled */

    /* Count IPs matching the protocol filter */
    int ip_count = 0;
    int total_ips = 0;
    for (struct addrinfo *ai = ai_list; ai; ai = ai->ai_next) {
        total_ips++;
        /* Filter by protocol */
        if (dns_multi_ip_proto == 4 && ai->ai_family != AF_INET)
            continue;  /* IPv4 filter: skip non-IPv4 */
        if (dns_multi_ip_proto == 6 && ai->ai_family != AF_INET6)
            continue;  /* IPv6 filter: skip non-IPv6 */
        /* dns_multi_ip_proto == 0 (any): accept all */
        ip_count++;
    }

    if (ip_count <= 1)
        return 0;  /* Single IP after filtering - no expansion needed */

    /* Log expansion */
    if (total_ips != ip_count) {
        const char *filter = (dns_multi_ip_proto == 4) ? "IPv4" :
                            (dns_multi_ip_proto == 6) ? "IPv6" : "any";
        logInfo("DNS for %s resolved to %d IPs (%d after %s filter), expanding to separate backends\n",
                hostname, total_ips, ip_count, filter);
    } else {
        logInfo("DNS for %s resolved to %d IPs, expanding to separate backends\n",
                hostname, ip_count);
    }

    /* Expand: create one backend per IP (filtered) */
    struct addrinfo *cur = ai_list;
    int backend_idx = 0;
    for (; cur; cur = cur->ai_next) {
        /* Apply protocol filter */
        if (dns_multi_ip_proto == 4 && cur->ai_family != AF_INET)
            continue;
        if (dns_multi_ip_proto == 6 && cur->ai_family != AF_INET6)
            continue;

        BackendInfo new_backend = *template_backend;  /* Copy template */

        /* Generate unique name: "hostname[0]", "hostname[1]", etc. */
        char name_buf[256];
        snprintf(name_buf, sizeof(name_buf), "%s[%d]", hostname, backend_idx);
        new_backend.name = safe_strdup(name_buf, 255);

        /* Duplicate single addrinfo (break chain) */
        new_backend.addrInfo = dup_single_addrinfo(cur);
        if (!new_backend.addrInfo) {
            logError("Failed to duplicate addrinfo for %s\n", name_buf);
            free(new_backend.name);
            continue;
        }

        /* Set tracking fields */
        new_backend.dns_parent_name = safe_strdup(hostname, 255);
        new_backend.is_implicit = 1;
        new_backend.dns_ip_index = backend_idx;

        /* Duplicate hostname/port (don't use template pointers - they'll be freed) */
        new_backend.host = safe_strdup(hostname, 255);
        new_backend.port = safe_strdup(template_backend->port, 10);
        new_backend.host_saved = safe_strdup(hostname, 255);
        new_backend.port_saved = safe_strdup(template_backend->port, 10);

        /* Log the IP for this backend */
        char ip_buf[INET6_ADDRSTRLEN];
        format_addr_ip(new_backend.addrInfo, ip_buf, sizeof(ip_buf));
        logInfo("  Created implicit backend %s -> %s\n", name_buf, ip_buf);

        /* Add to rule */
        if (rule->backend_count >= rule->backend_capacity) {
            int new_capacity = rule->backend_capacity ? rule->backend_capacity * 2 : 4;
            if (new_capacity > LB_MAX_BACKENDS_PER_RULE)
                new_capacity = LB_MAX_BACKENDS_PER_RULE;
            if (rule->backend_count >= new_capacity) {
                logError("Too many backends for rule (max %d)\n", LB_MAX_BACKENDS_PER_RULE);
                free(new_backend.name);
                free(new_backend.dns_parent_name);
                free(new_backend.host_saved);
                free(new_backend.port_saved);
                freeaddrinfo(new_backend.addrInfo);
                break;
            }
            BackendInfo *new_backends = realloc(rule->backends,
                                                new_capacity * sizeof(BackendInfo));
            if (!new_backends) {
                logError("Failed to expand backends array\n");
                free(new_backend.name);
                free(new_backend.dns_parent_name);
                free(new_backend.host_saved);
                free(new_backend.port_saved);
                freeaddrinfo(new_backend.addrInfo);
                break;
            }
            rule->backends = new_backends;
            rule->backend_capacity = new_capacity;
        }

        rule->backends[rule->backend_count++] = new_backend;
        backend_idx++;
    }

    return 1;  /* Expansion occurred */
}

/* Add a backend to current rule */
static int add_backend_to_rule(ParserContext *ctx)
{
    if (!ctx->current_rule || !ctx->current_backend)
        return 0;

    RuleInfo *rule = ctx->current_rule;
    BackendInfo *backend = ctx->current_backend;

    /* Validate backend has either host or unixPath */
    if (!backend->host && !backend->unixPath) {
        logError("Backend must have a 'dest' field with address\n");
        lb_backend_cleanup(backend);
        free(backend);
        ctx->current_backend = NULL;
        return -1;
    }

    /* Set default weight if not specified */
    if (backend->weight <= 0)
        backend->weight = LB_DEFAULT_WEIGHT;
    backend->effective_weight = backend->weight;

    /* Resolve backend address if not Unix socket */
    if (backend->host && !backend->unixPath) {
        int protocol = rule->listeners && rule->listener_count > 0 ?
            (rule->listeners[0]->handle_type == UV_UDP ? IPPROTO_UDP : IPPROTO_TCP) : IPPROTO_TCP;
        backend->protocol = protocol;

        struct addrinfo *ai = NULL;
        int ret = getAddrInfoWithProto(backend->host, backend->port, protocol, &ai);
        if (ret != 0) {
            lb_backend_cleanup(backend);
            free(backend);
            ctx->current_backend = NULL;
            return -1;
        }

        /* Try multi-IP expansion */
        int expanded = expand_backend_multi_ip(rule, backend, ai, backend->host,
                                                ctx->config->dns_multi_ip_expand,
                                                ctx->config->dns_multi_ip_proto);

        if (expanded == 1) {
            /* Expansion occurred - backends already added, free template and addrinfo */
            lb_backend_cleanup(backend);
            free(backend);
            ctx->current_backend = NULL;
            freeaddrinfo(ai);
            return 0;  /* Success */
        }

        /* No expansion - use first IP as normal (backward compatible) */
        backend->addrInfo = ai;
        backend->is_implicit = 0;  /* Explicit backend */
        backend->dns_parent_name = NULL;

        /* Save for DNS refresh */
        backend->host_saved = strdup(backend->host);
        backend->port_saved = backend->port ? strdup(backend->port) : NULL;
    }

    /* Add to rule's backends array */
    if (rule->backend_count >= rule->backend_capacity) {
        int new_cap = rule->backend_capacity ? rule->backend_capacity * 2 : 4;
        if (new_cap > LB_MAX_BACKENDS_PER_RULE)
            new_cap = LB_MAX_BACKENDS_PER_RULE;
        if (rule->backend_count >= new_cap) {
            logError("Too many backends for rule %s (max %d)\n",
                     rule->name ? rule->name : "unnamed", LB_MAX_BACKENDS_PER_RULE);
            lb_backend_cleanup(backend);
            free(backend);
            ctx->current_backend = NULL;
            return -1;
        }
        BackendInfo *new_backends = realloc(rule->backends, new_cap * sizeof(BackendInfo));
        if (!new_backends) {
            lb_backend_cleanup(backend);
            free(backend);
            ctx->current_backend = NULL;
            return -1;
        }
        rule->backends = new_backends;
        rule->backend_capacity = new_cap;
    }

    /* Copy backend into array */
    rule->backends[rule->backend_count] = *backend;
    rule->backend_count++;

    /* Free the temporary struct (but not its contents - they're now in the array) */
    free(backend);
    ctx->current_backend = NULL;

    return 0;
}

/* Finalize current rule */
static int finalize_rule(ParserContext *ctx)
{
    if (!ctx->current_rule)
        return 0;

    RuleInfo *rule = ctx->current_rule;

    /* Finalize any pending backend */
    if (ctx->current_backend)
        add_backend_to_rule(ctx);

    /* Validate rule has a name */
    if (!rule->name || rule->name[0] == '\0') {
        logError("Rule missing required 'name' field\n");
        return -1;
    }

    /* Check for duplicate rule names */
    YamlConfig *config = ctx->config;
    for (int i = 0; i < config->rule_count; i++) {
        if (config->rules[i].name && strcmp(config->rules[i].name, rule->name) == 0) {
            logError("Duplicate rule name: '%s'\n", rule->name);
            return -1;
        }
    }

    /* Validate rule has at least one listener and one backend */
    if (rule->listener_count == 0) {
        logError("Rule '%s' has no bind addresses\n", rule->name);
        return -1;
    }
    if (rule->backend_count == 0) {
        logError("Rule '%s' has no backends\n", rule->name);
        return -1;
    }

    /* Validate: UDP cannot be used with Unix socket backends */
    int has_udp_listener = 0;
    for (int i = 0; i < rule->listener_count; i++) {
        if (rule->listeners[i]->handle_type == UV_UDP) {
            has_udp_listener = 1;
            break;
        }
    }
    if (has_udp_listener) {
        for (int i = 0; i < rule->backend_count; i++) {
            if (rule->backends[i].unixPath) {
                logError("Rule '%s': UDP cannot forward to Unix socket backend\n", rule->name);
                return -1;
            }
        }
    }

    /* Auto-generate backend names if not specified */
    for (int i = 0; i < rule->backend_count; i++) {
        if (!rule->backends[i].name) {
            char auto_name[256];
            snprintf(auto_name, sizeof(auto_name), "%s-backend-%d", rule->name, i + 1);
            rule->backends[i].name = strdup(auto_name);
        }
    }

    /* Set default algorithm if multiple backends and none specified */
    if (rule->backend_count > 1 && rule->algorithm == LB_NONE)
        rule->algorithm = LB_ROUND_ROBIN;

    /* Create affinity table if needed */
    if (rule->affinity_ttl > 0) {
        rule->affinity_table = affinity_table_create(rule->affinity_max_entries, rule->affinity_ttl);
    }

    /* Update stats (total_weight, healthy_count) */
    lb_rule_update_stats(rule);

    /* Warn if LB options on single backend */
    if (rule->backend_count == 1 && rule->algorithm != LB_NONE) {
        logWarning("Rule '%s' has load_balancing options but only one backend - options ignored\n",
                   rule->name ? rule->name : "unnamed");
        rule->algorithm = LB_NONE;
    }

    /* Set toHost and toAddrInfo on listeners for legacy compatibility */
    for (int i = 0; i < rule->listener_count; i++) {
        ServerInfo *srv = rule->listeners[i];
        /* Point to first backend for logging purposes */
        if (rule->backends[0].host)
            srv->toHost = strdup(rule->backends[0].host);
        else if (rule->backends[0].unixPath)
            srv->toHost = strdup(rule->backends[0].unixPath);
    }

    /* Add rule to config */
    if (config->rule_count >= config->rule_capacity) {
        int new_cap = config->rule_capacity ? config->rule_capacity * 2 : 8;
        RuleInfo *new_rules = realloc(config->rules, new_cap * sizeof(RuleInfo));
        if (!new_rules)
            return -1;
        config->rules = new_rules;
        config->rule_capacity = new_cap;
    }

    config->rules[config->rule_count] = *rule;
    config->rule_count++;

    free(rule);
    ctx->current_rule = NULL;

    return 0;
}

/* Process a scalar value based on current state */
static void process_scalar(ParserContext *ctx, const char *value)
{
    if (ctx->error)
        return;

    switch (ctx->state) {
        case STATE_GLOBAL_KEY: {
            if (!ctx->current_key)
                break;

            int val;
            char err_msg[256];

            if (strcmp(ctx->current_key, "buffer_size") == 0) {
                val = parse_int_strict(value, 1024, 1024*1024, "buffer_size", err_msg, sizeof(err_msg));
                if (val < 0) {
                    logError("%s\n", err_msg);
                    ctx->error = 1;
                } else {
                    ctx->config->buffer_size = val;
                }
            } else if (strcmp(ctx->current_key, "dns_refresh") == 0) {
                val = parse_int_strict(value, 0, 86400*7, "dns_refresh", err_msg, sizeof(err_msg));
                if (val < 0) {
                    logError("%s\n", err_msg);
                    ctx->error = 1;
                } else {
                    ctx->config->dns_refresh = val;
                }
            } else if (strcmp(ctx->current_key, "log_file") == 0) {
                ctx->config->log_file = safe_strdup(value, 4096);
            } else if (strcmp(ctx->current_key, "pid_file") == 0) {
                ctx->config->pid_file = safe_strdup(value, 4096);
            } else if (strcmp(ctx->current_key, "log_common") == 0) {
                ctx->config->log_common = parse_bool(value, 0);
            } else if (strcmp(ctx->current_key, "max_udp_connections") == 0) {
                val = parse_int_strict(value, 100, 1000000, "max_udp_connections", err_msg, sizeof(err_msg));
                if (val < 0) {
                    logError("%s\n", err_msg);
                    ctx->error = 1;
                } else {
                    ctx->config->max_udp_connections = val;
                }
            } else if (strcmp(ctx->current_key, "listen_backlog") == 0) {
                val = parse_int_strict(value, 1, 65535, "listen_backlog", err_msg, sizeof(err_msg));
                if (val < 0) {
                    logError("%s\n", err_msg);
                    ctx->error = 1;
                } else {
                    ctx->config->listen_backlog = val;
                }
            } else if (strcmp(ctx->current_key, "pool_min_free") == 0) {
                val = parse_int_strict(value, 0, 100000, "pool_min_free", err_msg, sizeof(err_msg));
                if (val < 0) {
                    logError("%s\n", err_msg);
                    ctx->error = 1;
                } else {
                    ctx->config->pool_min_free = val;
                }
            } else if (strcmp(ctx->current_key, "pool_max_free") == 0) {
                val = parse_int_strict(value, 0, 100000, "pool_max_free", err_msg, sizeof(err_msg));
                if (val < 0) {
                    logError("%s\n", err_msg);
                    ctx->error = 1;
                } else {
                    ctx->config->pool_max_free = val;
                }
            } else if (strcmp(ctx->current_key, "pool_trim_delay") == 0) {
                val = parse_int_strict(value, 0, 3600000, "pool_trim_delay", err_msg, sizeof(err_msg));
                if (val < 0) {
                    logError("%s\n", err_msg);
                    ctx->error = 1;
                } else {
                    ctx->config->pool_trim_delay = val;
                }
            } else if (strcmp(ctx->current_key, "dns_multi_ip_expand") == 0) {
                ctx->config->dns_multi_ip_expand = parse_bool(value, 1);
            } else if (strcmp(ctx->current_key, "dns_multi_ip_proto") == 0) {
                ctx->config->dns_multi_ip_proto = parse_dns_proto_filter(value, DNS_PROTO_IPV4);
            } else if (strcmp(ctx->current_key, "stats_log_interval") == 0) {
                val = parse_int_strict(value, 0, 86400, "stats_log_interval", err_msg, sizeof(err_msg));
                if (val < 0) {
                    logError("%s\n", err_msg);
                    ctx->error = 1;
                } else {
                    ctx->config->stats_log_interval = val;
                }
            } else if (strcmp(ctx->current_key, "status") == 0) {
                /* status is a mapping, not a scalar - handled in MAPPING_START */
                logWarning("'status' should be a mapping block, not a scalar value\n");
            } else {
                logWarning("Unknown global option: %s\n", ctx->current_key);
            }

            free(ctx->current_key);
            ctx->current_key = NULL;
            ctx->state = STATE_GLOBAL;
            break;
        }

        case STATE_STATUS_KEY: {
            if (!ctx->current_key)
                break;

            int val;
            char err_msg[256];

            if (strcmp(ctx->current_key, "enabled") == 0) {
                ctx->config->status.enabled = parse_bool(value, 0);
            } else if (strcmp(ctx->current_key, "file") == 0) {
                free(ctx->config->status.file);
                ctx->config->status.file = safe_strdup(value, 4096);
            } else if (strcmp(ctx->current_key, "interval") == 0) {
                val = parse_int_strict(value, 1, 86400, "status.interval", err_msg, sizeof(err_msg));
                if (val < 0) {
                    logError("%s\n", err_msg);
                    ctx->error = 1;
                } else {
                    ctx->config->status.interval = val;
                }
            } else if (strcmp(ctx->current_key, "format") == 0) {
                if (strcasecmp(value, "json") == 0)
                    ctx->config->status.format_json = 1;
                else if (strcasecmp(value, "text") == 0)
                    ctx->config->status.format_json = 0;
                else
                    logWarning("Unknown status format: %s (using json)\n", value);
            } else {
                logWarning("Unknown status option: %s\n", ctx->current_key);
            }

            free(ctx->current_key);
            ctx->current_key = NULL;
            ctx->state = STATE_STATUS;
            break;
        }

        case STATE_RULE_KEY:
            if (!ctx->current_key || !ctx->current_rule)
                break;

            if (strcmp(ctx->current_key, "name") == 0) {
                free(ctx->current_rule->name);
                ctx->current_rule->name = safe_strdup(value, 256);
            } else if (strcmp(ctx->current_key, "bind") == 0) {
                /* Single bind address as scalar */
                if (add_listener_to_rule(ctx, value) != 0)
                    ctx->error = 1;
            } else if (strcmp(ctx->current_key, "timeout") == 0) {
                ctx->current_rule->timeout = parse_int(value, 1, 86400, RINETD_DEFAULT_UDP_TIMEOUT);
            } else if (strcmp(ctx->current_key, "keepalive") == 0) {
                ctx->current_rule->keepalive = parse_bool(value, 1);
            } else if (strcmp(ctx->current_key, "mode") == 0) {
                /* Parse octal mode like "0660" */
                ctx->current_rule->timeout = (int)strtol(value, NULL, 8);
            } else if (strcmp(ctx->current_key, "connect") == 0) {
                /* Single connect destination as scalar: connect: "host:port/proto" */
                if (add_backend_from_dest(ctx, value) != 0 || add_backend_to_rule(ctx) != 0)
                    ctx->error = 1;
            } else {
                logWarning("Unknown rule option: %s\n", ctx->current_key);
            }

            free(ctx->current_key);
            ctx->current_key = NULL;
            ctx->state = STATE_RULE;
            break;

        case STATE_BIND_LIST:
            if (add_listener_to_rule(ctx, value) != 0)
                ctx->error = 1;
            break;

        case STATE_BACKEND_KEY:
            if (!ctx->current_key || !ctx->current_backend)
                break;

            if (strcmp(ctx->current_key, "name") == 0) {
                free(ctx->current_backend->name);
                ctx->current_backend->name = safe_strdup(value, 256);
            } else if (strcmp(ctx->current_key, "dest") == 0) {
                /* Parse destination address: "host:port/proto" or "unix:path" */
                char *host = NULL, *port = NULL;
                int protocol = IPPROTO_TCP;
                if (parse_address_string(value, &host, &port, &protocol) == 0) {
                    if (isUnixSocketPath(host)) {
                        char *path = NULL;
                        int is_abstract = 0;
                        if (parseUnixSocketPath(host, &path, &is_abstract) == 0) {
                            ctx->current_backend->unixPath = path;
                            ctx->current_backend->isAbstract = is_abstract;
                        } else {
                            logError("Invalid Unix socket path: %s\n", host);
                            ctx->error = 1;
                        }
                        free(host);
                    } else {
                        ctx->current_backend->host = host;
                        ctx->current_backend->port = port;
                        ctx->current_backend->protocol = protocol;
                    }
                } else {
                    logError("Invalid dest address: %s\n", value);
                    ctx->error = 1;
                }
            } else if (strcmp(ctx->current_key, "weight") == 0) {
                char err_msg[256];
                int val = parse_int_strict(value, 1, 100, "weight", err_msg, sizeof(err_msg));
                if (val < 0) {
                    logError("%s\n", err_msg);
                    ctx->error = 1;
                } else {
                    ctx->current_backend->weight = val;
                }
            } else if (strcmp(ctx->current_key, "dns_refresh") == 0) {
                ctx->current_backend->dns_refresh_period = parse_int(value, 0, 86400*7, 0);
            } else if (strcmp(ctx->current_key, "src") == 0) {
                /* Source address for outgoing connections */
                int protocol = IPPROTO_TCP;
                struct addrinfo *ai = NULL;
                if (getAddrInfoWithProto((char *)value, NULL, protocol, &ai) == 0)
                    ctx->current_backend->sourceAddrInfo = ai;
            } else {
                logWarning("Unknown backend option: %s\n", ctx->current_key);
            }

            free(ctx->current_key);
            ctx->current_key = NULL;
            ctx->state = STATE_BACKEND;
            break;

        case STATE_LB_KEY: {
            if (!ctx->current_key || !ctx->current_rule)
                break;

            int val;
            char err_msg[256];

            if (strcmp(ctx->current_key, "algorithm") == 0) {
                LbAlgorithm algo = lb_parse_algorithm(value);
                if (algo == LB_INVALID)
                    ctx->error = 1;
                else
                    ctx->current_rule->algorithm = algo;
            } else if (strcmp(ctx->current_key, "health_threshold") == 0) {
                val = parse_int_strict(value, 1, 100, "health_threshold", err_msg, sizeof(err_msg));
                if (val < 0) {
                    logError("%s\n", err_msg);
                    ctx->error = 1;
                } else {
                    ctx->current_rule->health_threshold = val;
                }
            } else if (strcmp(ctx->current_key, "recovery_timeout") == 0) {
                val = parse_int_strict(value, 1, 86400, "recovery_timeout", err_msg, sizeof(err_msg));
                if (val < 0) {
                    logError("%s\n", err_msg);
                    ctx->error = 1;
                } else {
                    ctx->current_rule->recovery_timeout = val;
                }
            } else if (strcmp(ctx->current_key, "affinity_ttl") == 0) {
                val = parse_int_strict(value, 0, 86400*30, "affinity_ttl", err_msg, sizeof(err_msg));
                if (val < 0) {
                    logError("%s\n", err_msg);
                    ctx->error = 1;
                } else {
                    ctx->current_rule->affinity_ttl = val;
                }
            } else if (strcmp(ctx->current_key, "affinity_max_entries") == 0) {
                val = parse_int_strict(value, 100, 10000000, "affinity_max_entries", err_msg, sizeof(err_msg));
                if (val < 0) {
                    logError("%s\n", err_msg);
                    ctx->error = 1;
                } else {
                    ctx->current_rule->affinity_max_entries = val;
                }
            } else {
                logWarning("Unknown load_balancing option: %s\n", ctx->current_key);
            }

            free(ctx->current_key);
            ctx->current_key = NULL;
            ctx->state = STATE_LOAD_BALANCING;
            break;
        }

        case STATE_ACCESS_LIST:
            /* Add allow/deny pattern to global rules array */
            if (ctx->current_rule && value) {
                /* We need to add to global allRules array */
                extern Rule *allRules;
                extern int allRulesCount;

                allRules = realloc(allRules, (allRulesCount + 1) * sizeof(Rule));
                if (allRules) {
                    allRules[allRulesCount].pattern = strdup(value);
                    allRules[allRulesCount].type = ctx->current_rule_type;
                    if (ctx->current_rule->rulesCount == 0)
                        ctx->current_rule->rulesStart = allRulesCount;
                    ctx->current_rule->rulesCount++;
                    allRulesCount++;
                }
            }
            break;

        default:
            break;
    }
}

/* Process YAML events */
static int process_event(ParserContext *ctx, yaml_event_t *event)
{
    if (ctx->error)
        return -1;

    switch (event->type) {
        case YAML_STREAM_START_EVENT:
        case YAML_DOCUMENT_START_EVENT:
            ctx->state = STATE_INITIAL;
            break;

        case YAML_STREAM_END_EVENT:
        case YAML_DOCUMENT_END_EVENT:
            /* Finalize any pending rule */
            if (ctx->current_rule && finalize_rule(ctx) != 0)
                ctx->error = 1;
            break;

        case YAML_MAPPING_START_EVENT:
            switch (ctx->state) {
                case STATE_INITIAL:
                    ctx->state = STATE_ROOT;
                    break;
                case STATE_ROOT:
                    if (ctx->current_key) {
                        if (strcmp(ctx->current_key, "global") == 0) {
                            ctx->state = STATE_GLOBAL;
                        } else {
                            logWarning("Unknown root key: %s\n", ctx->current_key);
                        }
                        free(ctx->current_key);
                        ctx->current_key = NULL;
                    }
                    break;
                case STATE_GLOBAL_KEY:
                    /* Entering a nested mapping under global (e.g., status:) */
                    if (ctx->current_key) {
                        if (strcmp(ctx->current_key, "status") == 0) {
                            ctx->state = STATE_STATUS;
                        } else {
                            logWarning("Unknown global mapping: %s\n", ctx->current_key);
                            ctx->state = STATE_GLOBAL;
                        }
                        free(ctx->current_key);
                        ctx->current_key = NULL;
                    }
                    break;
                case STATE_RULES:
                    /* New rule */
                    ctx->current_rule = calloc(1, sizeof(RuleInfo));
                    if (ctx->current_rule)
                        lb_rule_init(ctx->current_rule);
                    ctx->state = STATE_RULE;
                    break;
                case STATE_BACKENDS:
                    /* New backend */
                    if (ctx->current_backend && add_backend_to_rule(ctx) != 0) {
                        ctx->error = 1;
                        break;
                    }
                    ctx->current_backend = calloc(1, sizeof(BackendInfo));
                    if (ctx->current_backend)
                        lb_backend_init(ctx->current_backend);
                    ctx->state = STATE_BACKEND;
                    break;
                case STATE_RULE_KEY:
                    if (ctx->current_key) {
                        if (strcmp(ctx->current_key, "load_balancing") == 0) {
                            ctx->state = STATE_LOAD_BALANCING;
                        } else if (strcmp(ctx->current_key, "access") == 0) {
                            ctx->state = STATE_ACCESS;
                        }
                        free(ctx->current_key);
                        ctx->current_key = NULL;
                    }
                    break;
                default:
                    break;
            }
            break;

        case YAML_MAPPING_END_EVENT:
            switch (ctx->state) {
                case STATE_GLOBAL:
                    ctx->state = STATE_ROOT;
                    break;
                case STATE_STATUS:
                    ctx->state = STATE_GLOBAL;
                    break;
                case STATE_RULE:
                    if (finalize_rule(ctx) != 0)
                        ctx->error = 1;
                    ctx->state = STATE_RULES;
                    break;
                case STATE_BACKEND:
                    if (add_backend_to_rule(ctx) != 0)
                        ctx->error = 1;
                    ctx->state = STATE_BACKENDS;
                    break;
                case STATE_LOAD_BALANCING:
                    ctx->state = STATE_RULE;
                    break;
                case STATE_ACCESS:
                    ctx->state = STATE_RULE;
                    break;
                case STATE_ROOT:
                    ctx->state = STATE_INITIAL;
                    break;
                default:
                    break;
            }
            break;

        case YAML_SEQUENCE_START_EVENT:
            switch (ctx->state) {
                case STATE_ROOT:
                    if (ctx->current_key && strcmp(ctx->current_key, "rules") == 0) {
                        ctx->state = STATE_RULES;
                        free(ctx->current_key);
                        ctx->current_key = NULL;
                    }
                    break;
                case STATE_RULE_KEY:
                    if (ctx->current_key) {
                        if (strcmp(ctx->current_key, "bind") == 0) {
                            ctx->state = STATE_BIND_LIST;
                        } else if (strcmp(ctx->current_key, "connect") == 0) {
                            ctx->state = STATE_BACKENDS;
                        }
                        free(ctx->current_key);
                        ctx->current_key = NULL;
                    }
                    break;
                case STATE_ACCESS_KEY:
                    if (ctx->current_key) {
                        if (strcmp(ctx->current_key, "allow") == 0) {
                            ctx->current_rule_type = allowRule;
                            ctx->state = STATE_ACCESS_LIST;
                        } else if (strcmp(ctx->current_key, "deny") == 0) {
                            ctx->current_rule_type = denyRule;
                            ctx->state = STATE_ACCESS_LIST;
                        }
                        free(ctx->current_key);
                        ctx->current_key = NULL;
                    }
                    break;
                default:
                    break;
            }
            break;

        case YAML_SEQUENCE_END_EVENT:
            switch (ctx->state) {
                case STATE_RULES:
                    ctx->state = STATE_ROOT;
                    break;
                case STATE_BIND_LIST:
                    ctx->state = STATE_RULE;
                    break;
                case STATE_BACKENDS:
                    if (ctx->current_backend && add_backend_to_rule(ctx) != 0)
                        ctx->error = 1;
                    ctx->state = STATE_RULE;
                    break;
                case STATE_ACCESS_LIST:
                    ctx->state = STATE_ACCESS;
                    break;
                default:
                    break;
            }
            break;

        case YAML_SCALAR_EVENT: {
            const char *value = (const char *)event->data.scalar.value;

            switch (ctx->state) {
                case STATE_ROOT:
                    ctx->current_key = safe_strdup(value, 64);
                    break;
                case STATE_GLOBAL:
                    ctx->current_key = safe_strdup(value, 64);
                    ctx->state = STATE_GLOBAL_KEY;
                    break;
                case STATE_GLOBAL_KEY:
                    process_scalar(ctx, value);
                    break;
                case STATE_STATUS:
                    ctx->current_key = safe_strdup(value, 64);
                    ctx->state = STATE_STATUS_KEY;
                    break;
                case STATE_STATUS_KEY:
                    process_scalar(ctx, value);
                    break;
                case STATE_RULE:
                    ctx->current_key = safe_strdup(value, 64);
                    ctx->state = STATE_RULE_KEY;
                    break;
                case STATE_RULE_KEY:
                    process_scalar(ctx, value);
                    break;
                case STATE_BIND_LIST:
                    process_scalar(ctx, value);
                    break;
                case STATE_BACKEND:
                    ctx->current_key = safe_strdup(value, 64);
                    ctx->state = STATE_BACKEND_KEY;
                    break;
                case STATE_BACKEND_KEY:
                    process_scalar(ctx, value);
                    break;
                case STATE_LOAD_BALANCING:
                    ctx->current_key = safe_strdup(value, 64);
                    ctx->state = STATE_LB_KEY;
                    break;
                case STATE_LB_KEY:
                    process_scalar(ctx, value);
                    break;
                case STATE_ACCESS:
                    ctx->current_key = safe_strdup(value, 64);
                    ctx->state = STATE_ACCESS_KEY;
                    break;
                case STATE_ACCESS_LIST:
                    process_scalar(ctx, value);
                    break;
                default:
                    break;
            }
            break;
        }

        default:
            break;
    }

    return 0;
}

int yaml_config_is_yaml_file(const char *filename)
{
    if (!filename)
        return 0;

    size_t len = strlen(filename);
    if (len >= 5 && strcasecmp(filename + len - 5, ".yaml") == 0)
        return 1;
    if (len >= 4 && strcasecmp(filename + len - 4, ".yml") == 0)
        return 1;

    return 0;
}

YamlConfig *yaml_config_parse(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (!file) {
        logError("Cannot open YAML config file: %s\n", filename);
        return NULL;
    }

    YamlConfig *config = calloc(1, sizeof(YamlConfig));
    if (!config) {
        fclose(file);
        return NULL;
    }

    /* Set defaults */
    config->buffer_size = RINETD_DEFAULT_BUFFER_SIZE;
    config->dns_refresh = RINETD_DEFAULT_DNS_REFRESH_PERIOD;
    config->max_udp_connections = RINETD_DEFAULT_MAX_UDP_CONNECTIONS;
    config->listen_backlog = RINETD_DEFAULT_LISTEN_BACKLOG;
    config->pool_min_free = RINETD_DEFAULT_POOL_MIN_FREE;
    config->pool_max_free = RINETD_DEFAULT_POOL_MAX_FREE;
    config->pool_trim_delay = RINETD_DEFAULT_POOL_TRIM_DELAY;

    /* Status reporting defaults */
    config->status.enabled = 0;
    config->status.file = NULL;
    config->status.interval = 30;
    config->status.format_json = 1;
    config->stats_log_interval = 60;

    /* DNS multi-IP expansion (enabled by default for YAML) */
    config->dns_multi_ip_expand = 1;
    config->dns_multi_ip_proto = DNS_PROTO_IPV4;  /* Default: IPv4 only */

    yaml_parser_t parser;
    yaml_event_t event;

    if (!yaml_parser_initialize(&parser)) {
        logError("Failed to initialize YAML parser\n");
        free(config);
        fclose(file);
        return NULL;
    }

    yaml_parser_set_input_file(&parser, file);

    ParserContext ctx = {
        .config = config,
        .state = STATE_INITIAL,
        .error = 0
    };

    int done = 0;
    while (!done && !ctx.error) {
        if (!yaml_parser_parse(&parser, &event)) {
            logError("YAML parse error at line %zu: %s\n",
                     parser.problem_mark.line + 1,
                     parser.problem ? parser.problem : "unknown error");
            ctx.error = 1;
            break;
        }

        if (event.type == YAML_STREAM_END_EVENT)
            done = 1;

        process_event(&ctx, &event);
        yaml_event_delete(&event);
    }

    yaml_parser_delete(&parser);
    fclose(file);

    if (ctx.error) {
        yaml_config_free(config);
        return NULL;
    }

    /* Validate for duplicate bind addresses across all rules */
    for (int i = 0; i < config->rule_count; i++) {
        RuleInfo *rule_i = &config->rules[i];
        for (int li = 0; li < rule_i->listener_count; li++) {
            ServerInfo *srv_i = rule_i->listeners[li];

            /* Check against all subsequent rules */
            for (int j = i; j < config->rule_count; j++) {
                RuleInfo *rule_j = &config->rules[j];
                int start_lj = (j == i) ? li + 1 : 0;  /* Skip same listener */

                for (int lj = start_lj; lj < rule_j->listener_count; lj++) {
                    ServerInfo *srv_j = rule_j->listeners[lj];

                    /* Must be same handle type (TCP, UDP, or PIPE) */
                    if (srv_i->handle_type != srv_j->handle_type)
                        continue;

                    /* Compare Unix socket paths */
                    if (srv_i->fromUnixPath && srv_j->fromUnixPath) {
                        if (strcmp(srv_i->fromUnixPath, srv_j->fromUnixPath) == 0 &&
                            srv_i->fromIsAbstract == srv_j->fromIsAbstract) {

                            logError("Duplicate Unix socket bind '%s' in rules '%s' and '%s'\n",
                                     srv_i->fromUnixPath,
                                     rule_i->name ? rule_i->name : "unnamed",
                                     rule_j->name ? rule_j->name : "unnamed");
                            yaml_config_free(config);
                            return NULL;
                        }
                        continue;
                    }

                    /* Compare network addresses (TCP/UDP) */
                    if (srv_i->fromAddrInfo && srv_j->fromAddrInfo) {
                        struct sockaddr *addr_i = srv_i->fromAddrInfo->ai_addr;
                        struct sockaddr *addr_j = srv_j->fromAddrInfo->ai_addr;

                        /* Must be same address family */
                        if (addr_i->sa_family != addr_j->sa_family)
                            continue;

                        /* Compare IPv4 addresses */
                        if (addr_i->sa_family == AF_INET) {
                            struct sockaddr_in *in_i = (struct sockaddr_in *)addr_i;
                            struct sockaddr_in *in_j = (struct sockaddr_in *)addr_j;

                            if (in_i->sin_addr.s_addr == in_j->sin_addr.s_addr &&
                                in_i->sin_port == in_j->sin_port) {

                                char addr_str[128];
                                snprintf(addr_str, sizeof(addr_str), "%s:%d/%s",
                                         srv_i->fromHost,
                                         ntohs(in_i->sin_port),
                                         srv_i->handle_type == UV_TCP ? "tcp" : "udp");

                                logError("Duplicate bind address '%s' in rules '%s' and '%s'\n",
                                         addr_str,
                                         rule_i->name ? rule_i->name : "unnamed",
                                         rule_j->name ? rule_j->name : "unnamed");
                                yaml_config_free(config);
                                return NULL;
                            }
                        }
                        /* Compare IPv6 addresses */
                        else if (addr_i->sa_family == AF_INET6) {
                            struct sockaddr_in6 *in6_i = (struct sockaddr_in6 *)addr_i;
                            struct sockaddr_in6 *in6_j = (struct sockaddr_in6 *)addr_j;

                            if (memcmp(&in6_i->sin6_addr, &in6_j->sin6_addr, sizeof(struct in6_addr)) == 0 &&
                                in6_i->sin6_port == in6_j->sin6_port) {

                                char addr_str[128];
                                snprintf(addr_str, sizeof(addr_str), "%s:%d/%s",
                                         srv_i->fromHost,
                                         ntohs(in6_i->sin6_port),
                                         srv_i->handle_type == UV_TCP ? "tcp" : "udp");

                                logError("Duplicate bind address '%s' in rules '%s' and '%s'\n",
                                         addr_str,
                                         rule_i->name ? rule_i->name : "unnamed",
                                         rule_j->name ? rule_j->name : "unnamed");
                                yaml_config_free(config);
                                return NULL;
                            }
                        }
                    }
                }
            }
        }
    }

    logInfo("Loaded YAML config: %d rule(s)\n", config->rule_count);
    return config;
}

void yaml_config_free(YamlConfig *config)
{
    if (!config)
        return;

    free(config->log_file);
    free(config->pid_file);
    free(config->status.file);

    /* Free rules */
    for (int i = 0; i < config->rule_count; i++) {
        RuleInfo *rule = &config->rules[i];

        /* Free listeners */
        for (int j = 0; j < rule->listener_count; j++) {
            ServerInfo *srv = rule->listeners[j];
            free(srv->fromHost);
            free(srv->toHost);
            free(srv->fromUnixPath);
            free(srv->toUnixPath);
            if (srv->fromAddrInfo) freeaddrinfo(srv->fromAddrInfo);
            if (srv->toAddrInfo) freeaddrinfo(srv->toAddrInfo);
            if (srv->sourceAddrInfo) freeaddrinfo(srv->sourceAddrInfo);
            free(srv);
        }
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
    free(config->rules);

    free(config);
}

void yaml_config_apply_globals(YamlConfig *config)
{
    if (!config)
        return;

    bufferSize = config->buffer_size;
    globalDnsRefreshPeriod = config->dns_refresh;
    globalDnsMultiIpExpand = config->dns_multi_ip_expand;
    globalDnsMultiIpProto = config->dns_multi_ip_proto;
    maxUdpConnections = config->max_udp_connections;
    listenBacklog = config->listen_backlog;
    poolMinFree = config->pool_min_free;
    poolMaxFree = config->pool_max_free;
    poolTrimDelay = config->pool_trim_delay;

    if (config->log_file) {
        extern char *logFileName;
        free(logFileName);
        logFileName = strdup(config->log_file);
    }

    if (config->pid_file) {
        free(pidFileName);
        pidFileName = strdup(config->pid_file);
    }

    if (config->log_common) {
        extern int logFormatCommon;
        logFormatCommon = 1;
    }

    /* Apply status reporting configuration */
    {
        extern StatusConfig statusConfig;
        extern int statsLogInterval;

        statusConfig.enabled = config->status.enabled;
        free(statusConfig.file);
        statusConfig.file = config->status.file ? strdup(config->status.file) : NULL;
        statusConfig.interval = config->status.interval;
        statusConfig.format = config->status.format_json ? STATUS_FORMAT_JSON : STATUS_FORMAT_TEXT;
        statsLogInterval = config->stats_log_interval;
    }
}

RuleInfo *yaml_config_get_rules(YamlConfig *config, int *count)
{
    if (!config || !count)
        return NULL;

    *count = config->rule_count;
    return config->rules;
}
