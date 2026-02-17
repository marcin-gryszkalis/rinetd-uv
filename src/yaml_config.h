/* Copyright © 2026 Marcin Gryszkalis <mg@fork.pl>

   This software is released for free use under the terms of
   the GNU Public License, version 2 or higher. NO WARRANTY
   IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK. */

#pragma once

#include "types.h"

/* DNS multi-IP protocol filter */
typedef enum {
    DNS_PROTO_ANY = 0,
    DNS_PROTO_IPV4 = 4,
    DNS_PROTO_IPV6 = 6
} DnsProtoFilter;

/* Status file configuration (parsed from YAML) */
typedef struct _yaml_status_config YamlStatusConfig;
struct _yaml_status_config {
    int enabled;
    char *file;
    int interval;       /* Seconds between writes (default: 30) */
    int format_json;    /* 1 = JSON (default), 0 = text */
};

/* Result structure for YAML parsing */
typedef struct _yaml_config YamlConfig;
struct _yaml_config {
    /* Global settings (applied to globals) */
    int buffer_size;
    int dns_refresh;
    char *log_file;
    char *pid_file;
    int log_common;
    int max_udp_connections;
    int listen_backlog;
    int pool_min_free;
    int pool_max_free;
    int pool_trim_delay;

    /* Status reporting */
    YamlStatusConfig status;
    int stats_log_interval;     /* Seconds, 0 = disabled (default: 60) */

    /* Backend connect timeout */
    int connect_timeout;        /* Backend TCP connect timeout in seconds (0 = OS default) */

    /* DNS multi-IP expansion */
    int dns_multi_ip_expand;    /* Enable DNS multi-IP expansion to backends */
    DnsProtoFilter dns_multi_ip_proto;  /* Protocol filter: ipv4, ipv6, or any */

    /* Global access rules (prepended to allRules before per-rule rules) */
    Rule *global_rules;
    int global_rules_count;
    int global_rules_capacity;

    /* Rules */
    RuleInfo *rules;
    int rule_count;
    int rule_capacity;
};

/* Check if a file is a YAML configuration file (by extension) */
int yaml_config_is_yaml_file(const char *filename);

/* Parse a YAML configuration file
 * Returns: YamlConfig structure on success, NULL on error
 * Caller must call yaml_config_free() when done */
YamlConfig *yaml_config_parse(const char *filename);

/* Free a YamlConfig structure */
void yaml_config_free(YamlConfig *config);

/* Apply YamlConfig global settings to the global variables */
void yaml_config_apply_globals(YamlConfig *config);

/* Get the array of rules from the config (for initialization) */
RuleInfo *yaml_config_get_rules(YamlConfig *config, int *count);
