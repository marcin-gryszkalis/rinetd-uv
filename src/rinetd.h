/* Copyright © 1997—1999 Thomas Boutell <boutell@boutell.com>
                         and Boutell.Com, Inc.
             © 2003—2021 Sam Hocevar <sam@hocevar.net>
             © 2026 Marcin Gryszkalis <mg@fork.pl>

   This software is released for free use under the terms of
   the GNU Public License, version 2 or higher. NO WARRANTY
   IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK. */

#pragma once

#include "types.h"
#include <stdint.h>
#include <uv.h>

/* Constants */

static int const RINETD_DEFAULT_BUFFER_SIZE = 65536;
static int const RINETD_DEFAULT_LISTEN_BACKLOG = 128;
static int const RINETD_DEFAULT_UDP_TIMEOUT = 10;
static int const RINETD_DEFAULT_DNS_REFRESH_PERIOD = 600;
static int const RINETD_DEFAULT_MAX_UDP_CONNECTIONS = 5000;
static int const RINETD_DEFAULT_POOL_MIN_FREE = 64;
static int const RINETD_DEFAULT_POOL_MAX_FREE = 1024;
static int const RINETD_DEFAULT_POOL_TRIM_DELAY = 60000;

static int const RINETD_DNS_REFRESH_FAILURE_THRESHOLD = 3;
static int const RINETD_CLEANUP_MAX_ITERATIONS = 1000;

#define RINETD_CONFIG_FILE_YAML "/etc/rinetd-uv.yaml"
#define RINETD_CONFIG_FILE_YML "/etc/rinetd-uv.yml"
#define RINETD_CONFIG_FILE_CONF "/etc/rinetd-uv.conf"
#define RINETD_PID_FILE "/var/run/rinetd-uv.pid"
#define MAX_INCLUDE_DEPTH 10

/* Global configuration */

extern Rule *allRules;
extern int allRulesCount;
extern int globalRulesCount;

extern ServerInfo *seInfo;
extern int seTotal;

extern char *pidFileName;
extern int bufferSize;
extern int globalDnsRefreshPeriod;
extern int poolMinFree;
extern int poolMaxFree;
extern int poolTrimDelay;
extern int listenBacklog;
extern int maxUdpConnections;

/* libuv event loop */
extern uv_loop_t *main_loop;

/* YAML configuration state */
extern RuleInfo *yamlRules;
extern int yamlRulesCount;
extern int usingYamlConfig;

/* Functions */
void addServer(char *bindAddress, char *bindPort, int bindProtocol,
               char *connectAddress, char *connectPort, int connectProtocol,
               int serverTimeout, char *sourceAddress, int keepalive,
               int dns_refresh_period, int socketMode);

/* Initialize servers from YAML rules (called after yaml_config_parse) */
void initializeFromYamlRules(void);
