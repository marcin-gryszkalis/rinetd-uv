/* Copyright © 2026 Marcin Gryszkalis <mg@fork.pl>

   This software is released for free use under the terms of
   the GNU Public License, version 2 or higher. NO WARRANTY
   IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK. */

#pragma once

#include "types.h"
#include <netinet/in.h>

/* Default values for load balancing configuration */
static int const LB_DEFAULT_HEALTH_THRESHOLD = 3;
static int const LB_DEFAULT_RECOVERY_TIMEOUT = 30;
static int const LB_DEFAULT_AFFINITY_TTL = 0;
static int const LB_DEFAULT_AFFINITY_MAX_ENTRIES = 10000;
static int const LB_DEFAULT_WEIGHT = 1;
static int const LB_MAX_BACKENDS_PER_RULE = 100;
static int const LB_MAX_LISTENERS_PER_RULE = 10;

/* Backend selection - main entry point for load balancing
 * Returns the selected backend, or NULL if no backends available
 * The client_addr is used for IP-hash and affinity lookups */
BackendInfo *lb_select_backend(RuleInfo *rule, struct sockaddr_storage *client_addr);

/* Health tracking - call on connection success/failure */
void lb_backend_mark_success(BackendInfo *backend, RuleInfo *rule);
void lb_backend_mark_failure(BackendInfo *backend, RuleInfo *rule);

/* Check if a backend should be retried (for recovery) */
int lb_backend_should_retry(BackendInfo *backend, RuleInfo *rule);

/* Statistics update - call when connection closes */
void lb_backend_connection_start(BackendInfo *backend);
void lb_backend_connection_end(BackendInfo *backend, uint64_t bytes_in, uint64_t bytes_out);

/* Initialize a new RuleInfo with defaults */
void lb_rule_init(RuleInfo *rule);

/* Initialize a new BackendInfo with defaults */
void lb_backend_init(BackendInfo *backend);

/* Free resources associated with a RuleInfo */
void lb_rule_cleanup(RuleInfo *rule);

/* Free resources associated with a BackendInfo */
void lb_backend_cleanup(BackendInfo *backend);

/* Recalculate total_weight and healthy_count for a rule */
void lb_rule_update_stats(RuleInfo *rule);

/* Parse algorithm name string to enum */
LbAlgorithm lb_parse_algorithm(const char *name);

/* Get algorithm name from enum */
const char *lb_algorithm_name(LbAlgorithm algo);
