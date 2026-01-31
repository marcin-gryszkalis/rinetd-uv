/* Copyright © 2026 Marcin Gryszkalis <mg@fork.pl>

   This software is released for free use under the terms of
   the GNU Public License, version 2 or higher. NO WARRANTY
   IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK. */

#pragma once

#include <netinet/in.h>
#include <time.h>
#include "types.h"  /* For AffinityTable typedef */

/* Create a new affinity table
 * max_entries: maximum number of entries (LRU eviction when exceeded)
 * ttl: entry lifetime in seconds (0 = entries never expire)
 * Returns: new affinity table, or NULL on error */
AffinityTable *affinity_table_create(int max_entries, int ttl);

/* Free an affinity table and all its entries */
void affinity_table_free(AffinityTable *table);

/* Look up a client IP in the affinity table
 * Returns: backend index if found and not expired, -1 otherwise */
int affinity_lookup(AffinityTable *table, struct sockaddr_storage *client_addr);

/* Insert or update an affinity mapping
 * client_addr: client IP address (port is ignored)
 * backend_idx: index of the backend to associate */
void affinity_insert(AffinityTable *table, struct sockaddr_storage *client_addr, int backend_idx);

/* Touch an entry (update last_used time, move to LRU head) */
void affinity_touch(AffinityTable *table, struct sockaddr_storage *client_addr);

/* Remove an entry from the affinity table */
void affinity_remove(AffinityTable *table, struct sockaddr_storage *client_addr);

/* Get the number of entries currently in the table */
int affinity_count(AffinityTable *table);

/* Evict expired entries from the table */
void affinity_cleanup_expired(AffinityTable *table);
