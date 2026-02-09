/* Copyright © 2026 Marcin Gryszkalis <mg@fork.pl>

   This software is released for free use under the terms of
   the GNU Public License, version 2 or higher. NO WARRANTY
   IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK. */

#pragma once

#include <stdint.h>

/* Initialize the buffer pool with given parameters
 * buffer_size: Size of each buffer in bytes
 * min_free: Minimum buffers to keep in pool (won't trim below this)
 * max_free: Maximum buffers in pool (excess freed immediately)
 * trim_delay_ms: Milliseconds pool must be oversized before trimming */
void buffer_pool_init(int buffer_size, int min_free, int max_free, int trim_delay_ms);

/* Close buffer pool timer (call before event loop cleanup) */
void buffer_pool_close_timer(void);

/* Shutdown the buffer pool, freeing all buffers */
void buffer_pool_shutdown(void);

/* Update pool configuration (called on SIGHUP)
 * Stale buffers (wrong size) are handled on return to pool */
void buffer_pool_update_config(int buffer_size, int min_free, int max_free, int trim_delay_ms);

/* Allocate a buffer from the pool (or malloc if pool empty) */
char *buffer_pool_alloc(void);

/* Return a buffer to the pool
 * size: The actual size of the buffer (for SIGHUP size change detection)
 * If size doesn't match current pool size, buffer is freed directly */
void buffer_pool_free(char *buffer, int size);

/* Pre-allocate min_free buffers (call after init for warm start) */
void buffer_pool_warm(void);

/* Force immediate trim to min_free (for testing/debugging) */
void buffer_pool_trim_now(void);

/* Statistics access */
typedef struct _buffer_pool_stats {
    uint64_t allocs_from_pool;
    uint64_t allocs_from_malloc;
    uint64_t returns_to_pool;
    uint64_t returns_freed;
    int current_free;
    int buffer_size;
} BufferPoolStats;

void buffer_pool_get_stats(BufferPoolStats *stats);
