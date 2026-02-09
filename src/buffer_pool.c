/* Copyright © 2026 Marcin Gryszkalis <mg@fork.pl>

   This software is released for free use under the terms of
   the GNU Public License, version 2 or higher. NO WARRANTY
   IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK. */

#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include "buffer_pool.h"
#include "log.h"
#include "net.h"
#include "rinetd.h"

typedef struct _buffer_node BufferNode;
struct _buffer_node {
    char *data;
    BufferNode *next;
};

typedef struct _buffer_pool BufferPool;
struct _buffer_pool {
    BufferNode *free_list;
    int free_count;
    int buffer_size;

    int min_free;
    int max_free;
    int trim_delay_ms;

    uv_timer_t trim_timer;
    int trim_timer_initialized;
    int trim_timer_active;
    int trim_timer_closing;
    uint64_t oversized_since;

    uint64_t allocs_from_pool;
    uint64_t allocs_from_malloc;
    uint64_t returns_to_pool;
    uint64_t returns_freed;
};

static BufferPool pool;

static void trim_timer_cb(uv_timer_t *handle);
static void start_trim_timer(void);
static void stop_trim_timer(void);

void buffer_pool_init(int buffer_size, int min_free, int max_free, int trim_delay_ms)
{
    memset(&pool, 0, sizeof(pool));
    pool.buffer_size = buffer_size;
    pool.min_free = min_free;
    pool.max_free = max_free;
    pool.trim_delay_ms = trim_delay_ms;
}

static void trim_timer_close_cb(uv_handle_t *handle)
{
    (void)handle;
    pool.trim_timer_closing = 0;
    pool.trim_timer_initialized = 0;
}

void buffer_pool_close_timer(void)
{
    /* Stop and close trim timer (must be called before event loop cleanup) */
    if (pool.trim_timer_initialized && !pool.trim_timer_closing) {
        if (pool.trim_timer_active) {
            uv_timer_stop(&pool.trim_timer);
            pool.trim_timer_active = 0;
        }
        pool.trim_timer_closing = 1;
        uv_close((uv_handle_t *)&pool.trim_timer, trim_timer_close_cb);
    }
}

void buffer_pool_shutdown(void)
{
    /* Close timer if not already closed */
    buffer_pool_close_timer();

    /* Free all buffers in the pool */
    while (pool.free_list) {
        BufferNode *node = pool.free_list;
        pool.free_list = node->next;
        free(node->data);
        free(node);
        pool.free_count--;
    }
}

void buffer_pool_update_config(int buffer_size, int min_free, int max_free, int trim_delay_ms)
{
    int size_changed = (buffer_size != pool.buffer_size);

    pool.buffer_size = buffer_size;
    pool.min_free = min_free;
    pool.max_free = max_free;
    pool.trim_delay_ms = trim_delay_ms;

    if (size_changed) {
        while (pool.free_list) {
            BufferNode *node = pool.free_list;
            pool.free_list = node->next;
            free(node->data);
            free(node);
            pool.free_count--;
        }
        pool.oversized_since = 0;
        if (pool.trim_timer_active)
            stop_trim_timer();
    }

    if (pool.free_count > pool.min_free && pool.oversized_since == 0) {
        pool.oversized_since = uv_now(main_loop);
        start_trim_timer();
    }
}

char *buffer_pool_alloc(void)
{
    char *buf;

    if (pool.free_list) {
        BufferNode *node = pool.free_list;
        pool.free_list = node->next;
        buf = node->data;
        free(node);
        pool.free_count--;
        pool.allocs_from_pool++;

        if (pool.free_count <= pool.min_free)
            pool.oversized_since = 0;
    } else {
        buf = malloc(pool.buffer_size);
        if (buf)
            pool.allocs_from_malloc++;
    }

    return buf;
}

void buffer_pool_free(char *buffer, int size)
{
    if (!buffer)
        return;

    if (size != pool.buffer_size) {
        free(buffer);
        pool.returns_freed++;
        return;
    }

    if (pool.free_count >= pool.max_free) {
        free(buffer);
        pool.returns_freed++;
        return;
    }

    BufferNode *node = malloc(sizeof(BufferNode));
    if (!node) {
        free(buffer);
        pool.returns_freed++;
        return;
    }

    node->data = buffer;
    node->next = pool.free_list;
    pool.free_list = node;
    pool.free_count++;
    pool.returns_to_pool++;

    if (pool.free_count > pool.min_free && pool.oversized_since == 0) {
        pool.oversized_since = uv_now(main_loop);
        start_trim_timer();
    }
}

void buffer_pool_warm(void)
{
    while (pool.free_count < pool.min_free) {
        char *buf = malloc(pool.buffer_size);
        if (!buf)
            break;

        BufferNode *node = malloc(sizeof(BufferNode));
        if (!node) {
            free(buf);
            break;
        }

        node->data = buf;
        node->next = pool.free_list;
        pool.free_list = node;
        pool.free_count++;
    }
}

void buffer_pool_trim_now(void)
{
    while (pool.free_count > pool.min_free) {
        BufferNode *node = pool.free_list;
        if (!node)
            break;
        pool.free_list = node->next;
        free(node->data);
        free(node);
        pool.free_count--;
    }
    pool.oversized_since = 0;
    if (pool.trim_timer_active)
        stop_trim_timer();
}

static void start_trim_timer(void)
{
    if (pool.trim_timer_active || pool.trim_timer_closing)
        return;

    if (!pool.trim_timer_initialized) {
        int ret = uv_timer_init(main_loop, &pool.trim_timer);
        if (ret != 0) {
            logError("uv_timer_init(trim_timer) failed: %s\n", uv_strerror(ret));
            return;
        }
        pool.trim_timer_initialized = 1;
    }

    int ret = uv_timer_start(&pool.trim_timer, trim_timer_cb, pool.trim_delay_ms, pool.trim_delay_ms);
    if (ret != 0) {
        logError("uv_timer_start(trim_timer) failed: %s\n", uv_strerror(ret));
        return;
    }
    pool.trim_timer_active = 1;
}

static void stop_trim_timer(void)
{
    if (!pool.trim_timer_active)
        return;

    uv_timer_stop(&pool.trim_timer);
    pool.trim_timer_active = 0;
}

static void trim_timer_cb(uv_timer_t *handle)
{
    (void)handle;

    if (pool.free_count <= pool.min_free) {
        pool.oversized_since = 0;
        stop_trim_timer();
        return;
    }

    if (pool.oversized_since == 0) {
        stop_trim_timer();
        return;
    }

    uint64_t now = uv_now(main_loop);
    if ((now - pool.oversized_since) >= (uint64_t)pool.trim_delay_ms) {
        while (pool.free_count > pool.min_free) {
            BufferNode *node = pool.free_list;
            if (!node)
                break;
            pool.free_list = node->next;
            free(node->data);
            free(node);
            pool.free_count--;
        }
        pool.oversized_since = 0;
        stop_trim_timer();
    }
}

void buffer_pool_get_stats(BufferPoolStats *stats)
{
    if (!stats)
        return;
    stats->allocs_from_pool = pool.allocs_from_pool;
    stats->allocs_from_malloc = pool.allocs_from_malloc;
    stats->returns_to_pool = pool.returns_to_pool;
    stats->returns_freed = pool.returns_freed;
    stats->current_free = pool.free_count;
    stats->buffer_size = pool.buffer_size;
}
