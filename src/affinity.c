/* Copyright © 2026 Marcin Gryszkalis <mg@fork.pl>

   This software is released for free use under the terms of
   the GNU Public License, version 2 or higher. NO WARRANTY
   IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK. */

#if HAVE_CONFIG_H
#   include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "affinity.h"

/* Prime number for hash table size (good distribution) */
#define AFFINITY_HASH_SIZE 4099

/* Single affinity entry */
typedef struct _affinity_entry AffinityEntry;
struct _affinity_entry {
    struct sockaddr_storage client_ip;  /* Key (port ignored) */
    int backend_idx;                    /* Value */
    time_t last_used;                   /* For TTL and LRU */

    /* Hash table chaining */
    AffinityEntry *hash_next;

    /* LRU doubly-linked list */
    AffinityEntry *lru_prev;
    AffinityEntry *lru_next;
};

/* Affinity table structure */
struct _affinity_table {
    AffinityEntry **buckets;    /* Hash table buckets */
    int bucket_count;
    int entry_count;
    int max_entries;
    int ttl;                    /* Entry TTL in seconds, 0 = no expiry */

    /* LRU list (most recent at head, least recent at tail) */
    AffinityEntry *lru_head;
    AffinityEntry *lru_tail;
};

/* Hash function for IP addresses (ignores port) */
static uint32_t hash_client_ip(struct sockaddr_storage *addr)
{
    uint32_t hash = 0;

    if (addr->ss_family == AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
        hash = addr4->sin_addr.s_addr;
    } else if (addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        uint32_t *words = (uint32_t *)&addr6->sin6_addr;
        hash = words[0] ^ words[1] ^ words[2] ^ words[3];
    }

    /* Mix hash bits */
    hash ^= (hash >> 16);
    hash *= 0x85ebca6b;
    hash ^= (hash >> 13);

    return hash;
}

/* Compare two client IPs (ignoring port) */
static int same_client_ip(struct sockaddr_storage *a, struct sockaddr_storage *b)
{
    if (a->ss_family != b->ss_family)
        return 0;

    if (a->ss_family == AF_INET) {
        struct sockaddr_in *a4 = (struct sockaddr_in *)a;
        struct sockaddr_in *b4 = (struct sockaddr_in *)b;
        return a4->sin_addr.s_addr == b4->sin_addr.s_addr;
    } else if (a->ss_family == AF_INET6) {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)a;
        struct sockaddr_in6 *b6 = (struct sockaddr_in6 *)b;
        return memcmp(&a6->sin6_addr, &b6->sin6_addr, 16) == 0;
    }

    return 0;
}

/* Remove entry from LRU list */
static void lru_remove(AffinityTable *table, AffinityEntry *entry)
{
    if (entry->lru_prev)
        entry->lru_prev->lru_next = entry->lru_next;
    else
        table->lru_head = entry->lru_next;

    if (entry->lru_next)
        entry->lru_next->lru_prev = entry->lru_prev;
    else
        table->lru_tail = entry->lru_prev;

    entry->lru_prev = entry->lru_next = NULL;
}

/* Insert entry at LRU head (most recently used) */
static void lru_insert_head(AffinityTable *table, AffinityEntry *entry)
{
    entry->lru_prev = NULL;
    entry->lru_next = table->lru_head;

    if (table->lru_head)
        table->lru_head->lru_prev = entry;
    else
        table->lru_tail = entry;

    table->lru_head = entry;
}

/* Move entry to LRU head */
static void lru_touch(AffinityTable *table, AffinityEntry *entry)
{
    lru_remove(table, entry);
    lru_insert_head(table, entry);
}

/* Remove entry from hash table */
static void hash_remove(AffinityTable *table, AffinityEntry *entry)
{
    uint32_t bucket = hash_client_ip(&entry->client_ip) % table->bucket_count;

    AffinityEntry **prev_ptr = &table->buckets[bucket];
    while (*prev_ptr) {
        if (*prev_ptr == entry) {
            *prev_ptr = entry->hash_next;
            return;
        }
        prev_ptr = &(*prev_ptr)->hash_next;
    }
}

/* Free a single entry */
static void entry_free(AffinityTable *table, AffinityEntry *entry)
{
    lru_remove(table, entry);
    hash_remove(table, entry);
    free(entry);
    table->entry_count--;
}

/* Evict the least recently used entry */
static void evict_lru(AffinityTable *table)
{
    if (table->lru_tail)
        entry_free(table, table->lru_tail);
}

AffinityTable *affinity_table_create(int max_entries, int ttl)
{
    AffinityTable *table = malloc(sizeof(AffinityTable));
    if (!table)
        return NULL;

    table->bucket_count = AFFINITY_HASH_SIZE;
    table->buckets = calloc(table->bucket_count, sizeof(AffinityEntry *));
    if (!table->buckets) {
        free(table);
        return NULL;
    }

    table->entry_count = 0;
    table->max_entries = max_entries > 0 ? max_entries : 10000;
    table->ttl = ttl;
    table->lru_head = NULL;
    table->lru_tail = NULL;

    return table;
}

void affinity_table_free(AffinityTable *table)
{
    if (!table)
        return;

    /* Free all entries via LRU list */
    AffinityEntry *entry = table->lru_head;
    while (entry) {
        AffinityEntry *next = entry->lru_next;
        free(entry);
        entry = next;
    }

    free(table->buckets);
    free(table);
}

int affinity_lookup(AffinityTable *table, struct sockaddr_storage *client_addr)
{
    if (!table || !client_addr)
        return -1;

    uint32_t bucket = hash_client_ip(client_addr) % table->bucket_count;

    for (AffinityEntry *entry = table->buckets[bucket]; entry; entry = entry->hash_next) {
        if (same_client_ip(&entry->client_ip, client_addr)) {
            /* Check TTL */
            if (table->ttl > 0) {
                time_t now = time(NULL);
                if (now - entry->last_used > table->ttl) {
                    entry_free(table, entry);
                    return -1;
                }
            }
            return entry->backend_idx;
        }
    }

    return -1;
}

void affinity_insert(AffinityTable *table, struct sockaddr_storage *client_addr, int backend_idx)
{
    if (!table || !client_addr)
        return;

    uint32_t bucket = hash_client_ip(client_addr) % table->bucket_count;

    /* Check if entry already exists */
    for (AffinityEntry *entry = table->buckets[bucket]; entry; entry = entry->hash_next) {
        if (same_client_ip(&entry->client_ip, client_addr)) {
            /* Update existing entry */
            entry->backend_idx = backend_idx;
            entry->last_used = time(NULL);
            lru_touch(table, entry);
            return;
        }
    }

    /* Evict if at capacity */
    while (table->entry_count >= table->max_entries)
        evict_lru(table);

    /* Create new entry */
    AffinityEntry *entry = malloc(sizeof(AffinityEntry));
    if (!entry)
        return;

    memcpy(&entry->client_ip, client_addr, sizeof(struct sockaddr_storage));
    entry->backend_idx = backend_idx;
    entry->last_used = time(NULL);

    /* Insert into hash table */
    entry->hash_next = table->buckets[bucket];
    table->buckets[bucket] = entry;

    /* Insert into LRU list */
    entry->lru_prev = entry->lru_next = NULL;
    lru_insert_head(table, entry);

    table->entry_count++;
}

void affinity_touch(AffinityTable *table, struct sockaddr_storage *client_addr)
{
    if (!table || !client_addr)
        return;

    uint32_t bucket = hash_client_ip(client_addr) % table->bucket_count;

    for (AffinityEntry *entry = table->buckets[bucket]; entry; entry = entry->hash_next) {
        if (same_client_ip(&entry->client_ip, client_addr)) {
            entry->last_used = time(NULL);
            lru_touch(table, entry);
            return;
        }
    }
}

void affinity_remove(AffinityTable *table, struct sockaddr_storage *client_addr)
{
    if (!table || !client_addr)
        return;

    uint32_t bucket = hash_client_ip(client_addr) % table->bucket_count;

    for (AffinityEntry *entry = table->buckets[bucket]; entry; entry = entry->hash_next) {
        if (same_client_ip(&entry->client_ip, client_addr)) {
            entry_free(table, entry);
            return;
        }
    }
}

int affinity_count(AffinityTable *table)
{
    return table ? table->entry_count : 0;
}

void affinity_cleanup_expired(AffinityTable *table)
{
    if (!table || table->ttl <= 0)
        return;

    time_t now = time(NULL);

    /* Walk LRU list from tail (oldest entries) */
    AffinityEntry *entry = table->lru_tail;
    while (entry) {
        AffinityEntry *prev = entry->lru_prev;
        if (now - entry->last_used > table->ttl)
            entry_free(table, entry);
        else
            break;  /* Remaining entries are newer */
        entry = prev;
    }
}
