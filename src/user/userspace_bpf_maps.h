#ifndef USERSPACE_BPF_MAPS_H_GUARD
#define USERSPACE_BPF_MAPS_H_GUARD
#ifndef __bpf__

#include "uthash.h"

#include <linux/bpf.h>
#include <unistd.h>
#include <sched.h>

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define CACHE_LINE_SIZE 64
#define ROUND_UP_CL_SIZE(x) ((x + (CACHE_LINE_SIZE-1)) & ~(CACHE_LINE_SIZE-1))

const long NUM_CPUS = sysconf(_SC_NPROCESSORS_CONF);

typedef struct {
    enum bpf_map_type type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
} map_spec_t;

typedef struct {
    enum bpf_map_type type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned char map_data[];
} map_t;

typedef struct {
    enum bpf_map_type type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int allocated_size;
    unsigned char map_data[];
} map_array_t;

typedef struct {
    UT_hash_handle hh;
    unsigned char key_value[];
} hash_elem_t;

typedef struct {
    enum bpf_map_type type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    hash_elem_t *hash[];
} map_hash_t;

map_t *bpf_map_create(const map_spec_t *spec)
{
    map_t *ret = NULL;

    switch (spec->type) {
    case BPF_MAP_TYPE_ARRAY:
    {
        unsigned int size = spec->value_size * spec->max_entries;
        map_array_t *map = (map_array_t*)malloc(sizeof(map_array_t) + size);
        if (!map) return NULL;
        map->allocated_size = size;
        ret = (map_t*)map;
    }
    case BPF_MAP_TYPE_PERCPU_ARRAY:
    {
        unsigned int perCpuSize = ROUND_UP_CL_SIZE(spec->value_size * spec->max_entries);
        unsigned int size = NUM_CPUS * perCpuSize;
        map_array_t *map = (map_array_t*)malloc(sizeof(map_array_t) + size);
        if (!map) return NULL;
        map->allocated_size = size;
        ret = (map_t*)map;
    }
    case BPF_MAP_TYPE_HASH:
    {
        unsigned int size = sizeof(hash_elem_t*);
        ret = (map_t*)malloc(sizeof(map_hash_t) + size);
        break;
    }
    case BPF_MAP_TYPE_PERCPU_HASH:
    {
        unsigned int size = NUM_CPUS * sizeof(hash_elem_t*);
        ret = (map_t*)malloc(sizeof(map_hash_t) + size);
        break;
    }
    default:
        return NULL;
    }

    ret->type = spec->type;
    ret->key_size = spec->key_size;
    ret->value_size = spec->value_size;
    ret->max_entries = spec->max_entries;
    return ret;
}

void bpf_map_destroy(map_t *map)
{
    switch (map->type) {
    case BPF_MAP_TYPE_ARRAY:
    case BPF_MAP_TYPE_PERCPU_ARRAY:
        free(map);
        break;
    case BPF_MAP_TYPE_HASH:
        bpf_map_hash_destroy((map_hash_t*)map);
        break;
    case BPF_MAP_TYPE_PERCPU_HASH:
        bpf_map_percpu_hash_destroy((map_hash_t*)map);
        break;
    default:
        break;
    }
}

void* bpf_map_lookup_elem(map_t *map, const void *key)
{
    switch (map->type) {
    case BPF_MAP_TYPE_ARRAY:
        return bpf_map_array_lookup_elem((map_array_t*)map, key);
    case BPF_MAP_TYPE_PERCPU_ARRAY:
        return bpf_map_percpu_array_lookup_elem((map_array_t*)map, key);
    case BPF_MAP_TYPE_HASH:
        return NULL;
    default:
        return NULL;
    }
}

long bpf_map_update_elem(map_t *map, const void *key, const void *value, uint64_t flags)
{
    switch (map->type) {
    case BPF_MAP_TYPE_ARRAY:
        return bpf_map_array_update_elem((map_array_t*)map, key, value);
    case BPF_MAP_TYPE_PERCPU_ARRAY:
        return bpf_map_percpu_array_update_elem((map_array_t*)map, key, value);
    case BPF_MAP_TYPE_HASH:
        return -1;
    default:
        return -1;
    }
}

long bpf_map_delete_elem(map_t *map, const void *key, const void *value, uint64_t flags)
{
    switch (map->type) {
    case BPF_MAP_TYPE_ARRAY:
        return -1;
    case BPF_MAP_TYPE_PERCPU_ARRAY:
        return -1;
    case BPF_MAP_TYPE_HASH:
        return -1;
    default:
        return -1;
    }
}

static void* bpf_map_array_lookup_elem(map_array_t *map, const void *key)
{
    uint64_t index = 0;
    if (map->key_size > sizeof(index))
        return NULL;
    memcpy(&index, key, map->key_size);

    if (((index + 1) * map->value_size) > map->allocated_size)
        return NULL;

    return map->map_data + (index * map->value_size);
}

static long bpf_map_array_update_elem(map_array_t *map, const void *key, const void *value)
{
    uint64_t index = 0;
    if (map->key_size > sizeof(index))
        return -1;
    memcpy(&index, key, map->key_size);

    if (((index + 1) * map->value_size) > map->allocated_size)
        return -1;

    unsigned char *ptr = map->map_data + (index * map->value_size);
    memcpy(ptr, value, map->value_size);

    return 0;
}

static void* bpf_map_percpu_array_lookup_elem(map_array_t *map, const void *key)
{
    uint64_t index = 0;
    if (map->key_size > sizeof(index))
        return NULL;
    memcpy(&index, key, map->key_size);

    unsigned int perCpuSize = ROUND_UP_CL_SIZE(map->value_size * map->max_entries);
    unsigned int cpuIndex = 0;
    if (getcpu(&cpuIndex, NULL))
        return NULL;

    unsigned int offset = cpuIndex * perCpuSize + index * map->value_size;

    if (offset + map->value_size > map->allocated_size)
        return NULL;

    return map->map_data + offset;
}

static long bpf_map_percpu_array_update_elem(map_array_t *map, const void *key, const void *value)
{
    uint64_t index = 0;
    if (map->key_size > sizeof(index))
        return -1;
    memcpy(&index, key, map->key_size);

    unsigned int perCpuSize = ROUND_UP_CL_SIZE(map->value_size * map->max_entries);
    unsigned int cpuIndex = 0;
    if (getcpu(&cpuIndex, NULL))
        return NULL;

    unsigned int offset = cpuIndex * perCpuSize + index * map->value_size;

    if (offset + map->value_size > map->allocated_size)
        return NULL;

    unsigned char *ptr = map->map_data + (index * map->value_size);
    memcpy(ptr, value, map->value_size);

    return 0;
}

static void bpf_map_hash_destroy(map_hash_t *map)
{
    hash_elem_t *head = ((map_hash_t*)map)->hash[0];
    hash_elem_t *el, *tmp;
    HASH_ITER(hh, head, el, tmp) {
        HASH_DEL(head, el);
        free(el);
    }
    free(map);
}

static void bpf_map_percpu_hash_destroy(map_hash_t *map)
{
    for (unsigned int i = 0; i < NUM_CPUS; ++i) {
        hash_elem_t *head = ((map_hash_t*)map)->hash[i];
        hash_elem_t *el, *tmp;
        HASH_ITER(hh, head, el, tmp) {
            HASH_DEL(head, el);
            free(el);
        }
    }
    free(map);
}

#endif // __bpf__
#endif // USERSPACE_BPF_MAPS_H_GUARD
