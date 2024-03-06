#ifndef _SRC_INCLUDE_NDPIP_UTIL_H_
#define _SRC_INCLUDE_NDPIP_UTIL_H_

#include "ndpip/pbuf.h"

#include <pthread.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef NDPIP_UK
#include "ndpip/uk.h"
#endif

#ifdef NDPIP_LINUX_DPDK
#include "ndpip/linux_dpdk.h"
#endif

struct ndpip_list_head {
	struct ndpip_list_head *next;
	struct ndpip_list_head *prev;
};

#define ETH_P_EQDSCN ETH_P_802_EX1

#define CN_GRANTS_GET 0
#define CN_GRANTS_ADD 1

#define ndpip_list_foreach(type, var, list_head) \
	for ( \
		type *(var) = (type *) (void *) (list_head)->next; \
		((void *) (var)) != ((void *) list_head); \
		(var) = (type *) (void *) ((struct ndpip_list_head *) (void *) (var))->next)

#define ndpip_ring_foreach(type, var, ring) \
	for ( \
		type *(var) = ring->ring_base + ring->ring_start; \
		((((var) - ring->ring_base) - ring->ring_start) < ring->ring_occupied) && \
		((((var) - ring->ring_base) - ring->ring_start) > (ring->ring_length - ring->ring_occupied)); \
		(var) = ring->ring_base + (((var) - ring->ring_base + 1) % ring->ring_length))

#define NDPIP_NSEC_IN_SEC 1000000000L

struct ndpip_timer {
	struct ndpip_list_head list;

	_Atomic bool armed;
	struct timespec timeout;
	void (*func)(void *argp);
	void *argp;
};

struct ndpip_ring {
	struct ndpip_pbuf **ring_base;
	size_t ring_length;
	size_t ring_mask;

	size_t ring_start;
	_Atomic size_t ring_end;
}; 

struct ndpip_hlist_node {
	struct ndpip_list_head hnode_list;
	uint64_t hnode_hash;
	void *hnode_data;
};

struct ndpip_hashtable {
	struct ndpip_list_head *hashtable_buckets;
	uint64_t hashtable_length;
	uint64_t hashtable_mask;
	struct ndpip_mutex lock;
};

struct eqds_cn {
	uint32_t destination;
	uint8_t operation;
	uint32_t value1;
	uint32_t value2;
} __attribute__((packed));

struct ndpip_ring *ndpip_ring_alloc(size_t length);
int ndpip_ring_push(struct ndpip_ring *ring, struct ndpip_pbuf **pbs, size_t count);
int ndpip_ring_push_one(struct ndpip_ring *ring, struct ndpip_pbuf *pb);
int ndpip_ring_pop(struct ndpip_ring *ring, size_t *count, struct ndpip_pbuf **pbs);
int ndpip_ring_peek(struct ndpip_ring *ring, size_t *count, struct ndpip_pbuf **pbs);
int ndpip_ring_flush(struct ndpip_ring *ring, size_t count);
size_t ndpip_ring_size(struct ndpip_ring *ring);
size_t ndpip_ring_free(struct ndpip_ring *ring);

void ndpip_list_init(struct ndpip_list_head *list);
void ndpip_list_add(struct ndpip_list_head *prev, struct ndpip_list_head *entry);
void ndpip_list_del(struct ndpip_list_head *entry);

typedef void (*ndpip_timer_callback_t)(void *argp);

struct ndpip_timer *ndpip_timer_alloc(ndpip_timer_callback_t cb, void *argp);
void ndpip_timer_arm(struct ndpip_timer *timer, struct timespec *timeout);
void ndpip_timer_arm_after(struct ndpip_timer *timer, struct timespec *after);
bool ndpip_timer_armed(struct ndpip_timer *timer);
bool ndpip_timer_expired(struct ndpip_timer *timer);
void ndpip_timer_disarm(struct ndpip_timer *timer);

void ndpip_timespec_add(struct timespec *ts, struct timespec *add);

static inline uint64_t rdtsc(void)
{
	uint64_t l, h;
	asm volatile("rdtsc" : "=a"(l), "=d"(h));
	return (h << 32) | l;
}

struct ndpip_hashtable *ndpip_hashtable_alloc(size_t buckets);
void *ndpip_hashtable_get(struct ndpip_hashtable *hashtable, uint64_t hash);
void ndpip_hashtable_put(struct ndpip_hashtable *hashtable, uint64_t hash, void *data);
void ndpip_hashtable_del(struct ndpip_hashtable *hashtable, uint64_t hash);

#endif
