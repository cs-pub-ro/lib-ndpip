#ifndef _SRC_INCLUDE_NDPIP_UTIL_H_
#define _SRC_INCLUDE_NDPIP_UTIL_H_

#include <time.h>

#include "ndpip/pbuf.h"

struct ndpip_list_head {
	struct ndpip_list_head *next;
	struct ndpip_list_head *prev;
};

#define NDPIP_LIST_HEAD(name) struct ndpip_list_head name = { (&name), (&name) };

#define ndpip_list_foreach(type, var, list_head) \
	for ( \
		type *(var) = (type *) (void *) (list_head)->next; \
		((void *) (var)) != ((void *) list_head); \
		(var) = (type *) (void *) ((struct ndpip_list_head *) (void *) (var))->next)

#define ndpip_pbuf_ring_foreach(var, ring) \
	for ( \
		struct ndpip_pbuf_train *(var) = ring->ring_base + ring->ring_start; \
		((((var) - ring->ring_base) - ring->ring_start) < ring->ring_occupied) && \
		((((var) - ring->ring_base) - ring->ring_start) > (ring->ring_length - ring->ring_occupied)); \
		(var) = ring->ring_base + (((var) - ring->ring_base + 1) % ring->ring_length))

#define NDPIP_NSEC_IN_SEC 1000000000L

struct ndpip_timer {
	struct ndpip_list_head list;

	bool armed;
	struct timespec timeout;
	void (*func)(void *argp);
	void *argp;
};

struct ndpip_pbuf_train {
	struct ndpip_pbuf **train_pbufs;
	size_t train_length;
};

struct ndpip_pbuf_ring {
	struct ndpip_pbuf_train *ring_base;
	size_t ring_length;

	size_t ring_start;
	size_t ring_occupied;
};

struct ndpip_pbuf_ring *ndpip_pbuf_ring_alloc(size_t length);
int ndpip_pbuf_ring_append(struct ndpip_pbuf_ring *ring, struct ndpip_pbuf **pb, size_t count);
int ndpip_pbuf_ring_peek(struct ndpip_pbuf_ring *ring, size_t offset, struct ndpip_pbuf ***pb, size_t *count);

void ndpip_list_add(struct ndpip_list_head *prev, struct ndpip_list_head *entry);
void ndpip_list_del(struct ndpip_list_head *entry);

typedef void (*ndpip_timer_callback_t)(void *argp);

struct ndpip_timer *ndpip_timer_alloc(ndpip_timer_callback_t cb, void *argp);
void ndpip_timer_arm(struct ndpip_timer *timer, struct timespec *timeout);
bool ndpip_timer_armed(struct ndpip_timer *timer);
bool ndpip_timer_expired(struct ndpip_timer *timer);
void ndpip_timer_disarm(struct ndpip_timer *timer);

void ndpip_timespec_add(struct timespec *ts, struct timespec add);

#endif
