#include "ndpip/util.h"

#ifdef NDPIP_UK

#include "ndpip/uk.h"

#endif

#include <string.h>

struct ndpip_pbuf_ring *ndpip_pbuf_ring_alloc(size_t length)
{
	struct ndpip_pbuf_ring *ret = malloc(sizeof(struct ndpip_pbuf_ring));

	ret->ring_base = malloc(length * sizeof(struct ndpip_pbuf_train));
	ret->ring_length = length;

	ret->ring_start = 0;
	ret->ring_occupied = 0;

	return ret;
}

int ndpip_pbuf_ring_append(struct ndpip_pbuf_ring *ring, struct ndpip_pbuf **pb, size_t count)
{
	if ((ring->ring_length - ring->ring_occupied) < 1)
		return -1;

	size_t ring_next = (ring->ring_start + ring->ring_occupied) % ring->ring_length;

	ring->ring_base[ring_next].train_pbufs = pb;
	ring->ring_base[ring_next].train_length = count;
	ring->ring_occupied++;

	return 0;
}

int ndpip_pbuf_ring_erase(struct ndpip_pbuf_ring *ring, size_t count)
{
	if (ring->ring_occupied < count)
		return -1;
	
	ring->ring_start = (ring->ring_start + count) % ring->ring_length;
	ring->ring_occupied -= count;

	return 0;
}

int ndpip_pbuf_ring_peek(struct ndpip_pbuf_ring *ring, size_t offset, struct ndpip_pbuf ***pb, size_t *count)
{
	if (ring->ring_occupied <= offset)
		return -1;

	offset = (ring->ring_start + ring->ring_occupied) % ring->ring_length;

	*pb = ring->ring_base[offset].train_pbufs;
	*count = ring->ring_base[offset].train_length;

	return 0;
}

void ndpip_list_add(struct ndpip_list_head *prev, struct ndpip_list_head *element)
{
	element->next = prev->next;
	element->prev = prev;

	prev->next = element;

	if (element->next != NULL)
		element->next->prev = element;
}

void ndpip_list_del(struct ndpip_list_head *entry)
{
	if (entry->prev != NULL)
		entry->prev->next = entry->next;

	if (entry->next != NULL)
		entry->next->prev = entry->prev;
}

bool ndpip_timer_expired(struct ndpip_timer *timer)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	if (((&now)->tv_sec <= timer->timeout.tv_sec) &&
		((&now)->tv_nsec <= timer->timeout.tv_nsec))
		return true;

	return false;
}

void ndpip_timer_arm(struct ndpip_timer *timer, struct timespec *timeout)
{
	timer->timeout = *timeout;
	timer->armed = true;
}

bool ndpip_timer_armed(struct ndpip_timer *timer)
{
	return timer->armed;
}

void ndpip_timer_disarm(struct ndpip_timer *timer)
{
	timer->armed = false;
}

void ndpip_timer_init(struct ndpip_timer *timer, ndpip_timer_callback_t cb, void *argp)
{
	timer->armed = false;
	timer->func = cb;
	timer->argp = argp;
}

void ndpip_timespec_add(struct timespec *ts, struct timespec add)
{
	int64_t nsec = (ts->tv_sec + (&add)->tv_sec) * NDPIP_NSEC_IN_SEC + (ts->tv_nsec + (&add)->tv_nsec);

	ts->tv_sec = nsec / NDPIP_NSEC_IN_SEC;
	ts->tv_nsec = nsec % NDPIP_NSEC_IN_SEC;
}
