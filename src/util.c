#include "ndpip/util.h"

#ifdef NDPIP_UK

#include "ndpip/uk.h"

#endif

#include <string.h>

struct ndpip_ring *ndpip_ring_alloc(size_t length, size_t esize)
{
	struct ndpip_ring *ret = malloc(sizeof(struct ndpip_ring));

	ret->ring_base = malloc(length * esize);
	ret->ring_length = length;

	ret->ring_start = 0;
	ret->ring_end = 0;
	ret->ring_mask = length - 1;
	ret->ring_esize = esize;

	return ret;
}

int ndpip_ring_push(struct ndpip_ring *ring, void *e)
{
	size_t producer = ring->ring_end & ring->ring_mask;
	size_t ring_next = ring->ring_end + 1;

	if (ring->ring_start == ring_next)
		return -1;

	memcpy(ring->ring_base + ring->ring_esize * producer, e, ring->ring_esize);

	ring->ring_end = ring_next;

	return 0;
}

size_t ndpip_ring_size(struct ndpip_ring *ring)
{
	return ring->ring_end - ring->ring_start;
}

int ndpip_ring_pop(struct ndpip_ring *ring, size_t *count, void *buf)
{
	size_t consumer = ring->ring_start & ring->ring_mask;
	size_t r_count = ring->ring_length - consumer;
	r_count = r_count < *count ? r_count : *count;

	if ((ring->ring_start + r_count) > ring->ring_end)
		return -1;

	ring->ring_start += r_count;

	*count = r_count;
	memcpy(buf, ring->ring_base + ring->ring_esize * consumer, ring->ring_esize * r_count);

	return 0;
}

int ndpip_ring_peek(struct ndpip_ring *ring, size_t offset, void *buf)
{
	if ((ring->ring_start + offset) >= ring->ring_end)
		return -1;

	size_t ring_elem = (ring->ring_start + offset) & ring->ring_mask;
	memcpy(buf, ring->ring_base + ring->ring_esize * ring_elem, ring->ring_esize);

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

	if (((&now)->tv_sec >= timer->timeout.tv_sec) &&
		((&now)->tv_nsec >= timer->timeout.tv_nsec))
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

struct ndpip_timer *ndpip_timer_alloc(ndpip_timer_callback_t cb, void *argp)
{
	struct ndpip_timer *ret = malloc(sizeof(struct ndpip_timer));

	ret->armed = false;
	ret->func = cb;
	ret->argp = argp;

	return ret;
}

void ndpip_timespec_add(struct timespec *ts, struct timespec add)
{
	int64_t nsec = (ts->tv_sec + (&add)->tv_sec) * NDPIP_NSEC_IN_SEC + (ts->tv_nsec + (&add)->tv_nsec);

	ts->tv_sec = nsec / NDPIP_NSEC_IN_SEC;
	ts->tv_nsec = nsec % NDPIP_NSEC_IN_SEC;
}
