#include "ndpip/util.h"

#ifdef NDPIP_UK

#include "ndpip/uk.h"

#endif

#ifdef NDPIP_LINUX_DPDK

#include "ndpip/linux_dpdk.h"

#include <stdlib.h>
#include <string.h>

#endif

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

int ndpip_ring_push(struct ndpip_ring *ring, void *buf, size_t count)
{
	if (count == 0)
		return 0;

	if ((ring->ring_end - ring->ring_start + count) > ring->ring_length)
		return -1;

	size_t producer = ring->ring_end & ring->ring_mask;

        size_t count1 = ring->ring_length - producer;
        count1 = count1 < count ? count1 : count;

	if (count1 != 0)
		memcpy(ring->ring_base + ring->ring_esize * producer, buf, ring->ring_esize * count1);

	if (count1 == count)
		goto ret;

	memcpy(ring->ring_base, buf + ring->ring_esize * count1, ring->ring_esize * (count - count1));

ret:
	ring->ring_end += count;

	return 0;
}

size_t ndpip_ring_size(struct ndpip_ring *ring)
{
	return ring->ring_end - ring->ring_start;
}

int ndpip_ring_pop(struct ndpip_ring *ring, size_t *count, void *buf)
{
	size_t consumer = ring->ring_start & ring->ring_mask;
	size_t r_count = ring->ring_end - ring->ring_start;
	if (r_count == 0)
		return 0;

	r_count = r_count < *count ? r_count : *count;

	ring->ring_start += r_count;

	size_t count1 = ring->ring_length - consumer;
	count1 = count1 < r_count ? count1 : r_count;

	memcpy(buf, ring->ring_base + ring->ring_esize * consumer, ring->ring_esize * count1);

	if (count1 == r_count)
		goto ret;

	memcpy(buf + ring->ring_esize * count1, ring->ring_base, ring->ring_esize * (r_count - count1));

ret:
	*count = r_count;

	return 0;
}

int ndpip_ring_peek(struct ndpip_ring *ring, size_t offset, void **buf)
{
	if ((ring->ring_start + offset) >= ring->ring_end)
		return -1;

	size_t ring_elem = (ring->ring_start + offset) & ring->ring_mask;
	*buf = ring->ring_base + ring->ring_esize * ring_elem;

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
	ndpip_time_now(&now);

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
