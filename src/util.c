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

static int ndpip_ring_pop0(struct ndpip_ring *ring, size_t *count, void *buf, bool pop)
{
	if (*count == 0)
		return 0;

	size_t r_count = ring->ring_end - ring->ring_start;
	if (r_count == 0)
		return -1;

	r_count = r_count < *count ? r_count : *count;
	size_t consumer = ring->ring_start & ring->ring_mask;

	if (pop)
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

int ndpip_ring_flush(struct ndpip_ring *ring, size_t count)
{
	if (count == 0)
		return 0;

	size_t r_count = ring->ring_end - ring->ring_start;
	r_count = r_count < count ? r_count : count;

	ring->ring_start += r_count;

	return 0;
}

int ndpip_ring_peek(struct ndpip_ring *ring, size_t *count, void *buf)
{
	return ndpip_ring_pop0(ring, count, buf, false);
}

int ndpip_ring_pop(struct ndpip_ring *ring, size_t *count, void *buf)
{
	return ndpip_ring_pop0(ring, count, buf, true);
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

	if ((&now)->tv_sec > timer->timeout.tv_sec)
		return true;

	if (((&now)->tv_sec == timer->timeout.tv_sec) &&
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

struct ndpip_hashtable *ndpip_hashtable_alloc(uint64_t buckets)
{
	struct ndpip_hashtable *ret = malloc(sizeof(struct ndpip_hashtable));

	ret->hashtable_buckets = malloc(sizeof(struct ndpip_list_head) * buckets);
	ret->hashtable_mask = buckets - 1;
	ret->hashtable_length = buckets;

	for (size_t idx = 0; idx < ret->hashtable_length; idx++)
		ret->hashtable_buckets[idx].prev = ret->hashtable_buckets[idx].next = &ret->hashtable_buckets[idx];

	return ret;
}

uint64_t ndpip_hash(void *key, size_t key_size)
{
	uint64_t ret = 0;
	size_t idx = 0;

	for (;idx <= (key_size - sizeof(uint64_t)); idx += sizeof(uint64_t))
		ret += *(uint64_t *)(key + idx);

	for (;idx < key_size; idx++)
		ret += *(uint8_t *)(key + idx);

	return ret;
}

void *ndpip_hashtable_get(struct ndpip_hashtable *hashtable, void *key, size_t key_size)
{
	uint64_t hash = ndpip_hash(key, key_size);
	/*
	if ((hash != 0x20101108a148a1dUL) && (hash != 0x10101108b148a1dUL) && (hash != 0x689130201010aUL))
		printf("%lx\n", hash);
		*/

	struct ndpip_list_head *bucket = (void *) &hashtable->hashtable_buckets[hash & hashtable->hashtable_mask];

	ndpip_list_foreach(struct ndpip_hlist_node, hnode, bucket) {
		if (hnode->hnode_hash == hash)
			return hnode->hnode_data;
	}

	return NULL;
}

void ndpip_hashtable_put(struct ndpip_hashtable *hashtable, void *key, size_t key_size, void *data)
{
	uint64_t hash = ndpip_hash(key, key_size);
	struct ndpip_list_head *bucket = (void *) &hashtable->hashtable_buckets[hash & hashtable->hashtable_mask];

	struct ndpip_hlist_node *hnode = malloc(sizeof(struct ndpip_hlist_node));
	hnode->hnode_hash = hash;
	hnode->hnode_data = data;

	ndpip_list_add(bucket, (struct ndpip_list_head *) hnode);
}

void ndpip_hashtable_del(struct ndpip_hashtable *hashtable, void *key, size_t key_size)
{
	uint64_t hash = ndpip_hash(key, key_size);
	struct ndpip_list_head *bucket = (void *) &hashtable->hashtable_buckets[hash & hashtable->hashtable_mask];

	struct ndpip_hlist_node *rmnode = NULL;

	ndpip_list_foreach(struct ndpip_hlist_node, hnode, bucket) {
		if (hnode->hnode_hash == hash)
			rmnode = hnode;
	}

	if (rmnode != NULL) {
		ndpip_list_del((struct ndpip_list_head *) rmnode);
		free(rmnode);
	}
}
