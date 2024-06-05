#include "ndpip/util.h"

#ifdef NDPIP_UK

#include "ndpip/uk.h"

#endif

#ifdef NDPIP_LINUX_DPDK

#include "ndpip/linux_dpdk.h"

#include <stdlib.h>
#include <string.h>

#endif


struct ndpip_ring *ndpip_ring_alloc(size_t length)
{
	struct ndpip_ring *ret = malloc(sizeof(struct ndpip_ring));

	ret->ring_base = malloc(length * sizeof(struct ndpip_pbuf *));
	ret->ring_length = length;

	ret->ring_start = 0;
	ret->ring_end = 0;
	ret->ring_mask = length - 1;

	return ret;
}

int ndpip_ring_push_one(struct ndpip_ring *ring, struct ndpip_pbuf *pb)
{
	size_t ring_end = ring->ring_end;
	if ((ring_end - ring->ring_start) >= ring->ring_length)
		return -1;

	size_t producer = ring_end & ring->ring_mask;
	ring->ring_base[producer] = pb;
	ring->ring_end++;

	return 0;
}

int ndpip_ring_push(struct ndpip_ring *ring, struct ndpip_pbuf **pbs, size_t count)
{
	if (count == 0)
		return 0;

	size_t ring_end = ring->ring_end;
	size_t ring_length = ring->ring_length;
	if ((ring_end - ring->ring_start + count) > ring_length)
		return -1;

	struct ndpip_pbuf **ring_base = ring->ring_base;
	size_t producer = ring_end & ring->ring_mask;
        size_t count1 = ring_length - producer;

	if (count > count1) {
		memcpy(&ring_base[producer], pbs, sizeof(struct ndpip_pbuf *) * count1);
		memcpy(ring_base, &pbs[count1], sizeof(struct ndpip_pbuf *) * (count - count1));
	} else
		memcpy(&ring_base[producer], pbs, sizeof(struct ndpip_pbuf *) * count);

	ring->ring_end += count;

	return 0;
}

size_t ndpip_ring_free(struct ndpip_ring *ring)
{
	return ring->ring_length - (ring->ring_end - ring->ring_start);
}

size_t ndpip_ring_size(struct ndpip_ring *ring)
{
	return ring->ring_end - ring->ring_start;
}

static int ndpip_ring_pop0(struct ndpip_ring *ring, size_t *count, struct ndpip_pbuf **pbs, bool pop)
{
	if (*count == 0)
		return 0;

	size_t ring_start = ring->ring_start;
	size_t r_count = ring->ring_end - ring_start;
	if (r_count == 0)
		return -1;

	size_t tmp_count = *count;
	r_count = r_count < tmp_count ? r_count : tmp_count;

	size_t consumer = ring_start & ring->ring_mask;
	struct ndpip_pbuf **ring_base = ring->ring_base;

	size_t count1 = ring->ring_length - consumer;
	if (r_count > count1) {
		memcpy(pbs, &ring_base[consumer], sizeof(struct ndpip_pbuf *) * count1);
		memcpy(&pbs[count1], ring_base, sizeof(struct ndpip_pbuf *) * (r_count - count1));
	} else
		memcpy(pbs, &ring_base[consumer], sizeof(struct ndpip_pbuf *) * r_count);

	if (pop)
		ring->ring_start += r_count;

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

int ndpip_ring_peek(struct ndpip_ring *ring, size_t *count, struct ndpip_pbuf **pbs)
{
	return ndpip_ring_pop0(ring, count, pbs, false);
}

int ndpip_ring_pop(struct ndpip_ring *ring, size_t *count, struct ndpip_pbuf **pbs)
{
	return ndpip_ring_pop0(ring, count, pbs, true);
}

void ndpip_list_init(struct ndpip_list_head *list)
{
	list->prev = list;
	list->next = list;
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

void ndpip_timer_arm_after(struct ndpip_timer *timer, struct timespec *after)
{
	struct timespec expire;
	ndpip_time_now(&expire);
	ndpip_timespec_add(&expire, after);
	ndpip_timer_arm(timer, &expire);
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

void ndpip_timespec_add(struct timespec *ts, struct timespec *add)
{
	int64_t nsec = (ts->tv_sec + add->tv_sec) * NDPIP_NSEC_IN_SEC + (ts->tv_nsec + add->tv_nsec);

	ts->tv_sec = nsec / NDPIP_NSEC_IN_SEC;
	ts->tv_nsec = nsec % NDPIP_NSEC_IN_SEC;
}

struct ndpip_hashtable *ndpip_hashtable_alloc(uint64_t buckets)
{
	struct ndpip_hashtable *ret = malloc(sizeof(struct ndpip_hashtable));

	ndpip_mutex_init(&ret->lock);
	ret->hashtable_buckets = malloc(sizeof(struct ndpip_list_head) * buckets);
	ret->hashtable_mask = buckets - 1;
	ret->hashtable_length = buckets;
	ret->last_node = NULL;

	for (size_t idx = 0; idx < ret->hashtable_length; idx++)
		ret->hashtable_buckets[idx].prev = ret->hashtable_buckets[idx].next = &ret->hashtable_buckets[idx];

	return ret;
}

void *ndpip_hashtable_get(struct ndpip_hashtable *hashtable, uint32_t hash)
{
	ndpip_mutex_lock(&hashtable->lock);

	if (hashtable->last_node != NULL) {
		if (hashtable->last_node->hnode_hash == hash) {
			ndpip_mutex_unlock(&hashtable->lock);
			return hashtable->last_node->hnode_data;
		}
	}

	struct ndpip_list_head *bucket = (void *) &hashtable->hashtable_buckets[hash & hashtable->hashtable_mask];

	ndpip_list_foreach(struct ndpip_hlist_node, hnode, bucket) {
		if (hnode->hnode_hash == hash) {
			hashtable->last_node = hnode;
			ndpip_mutex_unlock(&hashtable->lock);
			return hnode->hnode_data;
		}
	}

	ndpip_mutex_unlock(&hashtable->lock);

	return NULL;
}

void ndpip_hashtable_put(struct ndpip_hashtable *hashtable, uint32_t hash, void *data)
{
	struct ndpip_list_head *bucket = (void *) &hashtable->hashtable_buckets[hash & hashtable->hashtable_mask];

	struct ndpip_hlist_node *hnode = malloc(sizeof(struct ndpip_hlist_node));
	hnode->hnode_hash = hash;
	hnode->hnode_data = data;
	ndpip_list_init((void *) hnode);

	ndpip_mutex_lock(&hashtable->lock);
	ndpip_list_add(bucket, (struct ndpip_list_head *) hnode);
	ndpip_mutex_unlock(&hashtable->lock);
}

void ndpip_hashtable_del(struct ndpip_hashtable *hashtable, uint32_t hash)
{
	struct ndpip_list_head *bucket = (void *) &hashtable->hashtable_buckets[hash & hashtable->hashtable_mask];
	struct ndpip_hlist_node *rmnode = NULL;

	ndpip_mutex_lock(&hashtable->lock);
	ndpip_list_foreach(struct ndpip_hlist_node, hnode, bucket) {
		if (hnode->hnode_hash == hash)
			rmnode = hnode;
	}

	if (rmnode != NULL) {
		ndpip_list_del((struct ndpip_list_head *) rmnode);
		free(rmnode);
	}

	ndpip_mutex_unlock(&hashtable->lock);
}
