#ifndef _SRC_INCLUDE_NDPIP_UK_H_
#define _SRC_INCLUDE_NDPIP_UK_H_

#include "../../../include/ndpip/uk.h"

#include "ndpip/pbuf_pool.h"
#include "ndpip/util.h"

#include <uk/netdev.h>

struct ndpip_uk_iface {
        int iface_netdev_id;
        struct uk_netdev *iface_netdev;

        struct uk_netdev_info iface_netdev_info;
        struct uk_netdev_conf iface_netdev_conf;
	
	struct uk_netdev_rxqueue_conf iface_rxqueue_conf;
        struct uk_netdev_txqueue_conf iface_txqueue_conf;

        bool iface_intr;
        uint16_t iface_rx_burst_size;

	struct in_addr iface_inaddr;
        struct ether_addr iface_ethaddr;
        struct ndpip_arp_peer *iface_arp_table;
        size_t iface_arp_table_len;

        struct uk_thread *iface_rx_thread;
        bool iface_rx_thread_running;

        struct uk_thread *iface_timers_thread;
        bool iface_timers_thread_running;

	struct ndpip_pbuf_pool *iface_pbuf_pool_rx;
	struct ndpip_pbuf_pool *iface_pbuf_pool_tx;

	struct uk_alloc *iface_alloc;
        struct uk_sched *iface_sched;
};

struct ndpip_uk_pbuf_pool {
	struct uk_allocpool *pool_pool;
	uint16_t pool_pbalign;
	uint16_t pool_pbcount;
	uint16_t pool_pbsize;
	uint16_t pool_pbheadroom;
};

#define malloc(x) uk_malloc(uk_alloc_get_default(), (x))
#define free(x) uk_free(uk_alloc_get_default(), (x))

struct ndpip_iface;

struct ndpip_pbuf_pool *ndpip_uk_pbuf_pool_alloc(size_t pbuf_count, uint16_t pbuf_size, size_t pbuf_allign, uint16_t pbuf_headroom);
int ndpip_uk_pbuf_pool_request(struct ndpip_pbuf_pool *pool, struct ndpip_pbuf **pb, uint16_t *count);
int ndpip_uk_pbuf_pool_release(struct ndpip_pbuf_pool *pool, struct ndpip_pbuf **pb, uint16_t count);
int ndpip_uk_pbuf_pool_reset(struct ndpip_pbuf_pool *pool, struct ndpip_pbuf **pb, uint16_t count);

struct ndpip_iface *ndpip_uk_iface_get_by_inaddr(struct in_addr addr);

struct ether_addr *ndpip_uk_iface_get_ethaddr(struct ndpip_iface *iface);
struct in_addr *ndpip_uk_iface_get_inaddr(struct ndpip_iface *iface);

struct ether_addr *ndpip_uk_iface_resolve_arp(struct ndpip_iface *iface, struct in_addr peer);

int ndpip_uk_iface_xmit(struct ndpip_iface *iface, struct ndpip_pbuf **pb, uint16_t cnt);

void ndpip_uk_nanosleep(uint64_t nsec);

void ndpip_uk_timers_add(struct ndpip_timer *timer);

#define ndpip_iface_get_by_inaddr ndpip_uk_iface_get_by_inaddr
#define ndpip_iface_get_ethaddr ndpip_uk_iface_get_ethaddr
#define ndpip_iface_get_inaddr ndpip_uk_iface_get_inaddr
#define ndpip_iface_xmit ndpip_uk_iface_xmit
#define ndpip_nanosleep ndpip_uk_nanosleep

#define ndpip_iface_get_pbuf_pool_rx(iface) (((struct ndpip_uk_iface *) (iface))->iface_pbuf_pool_rx)
#define ndpip_iface_get_pbuf_pool_tx(iface) (((struct ndpip_uk_iface *) (iface))->iface_pbuf_pool_tx)
#define ndpip_iface_resolve_arp ndpip_uk_iface_resolve_arp

#define ndpip_timers_add ndpip_uk_timers_add

#endif
