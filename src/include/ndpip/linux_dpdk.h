#ifndef _SRC_INCLUDE_NDPIP_LINUX_DPDK_H_
#define _SRC_INCLUDE_NDPIP_LINUX_DPDK_H_

#include "../../../include/ndpip/linux_dpdk.h"

#include "ndpip/pbuf_pool.h"
#include "ndpip/util.h"

struct ndpip_linux_dpdk_iface {
        int iface_netdev_id;
        int iface_rx_queue_id;
        int iface_tx_queue_id;

        uint16_t iface_rx_burst_size;

	struct in_addr iface_inaddr;
        struct ether_addr iface_ethaddr;
        struct ndpip_arp_peer *iface_arp_table;
        size_t iface_arp_table_len;

        bool iface_rx_thread_running;
        bool iface_timers_thread_running;

	struct ndpip_pbuf_pool *iface_pbuf_pool_rx;
	struct ndpip_pbuf_pool *iface_pbuf_pool_tx;
};

struct ndpip_iface;
struct ndpip_pbuf_pool;

struct ndpip_pbuf_pool *ndpip_linux_dpdk_pbuf_pool_alloc(size_t pbuf_count, uint16_t pbuf_size, size_t pbuf_allign, uint16_t pbuf_headroom);
int ndpip_linux_dpdk_pbuf_pool_request(struct ndpip_pbuf_pool *pool, struct ndpip_pbuf **pb, uint16_t *count);
int ndpip_linux_dpdk_pbuf_pool_release(struct ndpip_pbuf_pool *pool, struct ndpip_pbuf **pb, uint16_t count);
int ndpip_linux_dpdk_pbuf_pool_reset(struct ndpip_pbuf_pool *pool, struct ndpip_pbuf **pb, uint16_t count);

int ndpip_linux_dpdk_iface_rx_burst(struct ndpip_iface *iface, struct ndpip_pbuf **pb, uint16_t *count);

struct ndpip_iface *ndpip_linux_dpdk_iface_get_by_inaddr(struct in_addr addr);

struct ether_addr *ndpip_linux_dpdk_iface_get_ethaddr(struct ndpip_iface *iface);
struct in_addr *ndpip_linux_dpdk_iface_get_inaddr(struct ndpip_iface *iface);

struct ether_addr *ndpip_linux_dpdk_iface_resolve_arp(struct ndpip_iface *iface, struct in_addr peer);

int ndpip_linux_dpdk_iface_xmit(struct ndpip_iface *iface, struct ndpip_pbuf **pb, uint16_t cnt);

void ndpip_linux_dpdk_nanosleep(uint64_t nsec);
void ndpip_linux_dpdk_thread_yield();

bool ndpip_linux_dpdk_iface_rx_thread_running(struct ndpip_iface *iface);
bool ndpip_linux_dpdk_iface_timers_thread_running(struct ndpip_iface *iface);
uint16_t ndpip_iface_get_rx_burst_size(struct ndpip_iface *iface);

#define ndpip_iface_get_by_inaddr ndpip_linux_dpdk_iface_get_by_inaddr
#define ndpip_iface_get_ethaddr ndpip_linux_dpdk_iface_get_ethaddr
#define ndpip_iface_get_inaddr ndpip_linux_dpdk_iface_get_inaddr
#define ndpip_iface_xmit ndpip_linux_dpdk_iface_xmit
#define ndpip_nanosleep ndpip_linux_dpdk_nanosleep
#define ndpip_thread_yield ndpip_linux_dpdk_thread_yield

#define ndpip_iface_get_pbuf_pool_rx(iface) (((struct ndpip_linux_dpdk_iface *) (iface))->iface_pbuf_pool_rx)
#define ndpip_iface_get_pbuf_pool_tx(iface) (((struct ndpip_linux_dpdk_iface *) (iface))->iface_pbuf_pool_tx)
#define ndpip_iface_resolve_arp ndpip_linux_dpdk_iface_resolve_arp

#define ndpip_iface_rx_thread_running ndpip_linux_dpdk_iface_rx_thread_running
#define ndpip_iface_timers_thread_running ndpip_linux_dpdk_iface_timers_thread_running
#define ndpip_iface_rx_burst ndpip_linux_dpdk_iface_rx_burst

#define ndpip_pbuf_data ndpip_linux_dpdk_pbuf_data
#define ndpip_pbuf_length ndpip_linux_dpdk_pbuf_length
#define ndpip_pbuf_offset ndpip_linux_dpdk_pbuf_offset
#define ndpip_pbuf_resize ndpip_linux_dpdk_pbuf_resize
#define ndpip_pbuf_refcount_get ndpip_linux_dpdk_pbuf_refcount_get
#define ndpip_pbuf_refcount_add ndpip_linux_dpdk_pbuf_refcount_add
#define ndpip_pbuf_refcount_set ndpip_linux_dpdk_pbuf_refcount_set

#define ndpip_pbuf_pool_alloc ndpip_linux_dpdk_pbuf_pool_alloc
#define ndpip_pbuf_pool_request ndpip_linux_dpdk_pbuf_pool_request
#define ndpip_pbuf_pool_release ndpip_linux_dpdk_pbuf_pool_release

#endif
