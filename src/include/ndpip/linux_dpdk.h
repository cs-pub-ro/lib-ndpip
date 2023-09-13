#ifndef _SRC_INCLUDE_NDPIP_LINUX_DPDK_H_
#define _SRC_INCLUDE_NDPIP_LINUX_DPDK_H_

#include "../../../include/ndpip/linux_dpdk.h"

#include "ndpip/iface.h"
#include "ndpip/pbuf.h"
#include "ndpip/pbuf_pool.h"
#include "ndpip/util.h"

#include <pthread.h>

#include <rte_ethdev.h>

struct ndpip_linux_dpdk_iface {
        int iface_netdev_id;
        int iface_rx_queue_id;
        int iface_tx_queue_id;

	struct rte_eth_dev_info iface_dev_info;
	struct rte_eth_conf iface_conf;

        uint16_t iface_burst_size;

	struct in_addr iface_inaddr;
        struct ether_addr iface_ethaddr;
        struct ndpip_arp_peer *iface_arp_table;
        size_t iface_arp_table_len;

        bool iface_rx_thread_running;
        bool iface_timers_thread_running;

	pthread_t iface_timers_thread;

	struct ndpip_pbuf_pool *iface_pbuf_pool_rx;
	struct ndpip_pbuf_pool *iface_pbuf_pool_tx;
};

enum ndpip_iface_offload {
	NDPIP_IFACE_OFFLOAD_TX_IPV4_CSUM,
	NDPIP_IFACE_OFFLOAD_TX_TCPV4_CSUM,
	NDPIP_IFACE_OFFLOAD_TX_UDPV4_CSUM,
	NDPIP_IFACE_OFFLOAD_RX_IPV4_CSUM,
	NDPIP_IFACE_OFFLOAD_RX_TCPV4_CSUM,
	NDPIP_IFACE_OFFLOAD_RX_UDPV4_CSUM
};

struct ndpip_pbuf_pool *ndpip_linux_dpdk_pbuf_pool_alloc(size_t pbuf_count, uint16_t pbuf_size, size_t pbuf_allign, uint16_t pbuf_headroom);
int ndpip_linux_dpdk_pbuf_pool_request(struct ndpip_pbuf_pool *pool, struct ndpip_pbuf **pbs, uint16_t *count);
int ndpip_linux_dpdk_pbuf_pool_release(struct ndpip_pbuf_pool *pool, struct ndpip_pbuf **pbs, uint16_t count);
int ndpip_linux_dpdk_pbuf_pool_reset(struct ndpip_pbuf_pool *pool, struct ndpip_pbuf **pbs, uint16_t count);

int ndpip_linux_dpdk_iface_rx_burst(struct ndpip_iface *iface, struct ndpip_pbuf **pbs, uint16_t *count);

struct ndpip_iface *ndpip_linux_dpdk_iface_get_by_inaddr(struct in_addr addr);

struct ether_addr *ndpip_linux_dpdk_iface_get_ethaddr(struct ndpip_iface *iface);
struct in_addr *ndpip_linux_dpdk_iface_get_inaddr(struct ndpip_iface *iface);
uint16_t ndpip_linux_dpdk_iface_get_mtu(struct ndpip_iface *iface);

struct ether_addr *ndpip_linux_dpdk_iface_resolve_arp(struct ndpip_iface *iface, struct in_addr peer);
bool ndpip_linux_dpdk_iface_has_offload(struct ndpip_iface *iface, enum ndpip_iface_offload off);

int ndpip_linux_dpdk_iface_xmit(struct ndpip_iface *iface, struct ndpip_pbuf **pbs, uint16_t cnt, bool free);

void ndpip_linux_dpdk_usleep(unsigned usec);
void ndpip_linux_dpdk_timers_usleep(unsigned usec);
void ndpip_linux_dpdk_thread_yield();

bool ndpip_linux_dpdk_iface_rx_thread_running(struct ndpip_iface *iface);
bool ndpip_linux_dpdk_iface_timers_thread_running(struct ndpip_iface *iface);

struct ndpip_pbuf_meta *ndpip_linux_dpdk_pbuf_metadata(struct ndpip_pbuf *pbuf);
struct ndpip_pbuf *ndpip_linux_dpdk_pbuf_copy(struct ndpip_pbuf *pb, struct ndpip_pbuf_pool *pool, uint32_t offset, uint32_t length);
bool ndpip_linux_dpdk_pbuf_has_flag(struct ndpip_pbuf *pb, enum ndpip_pbuf_flag flag);
void ndpip_linux_dpdk_pbuf_set_flag(struct ndpip_pbuf *pb, enum ndpip_pbuf_flag flag, bool val);
void ndpip_linux_dpdk_pbuf_set_l2_len(struct ndpip_pbuf *pb,uint16_t val);
void ndpip_linux_dpdk_pbuf_set_l3_len(struct ndpip_pbuf *pb,uint16_t val);
void ndpip_linux_dpdk_pbuf_refcount_update(struct ndpip_pbuf *pb, int16_t val);

uint16_t ndpip_linux_dpdk_iface_get_burst_size(struct ndpip_iface *iface);

void *ndpip_linux_dpdk_timers_thread(void *argp);

uint16_t ndpip_linux_dpdk_ipv4_cksum(struct iphdr *iph);
uint16_t ndpip_linux_dpdk_ipv4_udptcp_cksum(struct iphdr *iph, void *l4h);

#define ndpip_iface_get_by_inaddr ndpip_linux_dpdk_iface_get_by_inaddr
#define ndpip_iface_get_ethaddr ndpip_linux_dpdk_iface_get_ethaddr
#define ndpip_iface_get_inaddr ndpip_linux_dpdk_iface_get_inaddr
#define ndpip_iface_get_mtu ndpip_linux_dpdk_iface_get_mtu
#define ndpip_iface_get_pbuf_pool_rx(iface) (((struct ndpip_linux_dpdk_iface *) (iface))->iface_pbuf_pool_rx)
#define ndpip_iface_get_pbuf_pool_tx(iface) (((struct ndpip_linux_dpdk_iface *) (iface))->iface_pbuf_pool_tx)
#define ndpip_iface_resolve_arp ndpip_linux_dpdk_iface_resolve_arp
#define ndpip_iface_has_offload ndpip_linux_dpdk_iface_has_offload

#define ndpip_usleep ndpip_linux_dpdk_usleep
#define ndpip_timers_usleep ndpip_linux_dpdk_timers_usleep
#define ndpip_thread_yield ndpip_linux_dpdk_thread_yield

#define ndpip_iface_rx_thread_running ndpip_linux_dpdk_iface_rx_thread_running
#define ndpip_iface_timers_thread_running ndpip_linux_dpdk_iface_timers_thread_running

#define ndpip_iface_rx_burst ndpip_linux_dpdk_iface_rx_burst
#define ndpip_iface_xmit ndpip_linux_dpdk_iface_xmit

#define ndpip_pbuf_data ndpip_linux_dpdk_pbuf_data
#define ndpip_pbuf_length ndpip_linux_dpdk_pbuf_length
#define ndpip_pbuf_offset ndpip_linux_dpdk_pbuf_offset
#define ndpip_pbuf_resize ndpip_linux_dpdk_pbuf_resize
#define ndpip_pbuf_refcount_get ndpip_linux_dpdk_pbuf_refcount_get
#define ndpip_pbuf_refcount_set ndpip_linux_dpdk_pbuf_refcount_set
#define ndpip_pbuf_refcount_update ndpip_linux_dpdk_pbuf_refcount_update
#define ndpip_pbuf_copy ndpip_linux_dpdk_pbuf_copy

#define ndpip_pbuf_pool_alloc ndpip_linux_dpdk_pbuf_pool_alloc
#define ndpip_pbuf_pool_request ndpip_linux_dpdk_pbuf_pool_request
#define ndpip_pbuf_pool_release ndpip_linux_dpdk_pbuf_pool_release

#define ndpip_pbuf_metadata ndpip_linux_dpdk_pbuf_metadata
#define ndpip_pbuf_has_flag ndpip_linux_dpdk_pbuf_has_flag
#define ndpip_pbuf_set_flag ndpip_linux_dpdk_pbuf_set_flag
#define ndpip_pbuf_set_l2_len ndpip_linux_dpdk_pbuf_set_l2_len
#define ndpip_pbuf_set_l3_len ndpip_linux_dpdk_pbuf_set_l3_len

#define ndpip_iface_get_burst_size ndpip_linux_dpdk_iface_get_burst_size

#define ndpip_tsc ndpip_linux_dpdk_tsc
#define ndpip_tsc2time ndpip_linux_dpdk_tsc2time

#define ndpip_ipv4_cksum ndpip_linux_dpdk_ipv4_cksum
#define ndpip_ipv4_udptcp_cksum ndpip_linux_dpdk_ipv4_udptcp_cksum

#endif
