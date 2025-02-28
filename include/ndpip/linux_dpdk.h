#ifndef _INCLUDE_NDPIP_UK_H_
#define _INCLUDE_NDPIP_UK_H_

#include <netinet/in.h>
#include <netinet/ether.h>

#include <rte_mempool.h>
#include <rte_ring.h>

#include "pbuf.h"

struct ndpip_arp_peer {
	struct in_addr inaddr;
	struct ether_addr ethaddr;
};

int ndpip_linux_dpdk_register_iface(int netdev_id);
int ndpip_linux_dpdk_start_iface(int netdev_id);
int ndpip_linux_dpdk_stop_iface(int netdev_id);

int ndpip_linux_dpdk_set_ethaddr(int netdev_id, struct ether_addr iface_ethaddr);
int ndpip_linux_dpdk_set_inaddr(int netdev_id, struct in_addr iface_inaddr);
int ndpip_linux_dpdk_set_arp_table(int netdev_id, struct ndpip_arp_peer *iface_arp_table, size_t iface_arp_table_len);

void *ndpip_linux_dpdk_pbuf_data(struct ndpip_pbuf *pbuf);
uint16_t ndpip_linux_dpdk_pbuf_length(struct ndpip_pbuf *pbuf);
int ndpip_linux_dpdk_pbuf_offset(struct ndpip_pbuf *pbuf, int off);
int ndpip_linux_dpdk_pbuf_resize(struct ndpip_pbuf *pbuf, uint16_t len);

int ndpip_linux_dpdk_set_burst_size(int netdev_id, uint16_t iface_rx_burst_size);

void ndpip_linux_dpdk_time_now(struct timespec *req);

uint64_t ndpip_linux_dpdk_tsc();
void ndpip_linux_dpdk_tsc2time(uint64_t tsc, struct timespec *req);
void ndpip_linux_dpdk_init();

#define ndpip_time_now ndpip_linux_dpdk_time_now

#define ndpip_pbuf_data ndpip_linux_dpdk_pbuf_data
#define ndpip_pbuf_length ndpip_linux_dpdk_pbuf_length
#define ndpip_pbuf_offset ndpip_linux_dpdk_pbuf_offset
#define ndpip_pbuf_resize ndpip_linux_dpdk_pbuf_resize

#define ndpip_tsc ndpip_linux_dpdk_tsc
#define ndpip_tsc2time ndpip_linux_dpdk_tsc2time

#endif
