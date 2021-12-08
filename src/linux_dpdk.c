#include "ndpip/linux_dpdk.h"
#include "ndpip/workhorse.h"

#include <rte_mbuf.h>
#include <rte_ethdev.h>

#define NDPIP_TODO_NB_MBUF (1 << 16)
#define NDPIP_TODO_MEMPOOL_CACHE_SZ 256
#define NDPIP_TODO_MBUF_SIZE (3 * 4096)
#define NDPIP_TODO_MTU 1500

static struct ndpip_linux_dpdk_iface iface = {
        .iface_netdev_id = -1
};

static uint64_t tsc_hz;

int ndpip_linux_dpdk_pbuf_pool_request(struct ndpip_pbuf_pool *pool, struct ndpip_pbuf **pb, uint16_t *count)
{
	struct rte_mempool *p = (void *) pool;
	struct rte_mbuf **mb = (void *) pb;

	if (rte_pktmbuf_alloc_bulk(p, mb, *count) != 0)
		return -1;

	return 0;
}

bool ndpip_linux_dpdk_iface_rx_thread_running(struct ndpip_iface *iface)
{
	struct ndpip_linux_dpdk_iface *iface_linux_dpdk = (void *) iface;

	return iface_linux_dpdk->iface_rx_thread_running;
}

bool ndpip_linux_dpdk_iface_timers_thread_running(struct ndpip_iface *iface)
{
	struct ndpip_linux_dpdk_iface *iface_linux_dpdk = (void *) iface;

	return iface_linux_dpdk->iface_timers_thread_running;
}

void ndpip_linux_dpdk_thread_yield() {}

int ndpip_linux_dpdk_register_iface(int netdev_id)
{
	tsc_hz = rte_get_tsc_hz();

        if ((&iface)->iface_netdev_id >= 0)
                return -1;

	(&iface)->iface_netdev_id = netdev_id;
	(&iface)->iface_rx_queue_id = 0;
	(&iface)->iface_tx_queue_id = 0;

	struct rte_eth_conf conf;
	memset(&conf, 0, sizeof(struct rte_eth_conf));
        conf.rxmode.max_rx_pkt_len = NDPIP_TODO_MTU;

	if (rte_eth_dev_configure((&iface)->iface_netdev_id, 1, 1, &conf) < 0)
		return -1;

	(&iface)->iface_pbuf_pool_rx = (void *) rte_pktmbuf_pool_create("ndpip_pool_rx", NDPIP_TODO_NB_MBUF, NDPIP_TODO_MEMPOOL_CACHE_SZ, 0, NDPIP_TODO_MBUF_SIZE, rte_socket_id());
	if ((&iface)->iface_pbuf_pool_rx == NULL)
		return -1;

	(&iface)->iface_pbuf_pool_tx = (void *) rte_pktmbuf_pool_create("ndpip_pool_tx", NDPIP_TODO_NB_MBUF, NDPIP_TODO_MEMPOOL_CACHE_SZ, 0, NDPIP_TODO_MBUF_SIZE, rte_socket_id());
	if ((&iface)->iface_pbuf_pool_tx == NULL)
		return -1;

	if (rte_eth_rx_queue_setup((&iface)->iface_netdev_id, (&iface)->iface_rx_queue_id, 2048, rte_eth_dev_socket_id((&iface)->iface_netdev_id), NULL, (void *) (&iface)->iface_pbuf_pool_rx) < 0)
		return -1;

	if (rte_eth_tx_queue_setup((&iface)->iface_netdev_id, (&iface)->iface_tx_queue_id, 2048, rte_eth_dev_socket_id((&iface)->iface_netdev_id), NULL) < 0)
		return -1;

	(&iface)->iface_rx_thread_running = false;
	(&iface)->iface_timers_thread_running = false;

	return 0;
}

int ndpip_linux_dpdk_start_iface(int netdev_id)
{
        if ((&iface)->iface_netdev_id != netdev_id)
                return -1;

	if (rte_eth_dev_start((&iface)->iface_netdev_id) < 0)
		return -1;

	(&iface)->iface_rx_thread_running = true;
	(&iface)->iface_timers_thread_running = true;

	rte_eal_remote_launch(ndpip_rx_thread, &iface, rte_get_next_lcore(rte_lcore_id(), 1, 0));
	rte_eal_remote_launch(ndpip_timers_thread, &iface, rte_lcore_id());

	return 0;
}

int ndpip_linux_dpdk_iface_xmit(struct ndpip_iface *iface, struct ndpip_pbuf **pb, uint16_t cnt)
{
	struct rte_mbuf **mb = (void *) pb;
	struct ndpip_linux_dpdk_iface *iface_linux_dpdk = (void *) iface;

	for (uint16_t idx = 0; idx < cnt;)
		idx += rte_eth_tx_burst(
			iface_linux_dpdk->iface_netdev_id,
			iface_linux_dpdk->iface_tx_queue_id,
			mb + idx, cnt - idx);

	return 0;
}

int ndpip_linux_dpdk_iface_rx_burst(struct ndpip_iface *iface, struct ndpip_pbuf **pb, uint16_t *cnt)
{
	struct rte_mbuf **mb = (void *) pb;
	struct ndpip_linux_dpdk_iface *iface_linux_dpdk = (void *) iface;

	uint16_t r_cnt = 0;

	for (int i = 0; (i < 1000) && (r_cnt < *cnt); i++)
		r_cnt += rte_eth_rx_burst(iface_linux_dpdk->iface_netdev_id, iface_linux_dpdk->iface_rx_queue_id, mb + r_cnt, *cnt - r_cnt);

	*cnt = r_cnt;

	return 0;
}

void *ndpip_linux_dpdk_pbuf_data(struct ndpip_pbuf *pbuf)
{
	struct rte_mbuf *mb = (void *) pbuf;

	return rte_pktmbuf_mtod(mb, void *);
}

uint16_t ndpip_linux_dpdk_pbuf_length(struct ndpip_pbuf *pbuf)
{
	struct rte_mbuf *mb = (void *) pbuf;

	return rte_pktmbuf_data_len(mb);
}

int ndpip_linux_dpdk_pbuf_offset(struct ndpip_pbuf *pbuf, int off)
{
	struct rte_mbuf *mb = (void *) pbuf;

	if (off < 0)
		rte_pktmbuf_adj(mb, (uint16_t) -off);

	if (off > 0)
		rte_pktmbuf_prepend(mb, (uint16_t) off);

	return 0;
}
int ndpip_linux_dpdk_pbuf_resize(struct ndpip_pbuf *pbuf, uint16_t len)
{
	struct rte_mbuf *mb = (void *) pbuf;
	uint16_t pkt_len = ndpip_pbuf_length(pbuf);

	if (len < pkt_len)
		rte_pktmbuf_trim(mb, pkt_len - len);

	if (len > pkt_len)
		rte_pktmbuf_append(mb, len - pkt_len);

	return 0;
}

struct in_addr *ndpip_linux_dpdk_iface_get_inaddr(struct ndpip_iface *iface)
{
        return &((struct ndpip_linux_dpdk_iface *) iface)->iface_inaddr;
}                        
                      
struct ndpip_iface *ndpip_linux_dpdk_iface_get_by_inaddr(struct in_addr addr)
{
        if (ndpip_iface_get_inaddr((void *) &iface)->s_addr == addr.s_addr)
                return (struct ndpip_iface *)(void *) &iface;
        else                                                                 
                return NULL;
}

void ndpip_linux_dpdk_nanosleep(uint64_t nsec)
{
	struct timespec req = { .tv_sec = nsec / 1000000000ULL, .tv_nsec = nsec % 1000000000ULL };
	nanosleep(&req, NULL);
}

uint16_t ndpip_iface_get_rx_burst_size(struct ndpip_iface *iface)
{
	struct ndpip_linux_dpdk_iface *iface_linux_dpdk = (void *) iface;

	return iface_linux_dpdk->iface_rx_burst_size;
}

struct ether_addr *ndpip_linux_dpdk_iface_get_ethaddr(struct ndpip_iface *_)
{
        return &(&iface)->iface_ethaddr; 
}

int ndpip_linux_dpdk_set_arp_table(int netdev_id, struct ndpip_arp_peer *iface_arp_table, size_t iface_arp_table_len)
{                                                         
        if ((&iface)->iface_netdev_id != netdev_id)      
                return -1;
                                                                 
        (&iface)->iface_arp_table = malloc(sizeof(struct ndpip_arp_peer) * iface_arp_table_len);
        memcpy((&iface)->iface_arp_table, iface_arp_table, sizeof(struct ndpip_arp_peer) * iface_arp_table_len);
        (&iface)->iface_arp_table_len = iface_arp_table_len;
                                               
        return 0;                                 
}

struct ether_addr *ndpip_linux_dpdk_iface_resolve_arp(struct ndpip_iface *iface, struct in_addr peer)
{
        struct ndpip_linux_dpdk_iface *iface_linux_dpdk = (void *) iface;

        for (size_t idx = 0; idx < iface_linux_dpdk->iface_arp_table_len; idx++) {
                struct ndpip_arp_peer *cpeer = &iface_linux_dpdk->iface_arp_table[idx];

                if (cpeer->inaddr.s_addr == peer.s_addr)
                        return &cpeer->ethaddr;
        }

        return NULL;
}

int ndpip_linux_dpdk_pbuf_pool_release(struct ndpip_pbuf_pool *_, struct ndpip_pbuf **pb, uint16_t count)
{
        if (count == 0)                                                    
                return 0;
                                                        
	struct rte_mbuf **mb = (void *) pb;

	rte_pktmbuf_free_bulk(mb, count);

	return 0;
}

int ndpip_linux_dpdk_set_ethaddr(int netdev_id, struct ether_addr iface_ethaddr)
{
        if ((&iface)->iface_netdev_id != netdev_id)
                return -1;                               

        (&iface)->iface_ethaddr = iface_ethaddr;

        return 0;                                  
}

int ndpip_linux_dpdk_set_inaddr(int netdev_id, struct in_addr iface_inaddr)
{                                                        
        if ((&iface)->iface_netdev_id != netdev_id)
                return -1;
                                                                                  
        (&iface)->iface_inaddr = iface_inaddr;
                                                    
        return 0;                                     
}

int ndpip_linux_dpdk_set_rx_burst_size(int netdev_id, uint16_t iface_rx_burst_size)
{
                                      
        if ((&iface)->iface_netdev_id != netdev_id)
                return -1;

        if (iface_rx_burst_size > 0)
                (&iface)->iface_rx_burst_size = iface_rx_burst_size;
 
        else                             
                return -1;                               

        return 0;                 
}

void ndpip_linux_dpdk_time_now(struct timespec *req)
{
	uint64_t cycles = rte_get_tsc_cycles();

	req->tv_sec = cycles / tsc_hz;
	req->tv_nsec = (cycles % tsc_hz) * 1000000000UL / tsc_hz;
}
