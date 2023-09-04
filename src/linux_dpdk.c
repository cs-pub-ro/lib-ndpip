#include "ndpip/linux_dpdk.h"
#include "ndpip/workhorse.h"

#include <assert.h>
#include <unistd.h>

#include <rte_version.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#define NDPIP_TODO_NB_MBUF (1 << 15)
#define NDPIP_TODO_MEMPOOL_CACHE_SZ 256
#define NDPIP_TODO_MBUF_SIZE 3072
#define NDPIP_TODO_MTU 1500
#define NDPIP_LINUX_DPDK_MBUF_PRIVATE RTE_ALIGN_CEIL(sizeof(struct ndpip_pbuf_meta), RTE_MBUF_PRIV_ALIGN)
#define NDPIP_LINUX_DPDK_RX_BURST_RETRIES 1000

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

void ndpip_linux_dpdk_thread_yield() { }

void ndpip_linux_dpdk_timers_usleep(unsigned usecs) {
	usleep(usecs);
}

int ndpip_linux_dpdk_register_iface(int netdev_id)
{
	tsc_hz = rte_get_tsc_hz();

        if ((&iface)->iface_netdev_id >= 0) {
		perror("iface_netdev_id >= 0");
                return -1;
	}

	(&iface)->iface_netdev_id = netdev_id;
	(&iface)->iface_rx_queue_id = 0;
	(&iface)->iface_tx_queue_id = 0;

	memset(&(&iface)->iface_conf, 0, sizeof(struct rte_eth_conf));
        (&iface)->iface_conf.rxmode.max_lro_pkt_size = NDPIP_TODO_MTU;
//        (&iface)->iface_conf.rxmode.mtu = NDPIP_TODO_MTU;

	if (rte_eth_dev_info_get((&iface)->iface_netdev_id, &(&iface)->iface_dev_info) < 0) {
		perror("rte_eth_dev_info_get");
		return -1;
	}

#if RTE_VERSION < RTE_VERSION_NUM(21, 11, 0, 0)
	if ((&iface)->iface_dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM)
        	(&iface)->iface_conf.txmode.offloads |= DEV_TX_OFFLOAD_IPV4_CKSUM;

	if ((&iface)->iface_dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM)
        	(&iface)->iface_conf.txmode.offloads |= DEV_TX_OFFLOAD_TCP_CKSUM;

	if ((&iface)->iface_dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM)
        	(&iface)->iface_conf.txmode.offloads |= DEV_TX_OFFLOAD_UDP_CKSUM;

	if ((&iface)->iface_dev_info.rx_offload_capa & DEV_RX_OFFLOAD_IPV4_CKSUM)
        	(&iface)->iface_conf.rxmode.offloads |= DEV_RX_OFFLOAD_IPV4_CKSUM;

	if ((&iface)->iface_dev_info.rx_offload_capa & DEV_RX_OFFLOAD_TCP_CKSUM)
        	(&iface)->iface_conf.rxmode.offloads |= DEV_RX_OFFLOAD_TCP_CKSUM;

	if ((&iface)->iface_dev_info.rx_offload_capa & DEV_RX_OFFLOAD_UDP_CKSUM)
        	(&iface)->iface_conf.rxmode.offloads |= DEV_RX_OFFLOAD_UDP_CKSUM;
#else 
	if ((&iface)->iface_dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM)
        	(&iface)->iface_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;

	if ((&iface)->iface_dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM)
        	(&iface)->iface_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_CKSUM;

	if ((&iface)->iface_dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM)
        	(&iface)->iface_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_UDP_CKSUM;

	if ((&iface)->iface_dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM)
        	(&iface)->iface_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;

	if ((&iface)->iface_dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_CKSUM)
        	(&iface)->iface_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TCP_CKSUM;

	if ((&iface)->iface_dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_UDP_CKSUM)
        	(&iface)->iface_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_UDP_CKSUM;
#endif

	if (rte_eth_dev_configure((&iface)->iface_netdev_id, 1, 1, &(&iface)->iface_conf) < 0) {
		perror("rte_eth_dev_configure");
		return -1;
	}

	(&iface)->iface_pbuf_pool_rx = (void *) rte_pktmbuf_pool_create("ndpip_pool_rx", NDPIP_TODO_NB_MBUF, NDPIP_TODO_MEMPOOL_CACHE_SZ, NDPIP_LINUX_DPDK_MBUF_PRIVATE, NDPIP_TODO_MBUF_SIZE, rte_socket_id());
	if ((&iface)->iface_pbuf_pool_rx == NULL) {
		perror("rte_pktmbuf_pool_create");
		return -1;
	}

	(&iface)->iface_pbuf_pool_tx = (void *) rte_pktmbuf_pool_create("ndpip_pool_tx", NDPIP_TODO_NB_MBUF, NDPIP_TODO_MEMPOOL_CACHE_SZ, NDPIP_LINUX_DPDK_MBUF_PRIVATE, NDPIP_TODO_MBUF_SIZE, rte_socket_id());
	if ((&iface)->iface_pbuf_pool_tx == NULL) {
		perror("rte_pktmbuf_pool_create");
		return -1;
	}

	if (rte_eth_rx_queue_setup((&iface)->iface_netdev_id, (&iface)->iface_rx_queue_id, 2048, rte_eth_dev_socket_id((&iface)->iface_netdev_id), NULL, (void *) (&iface)->iface_pbuf_pool_rx) < 0) {
		perror("rte_eth_rx_queue_setup");
		return -1;
	}

	if (rte_eth_tx_queue_setup((&iface)->iface_netdev_id, (&iface)->iface_tx_queue_id, 2048, rte_eth_dev_socket_id((&iface)->iface_netdev_id), NULL) < 0) {
		perror("rte_eth_tx_queue_setup");
		return -1;
	}

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

	unsigned rx_lcore = rte_get_next_lcore(rte_lcore_id(), 1, 1);

	pthread_create(&(&iface)->iface_timers_thread, NULL, ndpip_linux_dpdk_timers_thread, &iface);
	rte_eal_remote_launch(ndpip_rx_thread, &iface, rx_lcore);

	return 0;
}

int ndpip_linux_dpdk_iface_xmit(struct ndpip_iface *iface, struct ndpip_pbuf **pb, uint16_t cnt, bool free)
{
	struct rte_mbuf **mb = (void *) pb;
	struct ndpip_linux_dpdk_iface *iface_linux_dpdk = (void *) iface;

	if (!free)
		for (uint16_t idx = 0; idx < cnt; idx++)
			rte_mbuf_refcnt_update(mb[idx], 1);

	rte_eth_tx_prepare(iface_linux_dpdk->iface_netdev_id, iface_linux_dpdk->iface_tx_queue_id, mb, cnt);
	uint16_t max_burst = ndpip_iface_get_burst_size(iface);

	for (uint16_t idx = 0; idx < cnt;) {
		uint16_t cnt2 = cnt - idx;
		cnt2 = max_burst < cnt2 ? max_burst : cnt2;

		/*
		printf("tcp.seq=[");
		for (uint16_t idx = 0; idx < cnt; idx++)
			printf("%u ", ntohl(((struct tcphdr *) (ndpip_pbuf_data(pb[idx]) + sizeof(struct ethhdr) + sizeof(struct iphdr)))->th_seq));
		printf("];\n");
		*/

		idx += rte_eth_tx_burst(
			iface_linux_dpdk->iface_netdev_id,
			iface_linux_dpdk->iface_tx_queue_id,
			mb + idx, cnt2);
	}

	return 0;
}

int ndpip_linux_dpdk_iface_rx_burst(struct ndpip_iface *iface, struct ndpip_pbuf **pb, uint16_t *cnt)
{
	struct rte_mbuf **mb = (void *) pb;
	struct ndpip_linux_dpdk_iface *iface_linux_dpdk = (void *) iface;

	uint16_t tmp_cnt = *cnt;

	for (int i = 0; i < NDPIP_LINUX_DPDK_RX_BURST_RETRIES; i++) {
		uint16_t r_cnt = rte_eth_rx_burst(iface_linux_dpdk->iface_netdev_id, iface_linux_dpdk->iface_rx_queue_id, mb, tmp_cnt);
		if (r_cnt > 0) {
			*cnt = r_cnt;
			return 0;
		}
	}

	return -1;
}

void *ndpip_linux_dpdk_pbuf_data(struct ndpip_pbuf *pbuf)
{
	struct rte_mbuf *mb = (void *) pbuf;

	return rte_pktmbuf_mtod(mb, void *);
}

struct ndpip_pbuf_meta *ndpip_linux_dpdk_pbuf_metadata(struct ndpip_pbuf *pbuf)
{
	struct rte_mbuf *mb = (void *) pbuf;

	return rte_mbuf_to_priv(mb);
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

void ndpip_linux_dpdk_usleep(unsigned usec)
{
	rte_delay_us_block(usec);
}

uint16_t ndpip_iface_get_burst_size(struct ndpip_iface *iface)
{
	struct ndpip_linux_dpdk_iface *iface_linux_dpdk = (void *) iface;

	return iface_linux_dpdk->iface_burst_size;
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

int ndpip_linux_dpdk_set_burst_size(int netdev_id, uint16_t iface_burst_size)
{
                                      
        if ((&iface)->iface_netdev_id != netdev_id)
                return -1;

        if (iface_burst_size > 0)
                (&iface)->iface_burst_size = iface_burst_size;
 
        else                             
                return -1;                               

        return 0;                 
}

uint64_t ndpip_linux_dpdk_tsc()
{
	return rte_get_tsc_cycles();
}

void ndpip_linux_dpdk_tsc2time(uint64_t cycles, struct timespec *req)
{
	req->tv_sec = cycles / tsc_hz;
	req->tv_nsec = (cycles % tsc_hz) * NDPIP_NSEC_IN_SEC / tsc_hz;
}

void ndpip_linux_dpdk_time_now(struct timespec *req)
{
	return ndpip_linux_dpdk_tsc2time(ndpip_linux_dpdk_tsc(), req);
}

void ndpip_linux_dpdk_pbuf_refcount_add(struct ndpip_pbuf *pb, int16_t val)
{
	struct rte_mbuf *mb = (void *) pb;
	rte_mbuf_refcnt_update(mb, val);
}

void *ndpip_linux_dpdk_timers_thread(void *argp)
{
	struct ndpip_iface *iface = argp;
	ndpip_timers_thread(iface);

	return NULL;
}

bool ndpip_linux_dpdk_iface_has_offload(struct ndpip_iface *iface, enum ndpip_iface_offload off)
{
	struct ndpip_linux_dpdk_iface *iface_linux_dpdk = (void *) iface;

	switch (off) {
#if RTE_VERSION < RTE_VERSION_NUM(21, 11, 0, 0)
		case NDPIP_IFACE_OFFLOAD_TX_IPV4_CSUM:
			return iface_linux_dpdk->iface_conf.txmode.offloads & DEV_TX_OFFLOAD_IPV4_CKSUM;

		case NDPIP_IFACE_OFFLOAD_TX_TCPV4_CSUM:
			return iface_linux_dpdk->iface_conf.txmode.offloads & DEV_TX_OFFLOAD_TCP_CKSUM;

		case NDPIP_IFACE_OFFLOAD_TX_UDPV4_CSUM:
			return iface_linux_dpdk->iface_conf.txmode.offloads & DEV_TX_OFFLOAD_UDP_CKSUM;

		case NDPIP_IFACE_OFFLOAD_RX_IPV4_CSUM:
			return iface_linux_dpdk->iface_conf.rxmode.offloads & DEV_RX_OFFLOAD_IPV4_CKSUM;

		case NDPIP_IFACE_OFFLOAD_RX_TCPV4_CSUM:
			return iface_linux_dpdk->iface_conf.rxmode.offloads & DEV_RX_OFFLOAD_TCP_CKSUM;

		case NDPIP_IFACE_OFFLOAD_RX_UDPV4_CSUM:
			return iface_linux_dpdk->iface_conf.rxmode.offloads & DEV_RX_OFFLOAD_UDP_CKSUM;
#else
		case NDPIP_IFACE_OFFLOAD_TX_IPV4_CSUM:
			return iface_linux_dpdk->iface_conf.txmode.offloads & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;

		case NDPIP_IFACE_OFFLOAD_TX_TCPV4_CSUM:
			return iface_linux_dpdk->iface_conf.txmode.offloads & RTE_ETH_TX_OFFLOAD_TCP_CKSUM;

		case NDPIP_IFACE_OFFLOAD_TX_UDPV4_CSUM:
			return iface_linux_dpdk->iface_conf.txmode.offloads & RTE_ETH_TX_OFFLOAD_UDP_CKSUM;

		case NDPIP_IFACE_OFFLOAD_RX_IPV4_CSUM:
			return iface_linux_dpdk->iface_conf.rxmode.offloads & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;

		case NDPIP_IFACE_OFFLOAD_RX_TCPV4_CSUM:
			return iface_linux_dpdk->iface_conf.rxmode.offloads & RTE_ETH_RX_OFFLOAD_TCP_CKSUM;

		case NDPIP_IFACE_OFFLOAD_RX_UDPV4_CSUM:
			return iface_linux_dpdk->iface_conf.rxmode.offloads & RTE_ETH_RX_OFFLOAD_UDP_CKSUM;
#endif

		default:
			return false;
	}
}

bool ndpip_linux_dpdk_pbuf_has_flag(struct ndpip_pbuf *pb, enum ndpip_pbuf_flag flag)
{
	struct rte_mbuf *mb = (void *) pb;

	switch (flag) {
#if RTE_VERSION < RTE_VERSION_NUM(21, 11, 0, 0)
		case NDPIP_PBUF_F_RX_L4_CSUM_GOOD:
			return (mb->ol_flags & PKT_RX_L4_CKSUM_MASK) == PKT_RX_L4_CKSUM_GOOD;

		case NDPIP_PBUF_F_RX_L4_CSUM_BAD:
			return (mb->ol_flags & PKT_RX_L4_CKSUM_MASK) == PKT_RX_L4_CKSUM_BAD;

		case NDPIP_PBUF_F_RX_L4_CSUM_NONE:
			return (mb->ol_flags & PKT_RX_L4_CKSUM_MASK) == PKT_RX_L4_CKSUM_NONE;

		case NDPIP_PBUF_F_RX_IP_CSUM_GOOD:
			return (mb->ol_flags & PKT_RX_IP_CKSUM_MASK) == PKT_RX_IP_CKSUM_GOOD;

		case NDPIP_PBUF_F_RX_IP_CSUM_BAD:
			return (mb->ol_flags & PKT_RX_IP_CKSUM_MASK) == PKT_RX_IP_CKSUM_BAD;

		case NDPIP_PBUF_F_RX_IP_CSUM_NONE:
			return (mb->ol_flags & PKT_RX_IP_CKSUM_MASK) == PKT_RX_IP_CKSUM_NONE;
#else
		case NDPIP_PBUF_F_RX_L4_CSUM_GOOD:
			return (mb->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) == RTE_MBUF_F_RX_L4_CKSUM_GOOD;

		case NDPIP_PBUF_F_RX_L4_CSUM_BAD:
			return (mb->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) == RTE_MBUF_F_RX_L4_CKSUM_BAD;

		case NDPIP_PBUF_F_RX_L4_CSUM_NONE:
			return (mb->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) == RTE_MBUF_F_RX_L4_CKSUM_NONE;

		case NDPIP_PBUF_F_RX_IP_CSUM_GOOD:
			return (mb->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) == RTE_MBUF_F_RX_IP_CKSUM_GOOD;

		case NDPIP_PBUF_F_RX_IP_CSUM_BAD:
			return (mb->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) == RTE_MBUF_F_RX_IP_CKSUM_BAD;

		case NDPIP_PBUF_F_RX_IP_CSUM_NONE:
			return (mb->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) == RTE_MBUF_F_RX_IP_CKSUM_NONE;
#endif

		default:
			return false;
	}
}

void ndpip_linux_dpdk_pbuf_set_flag(struct ndpip_pbuf *pb, enum ndpip_pbuf_flag flag, bool val)
{
	uint64_t ol_flag;

	switch (flag) {
#if RTE_VERSION < RTE_VERSION_NUM(21, 11, 0, 0)
		case NDPIP_PBUF_F_TX_IP_CKSUM:
			ol_flag = PKT_TX_IP_CKSUM;
			break;

		case NDPIP_PBUF_F_TX_TCP_CKSUM:
			ol_flag = PKT_TX_TCP_CKSUM;
			break;

		case NDPIP_PBUF_F_TX_IPV4:
			ol_flag = PKT_TX_IPV4;
			break;
#else
		case NDPIP_PBUF_F_TX_IP_CKSUM:
			ol_flag = RTE_MBUF_F_TX_IP_CKSUM;
			break;

		case NDPIP_PBUF_F_TX_TCP_CKSUM:
			ol_flag = RTE_MBUF_F_TX_TCP_CKSUM;
			break;

		case NDPIP_PBUF_F_TX_IPV4:
			ol_flag = RTE_MBUF_F_TX_IPV4;
			break;
#endif
		default:
			return;
	}

	struct rte_mbuf *mb = (void *) pb;

	if (val)
		mb->ol_flags |= ol_flag;
	else
		mb->ol_flags &= ~ol_flag;
}

void ndpip_linux_dpdk_pbuf_set_l2_len(struct ndpip_pbuf *pb, uint16_t val)
{
	struct rte_mbuf *mb = (void *) pb;

	mb->l2_len = val;
}

void ndpip_linux_dpdk_pbuf_set_l3_len(struct ndpip_pbuf *pb, uint16_t val)
{
	struct rte_mbuf *mb = (void *) pb;

	mb->l3_len = val;
}

uint16_t ndpip_linux_dpdk_iface_get_mtu(struct ndpip_iface *iface)
{
	struct ndpip_linux_dpdk_iface *iface_linux_dpdk = (void *) iface;

	return iface_linux_dpdk->iface_conf.rxmode.max_lro_pkt_size;
//	return iface_linux_dpdk->iface_conf.rxmode.mtu;
}

uint16_t ndpip_linux_dpdk_ipv4_cksum(struct iphdr *iph)
{
	return rte_ipv4_cksum((void *) iph);
}

uint16_t ndpip_linux_dpdk_ipv4_udptcp_cksum(struct iphdr *iph, void *l4h)
{
	return rte_ipv4_udptcp_cksum((void *) iph, l4h);
}

struct ndpip_pbuf *ndpip_linux_dpdk_pbuf_copy(struct ndpip_pbuf *pb, struct ndpip_pbuf_pool *pool, uint32_t offset, uint32_t length)
{
	struct rte_mbuf *m = (void *) pb;
	struct rte_mempool *p = (void *) pool;

	return (void *) rte_pktmbuf_copy(m, p, offset, length);
}
