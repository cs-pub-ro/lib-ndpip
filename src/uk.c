#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <uk/allocpool.h>
#include <uk/print.h>
#include <uk/thread.h>

#include "ndpip/pbuf_pool.h"
#include "ndpip/socket.h"
#include "ndpip/tcp.h"
#include "ndpip/uk.h"

#define NETBUF_ADDR_ALIGNMENT (sizeof(long long))
#define NETBUF_ADDR_ALIGN_UP(x) ALIGN_UP((__uptr) (x), NETBUF_ADDR_ALIGNMENT)

#define NDPIP_UK_DEFAULT_RX_QUEUE 0
#define NDPIP_UK_DEFAULT_TX_QUEUE 0

#define NDPIP_TODO_UK_PACKETS_COUNT 1024


static int get_netdev_info(struct ndpip_uk_iface *iface);
static int configure_netdev(struct ndpip_uk_iface *iface);
static int configure_netdev_queues(struct ndpip_uk_iface *iface);

static uint16_t alloc_rxpkts(void *argp, struct uk_netbuf **nb, uint16_t count);


static NDPIP_LIST_HEAD(ndpip_uk_timers_head);

static struct ndpip_uk_iface iface = {
	.iface_netdev_id = -1
};


static void ndpip_uk_rx_thread(void *argp)
{
	struct ndpip_iface *iface = argp;
	struct ndpip_uk_iface *uk_iface = (void *) iface;

	while (uk_iface->iface_rx_thread_running) {
		uk_sched_thread_sleep(10000);

		uint16_t pkt_cnt = uk_iface->iface_rx_burst_size;
		struct uk_netbuf *pkts[pkt_cnt];

		printf("%hu\n", pkt_cnt);

		int r = uk_netdev_rx_burst(
			uk_iface->iface_netdev,
			NDPIP_UK_DEFAULT_RX_QUEUE,
			pkts, &pkt_cnt);

		printf("%hu\n", pkt_cnt);

		if(uk_netdev_status_notready(r) || (pkt_cnt == 0))
			continue;

		printf("BRRC0\n");

		for (uint16_t idx = 0; idx < pkt_cnt; idx++) {
			struct uk_netbuf *pkt = pkts[idx];
			struct ethhdr *eth = pkt->data;

		printf("BRRC1\n");

			if (memcmp(eth->h_dest, ndpip_iface_get_ethaddr(iface), ETH_ALEN) != 0)
				continue;

		printf("BRRC2\n");
			if (ntohs(eth->h_proto) != ETH_P_IP)
				continue;

		printf("BRRC3\n");
			struct iphdr *iph = ((void *) eth) + sizeof(struct ethhdr);

			if (!((iph->ihl == 5) && (iph->version == 4)))
				continue;

			if (ntohl(iph->daddr) != ndpip_iface_get_inaddr(iface)->s_addr)
				continue;

			if (iph->protocol != IPPROTO_TCP)
				continue;

			struct tcphdr *th = ((void *) iph) + sizeof(struct iphdr);

			struct in_addr local_inaddr = { .s_addr = iph->daddr };
			uint16_t local_port = ntohs(th->th_dport);

			struct in_addr remote_inaddr = { .s_addr = iph->saddr };
			uint16_t remote_port = ntohs(th->th_sport);

			struct ndpip_socket *sock = ndpip_socket_get_by_peer(local_inaddr, local_port, remote_inaddr, remote_port);
			if (sock == NULL)
				continue;

			ndpip_tcp_feed(sock, &remote_inaddr, remote_port, th, ntohs(iph->tot_len) - sizeof(struct iphdr));
		}
	}
}

static void ndpip_uk_timers_thread(void *argp)
{
	struct ndpip_iface *iface = argp;
	struct ndpip_uk_iface *uk_iface = (void *) iface;

	while (uk_iface->iface_timers_thread_running) {
		ndpip_list_foreach(struct ndpip_timer, timer, &ndpip_uk_timers_head) {
			if (ndpip_timer_armed(timer) && ndpip_timer_expired(timer)) {
				ndpip_timer_disarm(timer);
				timer->func(timer->argp);
			}
		}

		uk_sched_thread_sleep(25000000);
	}
}

void ndpip_uk_timers_add(struct ndpip_timer *timer)
{
	ndpip_list_add(&ndpip_uk_timers_head, (void *) timer);
}

int ndpip_uk_register_iface(int netdev_id, bool intr)
{
	if ((&iface)->iface_netdev_id >= 0)
		return -1;

	(&iface)->iface_netdev = uk_netdev_get(netdev_id);
	if ((&iface)->iface_netdev == NULL)
		return -1;

	(&iface)->iface_netdev_id = netdev_id;

	(&iface)->iface_intr = intr;

	(&iface)->iface_alloc = uk_alloc_get_default();
	if ((&iface)->iface_alloc == NULL)
		return -1;

	(&iface)->iface_sched = uk_sched_get_default();
	if ((&iface)->iface_sched == NULL)
		return -1;

	if (get_netdev_info(&iface) < 0)
		return -1;

	(&iface)->iface_pbuf_pool_rx = ndpip_pbuf_pool_alloc(
		NDPIP_TODO_UK_PACKETS_COUNT,
		UK_ETH_PAYLOAD_MAXLEN,
		(&iface)->iface_netdev_info.ioalign,
		(&iface)->iface_netdev_info.nb_encap_rx);

	(&iface)->iface_pbuf_pool_tx = ndpip_pbuf_pool_alloc(
		NDPIP_TODO_UK_PACKETS_COUNT,
		UK_ETH_PAYLOAD_MAXLEN,
		(&iface)->iface_netdev_info.ioalign,
		(&iface)->iface_netdev_info.nb_encap_tx);

	if (((&iface)->iface_pbuf_pool_rx == NULL) ||
		((&iface)->iface_pbuf_pool_tx == NULL))
		return -1;

	if (configure_netdev(&iface) < 0)
		return -1;

	return 0;
}

int ndpip_uk_start_iface(int netdev_id)
{
	if ((&iface)->iface_netdev_id != netdev_id)
		return -1;

	(&iface)->iface_rx_thread_running = true;
	(&iface)->iface_rx_thread = uk_thread_create("ndpip_rx", ndpip_uk_rx_thread, &iface);

	(&iface)->iface_timers_thread_running = true;
	(&iface)->iface_timers_thread = uk_thread_create("ndpip_timers", ndpip_uk_timers_thread, &iface);

	if (uk_netdev_start((&iface)->iface_netdev) < 0)
		return -1;

	if ((&iface)->iface_intr) {
		if (uk_netdev_rxq_intr_enable((&iface)->iface_netdev, NDPIP_UK_DEFAULT_RX_QUEUE) < 0)
			return -1;
	} else {
		if (uk_netdev_rxq_intr_disable((&iface)->iface_netdev, NDPIP_UK_DEFAULT_RX_QUEUE) < 0)
			return -1;
	}

	return 0;
}

int ndpip_uk_stop_iface(int netdev_id)
{
	if ((&iface)->iface_netdev_id != netdev_id)
		return -1;

	(&iface)->iface_rx_thread_running = false;
	if (uk_thread_wait((&iface)->iface_rx_thread) < 0)
		return -1;

	(&iface)->iface_timers_thread_running = false;
	if (uk_thread_wait((&iface)->iface_timers_thread) < 0)
		return -1;

	return 0;
}

int ndpip_uk_set_ethaddr(int netdev_id, struct ether_addr iface_ethaddr)
{
	if ((&iface)->iface_netdev_id != netdev_id)
		return -1;

	(&iface)->iface_ethaddr = iface_ethaddr;

	return 0;
}

struct ether_addr *ndpip_uk_iface_get_ethaddr(struct ndpip_iface *)
{
	return &(&iface)->iface_ethaddr;
}

int ndpip_uk_set_inaddr(int netdev_id, struct in_addr iface_inaddr)
{
	if ((&iface)->iface_netdev_id != netdev_id)
		return -1;

	(&iface)->iface_inaddr = iface_inaddr;

	return 0;
}

int ndpip_uk_set_arp_table(int netdev_id, struct ndpip_arp_peer *iface_arp_table, size_t iface_arp_table_len)
{
	if ((&iface)->iface_netdev_id != netdev_id)
		return -1;

	(&iface)->iface_arp_table = iface_arp_table;
	(&iface)->iface_arp_table_len = iface_arp_table_len;

	return 0;
}

int ndpip_uk_set_rxtx_burst_size(int netdev_id, uint16_t iface_rx_burst_size)
{

	if ((&iface)->iface_netdev_id != netdev_id)
		return -1;

	if (iface_rx_burst_size > 0)
		(&iface)->iface_rx_burst_size = iface_rx_burst_size;

	else
		return -1;

	return 0;
}

uint32_t ndpip_uk_pbuf_refcount_get(struct ndpip_pbuf *pbuf)
{
	struct uk_netbuf *nb = (void *) pbuf;
	return uk_refcount_read(&nb->refcount);
}

void ndpip_uk_pbuf_refcount_set(struct ndpip_pbuf *pbuf, uint32_t val)
{
	struct uk_netbuf *nb = (void *) pbuf;
	uk_refcount_init(&nb->refcount, val);
}

void ndpip_uk_pbuf_refcount_dec(struct ndpip_pbuf *pbuf)
{
	struct uk_netbuf *nb = (void *) pbuf;
	uk_refcount_release(&nb->refcount);
}

void ndpip_uk_pbuf_refcount_inc(struct ndpip_pbuf *pbuf)
{
	struct uk_netbuf *nb = (void *) pbuf;
	uk_refcount_acquire(&nb->refcount);
}

void *ndpip_uk_pbuf_data(struct ndpip_pbuf *pbuf)
{
	struct uk_netbuf *nb = (void *) pbuf;
	return nb->data;
}

static void dummy_free_txpkts(void *argp, struct uk_netbuf *pkts[], uint16_t count)
{
	(void) argp;
	(void) pkts;
	(void) count;
}

static int configure_netdev_queues(struct ndpip_uk_iface *iface)
{
	iface->iface_txqueue_conf = (struct uk_netdev_txqueue_conf) {
		.a = iface->iface_alloc,
		.free_txpkts = dummy_free_txpkts,
		.free_txpkts_argp = NULL
	};

	iface->iface_rxqueue_conf = (struct uk_netdev_rxqueue_conf) {
		.a = iface->iface_alloc,
		.alloc_rxpkts = alloc_rxpkts,
		.alloc_rxpkts_argp = iface,
		.callback = NULL,
		.callback_cookie = NULL,
		.s = NULL
	};

	if (iface->iface_intr) {
		iface->iface_rxqueue_conf.callback = NULL;
		iface->iface_rxqueue_conf.s = iface->iface_sched;
	}

	if (uk_netdev_rxq_configure(iface->iface_netdev, NDPIP_UK_DEFAULT_RX_QUEUE, 0, &iface->iface_rxqueue_conf) < 0)
		return -1;

	if (uk_netdev_txq_configure(iface->iface_netdev, NDPIP_UK_DEFAULT_TX_QUEUE, 0, &iface->iface_txqueue_conf) < 0)
		return -1;

	return 0;
}

static int get_netdev_info(struct ndpip_uk_iface *iface)
{
	uk_netdev_info_get(iface->iface_netdev, &iface->iface_netdev_info);

	if (iface->iface_netdev_info.max_rx_queues <= 0)
		return -1;

	if (iface->iface_netdev_info.max_tx_queues <= 0)
		return -1;

	return 0;
}

static int configure_netdev(struct ndpip_uk_iface *iface)
{
	if (uk_netdev_state_get(iface->iface_netdev) != UK_NETDEV_UNCONFIGURED)
		return -1;

	iface->iface_netdev_conf = (struct uk_netdev_conf) {
		.nb_rx_queues = 1,
		.nb_tx_queues = 1
	};

	if (uk_netdev_configure(iface->iface_netdev, &iface->iface_netdev_conf) < 0)
		return -1;

	if (configure_netdev_queues(iface) < 0)
		return -1;

	if (uk_netdev_mtu_get(iface->iface_netdev) != UK_ETH_PAYLOAD_MAXLEN)
		return -1;

	return 0;
}

static uint16_t alloc_rxpkts(void *argp, struct uk_netbuf **nb, uint16_t count)
{
	struct ndpip_uk_iface *iface = argp;
	struct ndpip_pbuf **pb = (void *) nb;

	uint16_t rcount = count;
	if (ndpip_pbuf_pool_request(ndpip_iface_get_pbuf_pool_rx(iface), pb, &rcount) < 0)
		return 0;

	return rcount;
}

struct ndpip_pbuf_pool *ndpip_uk_pbuf_pool_alloc(size_t pbuf_count, uint16_t pbuf_size, size_t pbuf_allign, uint16_t pbuf_headroom)
{
	struct uk_alloc *a = uk_alloc_get_default();
	pbuf_size = NETBUF_ADDR_ALIGN_UP(sizeof(struct uk_netbuf)) + NETBUF_ADDR_ALIGN_UP(pbuf_size);

	size_t min_allign = 1 << (16 - __builtin_clz(pbuf_size));
	pbuf_allign = min_allign > pbuf_allign ? min_allign : pbuf_allign;

	struct ndpip_uk_pbuf_pool *ret = malloc(sizeof(struct ndpip_uk_pbuf_pool));
	if (ret == NULL)
		return NULL;

	struct uk_allocpool *p = uk_allocpool_alloc(a, pbuf_count, pbuf_size, pbuf_allign);
	if (p == NULL)
		return NULL;

	*ret = (struct ndpip_uk_pbuf_pool) {
		.pool_pool = p,
		.pool_pbcount = pbuf_count,
		.pool_pbsize = pbuf_size,
		.pool_pbheadroom = pbuf_headroom
	};

	return (void *) ret;
}

int ndpip_uk_pbuf_pool_request(struct ndpip_pbuf_pool *pool, struct ndpip_pbuf **pb, uint16_t *count)
{
	struct ndpip_uk_pbuf_pool *pool_uk = (void *) pool;

	struct uk_allocpool *p = pool_uk->pool_pool;

	void *objs[*count];
	*count = uk_allocpool_take_batch(p, objs, *count);
	if (*count <= 0)
		return -1;

	for (uint16_t idx = 0; idx < *count; idx++) {
		pb[idx] = (void *) uk_netbuf_prepare_buf(
			objs[idx],
			pool_uk->pool_pbsize,
			pool_uk->pool_pbheadroom,
			0, NULL);
	}

	return 0;
}

struct in_addr *ndpip_uk_iface_get_inaddr(struct ndpip_iface *iface)
{
	return &((struct ndpip_uk_iface *) iface)->iface_inaddr;
}

struct ndpip_iface *ndpip_uk_iface_get_by_inaddr(struct in_addr addr)
{
	if (ndpip_iface_get_inaddr((void *) &iface)->s_addr == addr.s_addr)
		return (struct ndpip_iface *)(void *) &iface;
	else
		return NULL;
}

int ndpip_uk_iface_xmit(struct ndpip_iface *iface, struct ndpip_pbuf **pb, uint16_t cnt)
{
	for (uint16_t idx = 0; idx < cnt; idx++) {
		/* hack to work around a bug */
		uk_netbuf_header((struct uk_netbuf *)(void *) pb[idx], -10);
	}

	for (uint16_t off = 0, cnt2 = cnt; off < cnt; off += cnt2, cnt2 = cnt - off) {
		int ret;

		do {
			ret = uk_netdev_tx_burst(((struct ndpip_uk_iface *) iface)->iface_netdev, NDPIP_UK_DEFAULT_TX_QUEUE, (struct uk_netbuf **) pb, &cnt2);
		} while(uk_netdev_status_notready(ret));

		if (ret < 0)
			return -1;
	}

	return 0;
}

struct ether_addr *ndpip_uk_iface_resolve_arp(struct ndpip_iface *iface, struct in_addr peer)
{
	struct ndpip_uk_iface *uk_iface = (void *) iface;

	for (size_t idx = 0; idx < uk_iface->iface_arp_table_len; idx++) {
		struct ndpip_arp_peer *cpeer = &uk_iface->iface_arp_table[idx];

		if (cpeer->inaddr.s_addr == peer.s_addr)
			return &cpeer->ethaddr;
	}

	return NULL;
}

int ndpip_uk_pbuf_resize(struct ndpip_pbuf *pb, uint16_t len)
{
	((struct uk_netbuf *)(void *) pb)->len = len;

	return 0;
}

void ndpip_uk_nanosleep(uint64_t nsec)
{
	uint64_t until = ukplat_monotonic_clock() + nsec;
	
	while (until > ukplat_monotonic_clock())
		ukplat_lcpu_halt_to(until);
}
