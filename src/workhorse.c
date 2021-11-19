#include "ndpip/util.h"
#include "ndpip/socket.h"
#include "ndpip/tcp.h"
#include "ndpip/workhorse.h"

#ifdef NDPIP_UK
#include "ndpip/uk.h"
#endif

#ifdef NDPIP_LINUX_DPDK
#include "ndpip/linux_dpdk.h"
#endif

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

int ndpip_rx_thread(void *argp)
{
	struct ndpip_iface *iface = argp;
	uint64_t before = rdtsc();
	uint16_t rx_burst_size = ndpip_iface_get_rx_burst_size(iface);

	while (ndpip_iface_rx_thread_running(iface)) {
		uint64_t now = rdtsc();

		if ((now - before) > 1000000000UL) {
			before = now;
			ndpip_thread_yield();
		}

		uint16_t pkt_cnt = rx_burst_size;
		struct ndpip_pbuf *pkts[pkt_cnt];

		int r = ndpip_iface_rx_burst(iface, (void *) pkts, &pkt_cnt);

		if ((r < 0) || (pkt_cnt == 0))
			continue;

		uint16_t replies_len = 0;
		struct ndpip_pbuf *replies[pkt_cnt];

		uint16_t tmp_pkt_cnt = pkt_cnt;
		assert(ndpip_pbuf_pool_request(ndpip_iface_get_pbuf_pool_tx(iface), replies, &tmp_pkt_cnt) >= 0);
		assert(tmp_pkt_cnt == pkt_cnt);

		for (uint16_t idx = 0; idx < pkt_cnt; idx++) {
			struct ndpip_pbuf *pb = pkts[idx];
			struct ethhdr *eth = ndpip_pbuf_data(pb);

			if (memcmp(eth->h_dest, ndpip_iface_get_ethaddr(iface), ETH_ALEN) != 0)
				continue;

			if (ntohs(eth->h_proto) != ETH_P_IP)
				continue;

			struct iphdr *iph = ((void *) eth) + sizeof(struct ethhdr);

			if (!((iph->ihl == 5) && (iph->version == 4)))
				continue;

			if (iph->daddr != ndpip_iface_get_inaddr(iface)->s_addr)
				continue;

			if (iph->protocol != IPPROTO_TCP)
				continue;

			struct tcphdr *th = ((void *) iph) + sizeof(struct iphdr);

			struct sockaddr_in local = {
				.sin_family = AF_INET,
				.sin_addr.s_addr = iph->daddr,
				.sin_port = ntohs(th->th_dport)
			};

			struct sockaddr_in remote = {
				.sin_family = AF_INET,
				.sin_addr.s_addr = iph->saddr,
				.sin_port = ntohs(th->th_sport)
			};

			struct ndpip_socket *sock = ndpip_socket_get_by_peer(&local, &remote);
			if (sock == NULL)
				continue;

			ndpip_pbuf_offset(pb, -(int) (sizeof(struct ethhdr) + sizeof(struct iphdr)));
			int r = ndpip_tcp_feed(sock, &remote, pb, replies[replies_len]);
			if (r > 0)
				replies_len++;
		}

		if (replies_len > 0)
			ndpip_iface_xmit(iface, replies, replies_len);

		ndpip_pbuf_pool_release(ndpip_iface_get_pbuf_pool_tx(iface), replies + replies_len, pkt_cnt - replies_len);
	}

	return 0;
}

static NDPIP_LIST_HEAD(ndpip_timers_head);

void ndpip_timers_add(struct ndpip_timer *timer)
{
        ndpip_list_add(&ndpip_timers_head, (void *) timer);
}

int ndpip_timers_thread(void *argp)
{
	struct ndpip_iface *iface = argp;

	while (ndpip_iface_timers_thread_running(iface)) {
		ndpip_list_foreach(struct ndpip_timer, timer, &ndpip_timers_head) {
			if (ndpip_timer_armed(timer) && ndpip_timer_expired(timer)) {
				ndpip_timer_disarm(timer);
				timer->func(timer->argp);
			}
		}

		ndpip_nanosleep(25000000);
	}

	return 0;
}
