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

#include <arpa/inet.h>

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <dnet/ip.h>

int ndpip_rx_thread(void *argp)
{
	struct ndpip_iface *iface = argp;
	uint16_t burst_size = ndpip_iface_get_burst_size(iface);

	uint64_t iter = 0;
	uint64_t pkt_cnt_a = 0;
	uint64_t replies_len_a = 0;

	while (ndpip_iface_rx_thread_running(iface)) {
		uint16_t pkt_cnt = burst_size;
		struct ndpip_pbuf *pkts[pkt_cnt];

		int r = ndpip_iface_rx_burst(iface, (void *) pkts, &pkt_cnt);

		if ((r < 0) || (pkt_cnt == 0))
			continue;

		struct ndpip_socket *reply_sockets[pkt_cnt];
		uint16_t reply_sockets_len = 0;

		uint16_t replies_len = 0;
		struct ndpip_pbuf *replies[pkt_cnt];

		uint16_t tmp_pkt_cnt = pkt_cnt;
		assert(ndpip_pbuf_pool_request(ndpip_iface_get_pbuf_pool_tx(iface), replies, &tmp_pkt_cnt) >= 0);
		assert(tmp_pkt_cnt == pkt_cnt);

		for (uint16_t idx = 0; idx < pkt_cnt; idx++) {
			struct ndpip_pbuf *pb = pkts[idx];

			if (ndpip_pbuf_length(pb) < sizeof(struct ethhdr))
				goto free_pkt;

			struct ethhdr *eth = ndpip_pbuf_data(pb);

			uint8_t bcast[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
			if ((memcmp(eth->h_dest, ndpip_iface_get_ethaddr(iface), ETH_ALEN) != 0) &&
				(memcmp(eth->h_dest, bcast, ETH_ALEN) != 0))
				goto free_pkt;

			if (ntohs(eth->h_proto) == ETH_P_EQDSCN) {
				struct eqds_cn *cn = ((void *) eth) + sizeof(struct ethhdr);
				struct in_addr cn_destination = { .s_addr = cn->destination };
				int32_t cn_value1 = ntohl(cn->value1);
				int32_t cn_value2 = ntohl(cn->value2);

				// printf("CN: operation=%d; destination=%s; value1=%d; value2=%d;\n", cn->operation, inet_ntoa(cn_destination), cn_value1, cn_value2);

				ndpip_socket_foreach(sock) {
					if ((*sock) == NULL)
						continue;

					if ((*sock)->remote.sin_addr.s_addr == cn->destination) {
						if ((cn->operation == CN_GRANTS_SET) && ((*sock)->grants_overhead < 0)) {
							(*sock)->grants = cn_value1;
							(*sock)->grants_overhead = cn_value2;
						}

						if ((cn->operation == CN_GRANTS_INC) && ((*sock)->grants_overhead >= 0))
							(*sock)->grants += cn_value1;

						// printf("CN: grants=%ld;\n", (*sock)->grants);
					}
				}

				goto free_pkt;
			}

			if (ntohs(eth->h_proto) != ETH_P_IP)
				goto free_pkt;

			if (ndpip_pbuf_length(pb) < (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
				goto free_pkt;

			struct iphdr *iph = ((void *) eth) + sizeof(struct ethhdr);

			if (!ndpip_iface_has_offload(iface, NDPIP_IFACE_OFFLOAD_RX_IPV4_CSUM)) {
				if (ipv4_checksum(iph) != 0)
					goto free_pkt;
			}

			if (!((iph->ihl == 5) && (iph->version == 4)))
				goto free_pkt;

			if (iph->daddr != ndpip_iface_get_inaddr(iface)->s_addr)
				goto free_pkt;

			if (iph->protocol != IPPROTO_TCP)
				goto free_pkt;

			struct tcphdr *th = ((void *) iph) + sizeof(struct iphdr);

			if (!ndpip_iface_has_offload(iface, NDPIP_IFACE_OFFLOAD_RX_TCPV4_CSUM)) {
				if (tcpv4_checksum(iph) != 0)
					goto free_pkt;
			} else {
				if (ndpip_pbuf_has_flag(pb, NDPIP_PBUF_F_RX_L4_CSUM_BAD))
					goto free_pkt;
			}

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
				goto free_pkt;

			if (!sock->rx_loop_seen) {
				reply_sockets[reply_sockets_len++] = sock;
				sock->rx_loop_seen = true;
			}

			ndpip_pbuf_offset(pb, -(int) (sizeof(struct ethhdr) + sizeof(struct iphdr)));
			ndpip_pbuf_resize(pb, ntohs(iph->tot_len) - (iph->ihl << 2));
			int r = ndpip_tcp_feed(sock, &remote, pb, replies[replies_len]);
			if (r == 1)
				replies_len++;

			if (r == 2)
				continue;

free_pkt:
			ndpip_pbuf_pool_release(ndpip_iface_get_pbuf_pool_rx(iface), &pb, 1);
		}

		for (uint16_t idx = 0; idx < reply_sockets_len; idx++) {
			int r = ndpip_tcp_feed(reply_sockets[idx], NULL, NULL, replies[replies_len]);
			if (r == 1) {
				reply_sockets[idx]->grants -= ndpip_pbuf_length(replies[replies_len]);
				reply_sockets[idx]->grants -= reply_sockets[idx]->grants_overhead;
				// printf("reply: grants=%ld;\n", reply_sockets[idx]->grants);
				replies_len++;
			}

			reply_sockets[idx]->rx_loop_seen = false;
		}

		if (replies_len > 0)
			ndpip_iface_xmit(iface, replies, replies_len, true);

		ndpip_pbuf_pool_release(ndpip_iface_get_pbuf_pool_tx(iface), replies + replies_len, pkt_cnt - replies_len);

		replies_len_a += replies_len;
		pkt_cnt_a += pkt_cnt;
		iter++;

		if (iter >= 50000UL) {
			printf("avg_burst=%lu; avg_replies=%lu;\n", pkt_cnt_a / iter, replies_len_a / iter);
			replies_len_a = 0;
			pkt_cnt_a = 0;
			iter = 0;
		}

		ndpip_thread_yield();
	}

	return 0;
}

static NDPIP_LIST_HEAD(ndpip_timers_head);

void ndpip_timers_add(struct ndpip_timer *timer)
{
        ndpip_list_add(&ndpip_timers_head, (void *) timer);
}

void ndpip_timers_thread(struct ndpip_iface *iface)
{
	while (ndpip_iface_timers_thread_running(iface)) {
		ndpip_list_foreach(struct ndpip_timer, timer, &ndpip_timers_head) {
			if (ndpip_timer_armed(timer) && ndpip_timer_expired(timer)) {
				ndpip_timer_disarm(timer);
				timer->func(timer->argp);
			}
		}

		ndpip_timers_usleep(25000);
	}
}
