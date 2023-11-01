#include "ndpip/util.h"
#include "ndpip/socket.h"
#include "ndpip/tcp.h"
#include "ndpip/udp.h"
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
#include <netinet/udp.h>
#include <netinet/tcp.h>


#ifdef NDPIP_GRANTS_ENABLE
bool ndpip_log_grants = false;
int64_t (*ndpip_log_grants_msg)[5];
size_t ndpip_log_grants_idx = 0;
#endif

static void ndpip_timers_hook(struct ndpip_iface *iface);

int ndpip_rx_thread(void *argp)
{
	struct ndpip_iface *iface = argp;
	uint16_t burst_size = ndpip_iface_get_burst_size(iface);

	uint64_t iter = 0;
	uint64_t pkt_cnt_a = 0;
	uint64_t replies_len_a = 0;

	struct timespec before;
	ndpip_time_now(&before);

	while (ndpip_iface_rx_thread_running(iface)) {
		ndpip_timers_hook(iface);

		if (iter++ >= 100000UL) {
			struct timespec now;
			ndpip_time_now(&now);

                        uint64_t delta = (now.tv_sec - before.tv_sec) * NDPIP_NSEC_IN_SEC + (now.tv_nsec - before.tv_nsec);
			if (delta > NDPIP_NSEC_IN_SEC) {
				if (pkt_cnt_a != 0)
					printf("ndpip_rx_thread: avg_burst=%lf; avg_replies=%lf; pps=%lf;\n", ((double) pkt_cnt_a) / iter, ((double) replies_len_a) / iter, ((double) pkt_cnt_a) * NDPIP_NSEC_IN_SEC / delta);

				replies_len_a = 0;
				pkt_cnt_a = 0;
				before = now;
			}

			iter = 0;
		}

		uint16_t pkt_cnt = burst_size;
		struct ndpip_pbuf *pkts[pkt_cnt];

		uint16_t freed_pkt_cnt = 0;
		struct ndpip_pbuf *freed_pkts[pkt_cnt];

		int r = ndpip_iface_rx_burst(iface, (void *) pkts, &pkt_cnt);

		if ((r < 0) || (pkt_cnt == 0))
			continue;

		struct ndpip_tcp_socket *reply_sockets[pkt_cnt];
		uint16_t reply_sockets_len = 0;

		uint16_t replies_len = 0;
		struct ndpip_pbuf *replies[pkt_cnt * 2];

		size_t tmp_pkt_cnt = pkt_cnt;
		assert(ndpip_pbuf_pool_request(ndpip_iface_get_pbuf_pool_tx(iface), replies, &tmp_pkt_cnt) >= 0);
		assert(tmp_pkt_cnt == pkt_cnt);

		for (uint16_t idx = 0; idx < pkt_cnt; idx++) {
			struct ndpip_pbuf *pb = pkts[idx];
			uint16_t pbuf_len = ndpip_pbuf_length(pb);

			if (pbuf_len < sizeof(struct ethhdr))
				goto free_pkt;

			struct ethhdr *eth = ndpip_pbuf_data(pb);

			uint8_t bcast[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
			if ((memcmp(eth->h_dest, ndpip_iface_get_ethaddr(iface), ETH_ALEN) != 0) &&
				(memcmp(eth->h_dest, bcast, ETH_ALEN) != 0))
				goto free_pkt;

#ifdef NDPIP_GRANTS_ENABLE
			if (ntohs(eth->h_proto) == ETH_P_EQDSCN) {
				struct eqds_cn *cn = ((void *) eth) + sizeof(struct ethhdr);
				//struct in_addr cn_destination = { .s_addr = cn->destination };
				int32_t cn_value1 = ntohl(cn->value1);
				int32_t cn_value2 = ntohl(cn->value2);

				ndpip_socket_foreach(sock) {
					if ((*sock) == NULL)
						continue;

					if ((*sock)->remote.sin_addr.s_addr == cn->destination) {
						if (cn->operation == CN_GRANTS_ADD) {
							(*sock)->grants += cn_value1;
							(*sock)->grants_overcommit = 0;
						}

						if (ndpip_log_grants) {
							ndpip_log_grants_msg[ndpip_log_grants_idx][0] = (*sock)->grants;
							ndpip_log_grants_msg[ndpip_log_grants_idx][1] = cn->operation;
							ndpip_log_grants_msg[ndpip_log_grants_idx][2] = cn->destination;
							ndpip_log_grants_msg[ndpip_log_grants_idx][3] = cn_value1;
							ndpip_log_grants_msg[ndpip_log_grants_idx][4] = cn_value2;

							ndpip_log_grants_idx++;
						}
					}
				}

				goto free_pkt;
			}
#endif

			if (ntohs(eth->h_proto) != ETH_P_IP)
				goto free_pkt;

			assert(ndpip_pbuf_offset(pb, -(int) sizeof(struct ethhdr)) >= 0);

			if (pbuf_len < (sizeof(struct ethhdr) + sizeof(struct iphdr)))
				goto free_pkt;

			struct iphdr *iph = ndpip_pbuf_data(pb);

#ifndef NDPIP_DEBUG_NO_CKSUM
			if (ndpip_iface_has_offload(iface, NDPIP_IFACE_OFFLOAD_RX_IPV4_CSUM)) {
				if (ndpip_pbuf_has_flag(pb, NDPIP_PBUF_F_RX_IP_CSUM_BAD))
					goto free_pkt;

				if (ndpip_pbuf_has_flag(pb, NDPIP_PBUF_F_RX_IP_CSUM_NONE)) {
					if (!ndpip_ipv4_cksum(iph))
						goto free_pkt;
				}

			} else if (ndpip_ipv4_cksum(iph))
				goto free_pkt;
#endif

			if (!((iph->ihl == 5) && (iph->version == 4)))
				goto free_pkt;

			if (iph->daddr != ndpip_iface_get_inaddr(iface)->s_addr)
				goto free_pkt;

			uint8_t protocol = iph->protocol;
			uint16_t iph_hlen = iph->ihl << 2;
			pbuf_len = ntohs(iph->tot_len) - iph_hlen;

			assert(ndpip_pbuf_offset(pb, -(int) iph_hlen) >= 0);
			assert(ndpip_pbuf_resize(pb, pbuf_len) >= 0);

			if (protocol == IPPROTO_TCP) {
				if (pbuf_len < sizeof(struct tcphdr))
					goto free_pkt;

				struct tcphdr *th = ndpip_pbuf_data(pb);
#ifndef NDPIP_DEBUG_NO_CKSUM
				if (ndpip_iface_has_offload(iface, NDPIP_IFACE_OFFLOAD_RX_TCPV4_CSUM)) {
					if (ndpip_pbuf_has_flag(pb, NDPIP_PBUF_F_RX_L4_CSUM_BAD))
						goto free_pkt;

					if (ndpip_pbuf_has_flag(pb, NDPIP_PBUF_F_RX_L4_CSUM_NONE)) {
						if (!ndpip_ipv4_udptcp_cksum(iph, th))
							goto free_pkt;
					}

				} else if (ndpip_ipv4_udptcp_cksum(iph, th))
					goto free_pkt;
#endif

				struct sockaddr_in local = {
					.sin_family = AF_INET,
					.sin_addr.s_addr = iph->daddr,
					.sin_port = th->th_dport
				};

				struct sockaddr_in remote = {
					.sin_family = AF_INET,
					.sin_addr.s_addr = iph->saddr,
					.sin_port = th->th_sport
				};

				struct ndpip_tcp_socket *tcp_sock = (struct ndpip_tcp_socket *) ndpip_socket_get_by_peer(local, remote, IPPROTO_TCP);
				if (tcp_sock == NULL)
					goto free_pkt;

				if (!tcp_sock->rx_loop_seen) {
					reply_sockets[reply_sockets_len++] = tcp_sock;
					tcp_sock->rx_loop_seen = true;
				}

				if (ndpip_tcp_feed(tcp_sock, &remote, pb, pbuf_len) == 1)
					continue;
			}

			if (protocol == IPPROTO_UDP) {
				if (pbuf_len < sizeof(struct udphdr))
					goto free_pkt;

				struct udphdr *uh = ndpip_pbuf_data(pb);

#ifndef NDPIP_DEBUG_NO_CKSUM
				if (ndpip_iface_has_offload(iface, NDPIP_IFACE_OFFLOAD_RX_UDPV4_CSUM)) {
					if (ndpip_pbuf_has_flag(pb, NDPIP_PBUF_F_RX_L4_CSUM_BAD))
						goto free_pkt;

					if (ndpip_pbuf_has_flag(pb, NDPIP_PBUF_F_RX_L4_CSUM_NONE))
						if (!ndpip_ipv4_udptcp_cksum(iph, uh))
							goto free_pkt;

				} else if (ndpip_ipv4_udptcp_cksum(iph, uh))
					goto free_pkt;
#endif

				struct sockaddr_in local = {
					.sin_family = AF_INET,
					.sin_addr.s_addr = iph->daddr,
					.sin_port = uh->uh_dport
				};

				struct sockaddr_in remote = {
					.sin_family = AF_INET,
					.sin_addr.s_addr = iph->saddr,
					.sin_port = uh->uh_sport
				};

				struct ndpip_udp_socket *udp_sock = (struct ndpip_udp_socket *) ndpip_socket_get_by_peer(local, remote, IPPROTO_UDP);
				if (udp_sock == NULL)
					goto free_pkt;

				if (ndpip_udp_feed(udp_sock, &remote, pb) == 2)
					continue;
			}

free_pkt:
			freed_pkts[freed_pkt_cnt++] = pb;
		}

		ndpip_pbuf_pool_release(ndpip_iface_get_pbuf_pool_rx(iface), freed_pkts, freed_pkt_cnt);

		for (uint16_t idx = 0; idx < reply_sockets_len; idx++) {
			struct ndpip_tcp_socket *reply_tcp_socket = reply_sockets[idx];

			int r = ndpip_tcp_flush(reply_tcp_socket, replies[replies_len]);
			if (r == 1) {
				replies_len++;
#ifdef NDPIP_GRANTS_ENABLE
				reply_socket_socket->socket.grants -= ndpip_pbuf_length(reply) + reply_socket->grants_overhead;
				/*
				if (ndpip_log_grants) {
					ndpip_log_grants_idx++;

					ndpip_log_grants_msg[ndpip_log_grants_idx][0] = 1;
					ndpip_log_grants_msg[ndpip_log_grants_idx][1] = reply_socket->grants;
				}
				*/
#endif
			}

			reply_tcp_socket->rx_loop_seen = false;
		}

		if (replies_len > 0)
			ndpip_iface_xmit(iface, replies, replies_len, true);

		ndpip_pbuf_pool_release(ndpip_iface_get_pbuf_pool_tx(iface), replies + replies_len, pkt_cnt - replies_len);

		replies_len_a += replies_len;
		pkt_cnt_a += pkt_cnt;
	}

	return 0;
}

static NDPIP_LIST_HEAD(ndpip_timers_head);

void ndpip_timers_add(struct ndpip_timer *timer)
{
        ndpip_list_add(&ndpip_timers_head, (void *) timer);
}

static void ndpip_timers_hook(struct ndpip_iface *iface)
{
	static int timer = 0;
	if (++timer < 1000)
		return;

	timer = 0;

	ndpip_list_foreach(struct ndpip_timer, timer, &ndpip_timers_head) {
		if (ndpip_timer_armed(timer) && ndpip_timer_expired(timer)) {
			ndpip_timer_disarm(timer);
			timer->func(timer->argp);
		}
	}
}
