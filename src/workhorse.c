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
	uint64_t iter2 = 0;
	uint64_t pkt_cnt_a = 0;
	uint64_t replies_len_a = 0;

	struct timespec before;
	ndpip_time_now(&before);

	char iface_ethaddr[ETH_ALEN];
	memcpy(iface_ethaddr, ndpip_iface_get_ethaddr(iface), ETH_ALEN);
	struct ndpip_pbuf_pool *rpl_pool = ndpip_iface_get_pbuf_pool_rpl(iface);

	uint64_t start = 0, burst_delay_a = 0;

	while (ndpip_iface_rx_thread_running(iface)) {
		ndpip_timers_hook(iface);

		uint16_t pkt_cnt = burst_size;
		struct ndpip_pbuf *pkts[pkt_cnt];

		uint16_t freed_pkt_cnt = 0;
		struct ndpip_pbuf *freed_pkts[pkt_cnt];

		int r = ndpip_iface_rx_burst(iface, (void *) pkts, &pkt_cnt);

		if (start != 0)
			burst_delay_a += ndpip_tsc() - start;

		start = ndpip_tsc();

		if (iter++ >= 10000UL) {
			struct timespec now;
			ndpip_time_now(&now);

                        uint64_t delta = (now.tv_sec - before.tv_sec) * NDPIP_NSEC_IN_SEC + (now.tv_nsec - before.tv_nsec);
			if (delta > NDPIP_NSEC_IN_SEC) {
				if (pkt_cnt_a != 0)
					printf("ndpip_rx_thread: avg_burst=%lf; avg_replies=%lf; pps=%lf; burst_tsc=%lf;\n",
							((double) pkt_cnt_a) / iter2,
							((double) replies_len_a) / iter2,
							((double) pkt_cnt_a) * NDPIP_NSEC_IN_SEC / delta,
							((double) burst_delay_a) / iter2);

				replies_len_a = 0;
				pkt_cnt_a = 0;
				burst_delay_a = 0;
				before = now;

				iter2 = 0;
			}

			iter = 0;
		}

		iter2++;

		struct ndpip_tcp_socket *tcp_sockets[pkt_cnt];
		struct ndpip_udp_socket *udp_sockets[pkt_cnt];
		if ((r < 0) || (pkt_cnt == 0))
			continue;

		uint16_t tcp_sockets_len = 0;
		uint16_t udp_sockets_len = 0;

		uint16_t replies_len = 0;
		struct ndpip_pbuf *replies[pkt_cnt * 2];

		for (uint16_t idx = 0; idx < pkt_cnt; idx++) {
			struct ndpip_pbuf *pb = pkts[idx];
			uint16_t pbuf_len = ndpip_pbuf_length(pb);

			if (pbuf_len < sizeof(struct ethhdr))
				goto free_pkt;

			struct ethhdr *eth = ndpip_pbuf_data(pb);

			uint8_t bcast[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
			if ((memcmp(eth->h_dest, iface_ethaddr, ETH_ALEN) != 0) &&
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

			if (pbuf_len < (sizeof(struct ethhdr) + sizeof(struct iphdr)))
				goto free_pkt;

			struct iphdr *iph = (void *) (eth + 1);

#ifndef NDPIP_DEBUG_NO_RX_CKSUM
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

			if (protocol == IPPROTO_TCP) {
				if (pbuf_len < sizeof(struct tcphdr))
					goto free_pkt;

				struct tcphdr *th = ((void *) iph) + iph_hlen;
#ifndef NDPIP_DEBUG_NO_RX_CKSUM
				if (ndpip_iface_has_offload(iface, NDPIP_IFACE_OFFLOAD_RX_TCPV4_CSUM)) {
					if (ndpip_pbuf_has_flag(pb, NDPIP_PBUF_F_RX_L4_CSUM_BAD))
						goto free_pkt;

					if (ndpip_pbuf_has_flag(pb, NDPIP_PBUF_F_RX_L4_CSUM_NONE)) {
						if (ndpip_ipv4_udptcp_cksum(iph, th) != 0)
							goto free_pkt;
					}

				} else if (ndpip_ipv4_udptcp_cksum(iph, th) != 0)
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

				struct ndpip_socket *sock = ndpip_socket_get_by_peer(&local, &remote, IPPROTO_TCP);
				struct ndpip_tcp_socket *tcp_sock = (struct ndpip_tcp_socket *) sock;
				if (tcp_sock == NULL)
					goto free_pkt;

				uint16_t th_hlen = th->th_off << 2;
				uint16_t data_len = pbuf_len - th_hlen;

				if (ndpip_pbuf_offset(pb, -(sizeof(struct ethhdr) + iph_hlen + th_hlen)) < 0)
					goto free_pkt;

				if (ndpip_pbuf_resize(pb, data_len) < 0)
					goto free_pkt;

				if (!sock->rx_loop_seen) {
					tcp_sockets[tcp_sockets_len++] = tcp_sock;
					sock->rx_loop_seen = true;
				}

				struct ndpip_pbuf_meta *pm = ndpip_pbuf_metadata(pb);
				pm->remote = remote;
				pm->data_len = data_len;
				pm->th = th;
				pm->th_hlen = th_hlen;

				sock->feed_tmp[sock->feed_tmp_len++] = pb;

				continue;
			}

			if (protocol == IPPROTO_UDP) {
				if (pbuf_len < sizeof(struct udphdr))
					goto free_pkt;

				struct udphdr *uh = ((void *) iph) + iph_hlen;
#ifndef NDPIP_DEBUG_NO_RX_CKSUM
				if (ndpip_iface_has_offload(iface, NDPIP_IFACE_OFFLOAD_RX_UDPV4_CSUM)) {
					if (ndpip_pbuf_has_flag(pb, NDPIP_PBUF_F_RX_L4_CSUM_BAD))
						goto free_pkt;

					if (ndpip_pbuf_has_flag(pb, NDPIP_PBUF_F_RX_L4_CSUM_NONE))
						if (ndpip_ipv4_udptcp_cksum(iph, uh) != 0xffff)
							goto free_pkt;

				} else if (ndpip_ipv4_udptcp_cksum(iph, uh) != 0xffff)
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

				struct ndpip_socket *sock = ndpip_socket_get_by_peer(&local, &remote, IPPROTO_UDP);
				struct ndpip_udp_socket *udp_sock = (struct ndpip_udp_socket *) sock;
				if (udp_sock == NULL)
					goto free_pkt;

				if (ndpip_pbuf_offset(pb, -(sizeof(struct ethhdr) + iph_hlen + sizeof(struct udphdr))) < 0)
					goto free_pkt;

				if (ndpip_pbuf_resize(pb, ntohs(uh->len) - sizeof(struct udphdr)) < 0)
					goto free_pkt;

				if (!sock->rx_loop_seen) {
					udp_sockets[udp_sockets_len++] = udp_sock;
					sock->rx_loop_seen = true;
				}

				struct ndpip_pbuf_meta *pm = ndpip_pbuf_metadata(pb);
				pm->remote = remote;

				sock->feed_tmp[sock->feed_tmp_len++] = pb;

				continue;
			}

free_pkt:
			freed_pkts[freed_pkt_cnt++] = pb;
		}

		assert(ndpip_pbuf_pool_request(rpl_pool, replies, tcp_sockets_len) >= 0);

		for (uint16_t idx = 0; idx < tcp_sockets_len; idx++) {
			struct ndpip_tcp_socket *tcp_sock = tcp_sockets[idx];
			struct ndpip_socket *sock = (struct ndpip_socket *) tcp_sock;

			ndpip_mutex_lock(&sock->lock);
			uint16_t sock_feed_tmp_len = sock->feed_tmp_len;
			struct ndpip_pbuf **sock_feed_tmp = sock->feed_tmp;

			for (uint16_t idx = 0; idx < sock_feed_tmp_len; idx++) {
				struct ndpip_pbuf *pb = sock_feed_tmp[idx];
				struct ndpip_pbuf_meta *pm = ndpip_pbuf_metadata(pb);

				if (ndpip_tcp_feed(tcp_sock, &pm->remote, pb, pm->th, pm->th_hlen, pm->data_len) != 1)
					freed_pkts[freed_pkt_cnt++] = pb;
			}

			assert(ndpip_ring_push(sock->recv_ring, sock->recv_tmp, sock->recv_tmp_len) >= 0);

			int r = ndpip_tcp_flush(tcp_sock, replies[replies_len]);
			ndpip_mutex_unlock(&sock->lock);

			if (r == 1) {
				replies_len++;
#ifdef NDPIP_GRANTS_ENABLE
				sock->grants -= ndpip_pbuf_length(reply) + sock->grants_overhead;
				/*
				if (ndpip_log_grants) {
					ndpip_log_grants_idx++;

					ndpip_log_grants_msg[ndpip_log_grants_idx][0] = 1;
					ndpip_log_grants_msg[ndpip_log_grants_idx][1] = reply_socket->grants;
				}
				*/
#endif
			}

			sock->rx_loop_seen = false;
		}

		if (replies_len > 0)
			ndpip_iface_xmit(iface, replies, replies_len, true);

		ndpip_pbuf_release(replies + replies_len, tcp_sockets_len - replies_len);

		for (uint16_t idx = 0; idx < udp_sockets_len; idx++) {
			struct ndpip_udp_socket *udp_sock = udp_sockets[idx];
			struct ndpip_socket *sock = (struct ndpip_socket *) udp_sock;

			uint16_t sock_feed_tmp_len = sock->feed_tmp_len;
			struct ndpip_pbuf **sock_feed_tmp = sock->feed_tmp;

			for (uint16_t idx = 0; idx < sock_feed_tmp_len; idx++) {
				struct ndpip_pbuf *pb = sock_feed_tmp[idx];
				struct ndpip_pbuf_meta *pm = ndpip_pbuf_metadata(pb);

				ndpip_udp_feed(udp_sock, &pm->remote, pb);
			}

			assert(ndpip_ring_push(sock->recv_ring, sock->recv_tmp, sock->recv_tmp_len) >= 0);
			ndpip_udp_flush(udp_sock);
			sock->rx_loop_seen = false;
		}

		ndpip_pbuf_release(freed_pkts, freed_pkt_cnt);

		replies_len_a += replies_len;
		pkt_cnt_a += pkt_cnt;
	}

	return 0;
}

static struct ndpip_list_head ndpip_timers_list;
static struct ndpip_mutex ndpip_timers_list_lock;
static struct ndpip_timer *ndpip_last_timer = (void *) &ndpip_timers_list;

void ndpip_workhorse_init()
{
	ndpip_list_init(&ndpip_timers_list);
	ndpip_mutex_init(&ndpip_timers_list_lock);
}

void ndpip_timers_add(struct ndpip_timer *timer)
{
	ndpip_mutex_lock(&ndpip_timers_list_lock);
	ndpip_list_add(&ndpip_timers_list, (void *) timer);
	ndpip_last_timer = (void *) &ndpip_timers_list;
	ndpip_mutex_unlock(&ndpip_timers_list_lock);
}

void ndpip_timers_del(struct ndpip_timer *timer)
{
	ndpip_mutex_lock(&ndpip_timers_list_lock);
	ndpip_list_del((void *) timer);
	ndpip_last_timer = (void *) &ndpip_timers_list;
	ndpip_mutex_unlock(&ndpip_timers_list_lock);
}

static void ndpip_timers_hook(struct ndpip_iface *iface)
{
	static int timer_s = 0;
	if (++timer_s < 1000)
		return;

	timer_s = 0;

	ndpip_mutex_lock(&ndpip_timers_list_lock);

	ndpip_last_timer = (void *) ndpip_last_timer->list.next;
	if (((void *) ndpip_last_timer) == &ndpip_timers_list)
		goto ret;

	if (ndpip_timer_armed(ndpip_last_timer) && ndpip_timer_expired(ndpip_last_timer)) {
		ndpip_timer_disarm(ndpip_last_timer);
		ndpip_last_timer->func(ndpip_last_timer->argp);
	}

ret:
	ndpip_mutex_unlock(&ndpip_timers_list_lock);
}
