#include <time.h>

#include "ndpip/util.h"
#include "ndpip/udp.h"

#include <assert.h>
#include <string.h>

#include <netinet/ip.h>
#include <netinet/udp.h>

#include <sys/epoll.h>


#ifndef NDPIP_DEBUG_NO_TX_HW_CKSUM
static void ndpip_udp_prepare_pbuf(struct ndpip_udp_socket *tcp_sock, struct ndpip_pbuf *pb, struct iphdr *iph, struct udphdr *uh);
#endif

uint32_t ndpip_udp_poll(struct ndpip_udp_socket *udp_sock)
{
	uint32_t mask = EPOLLOUT;
	mask |= ndpip_ring_size(udp_sock->socket.recv_ring) == 0 ? 0 : EPOLLIN;

	return mask;
}

int ndpip_udp_close(struct ndpip_udp_socket *udp_sock)
{
	struct ndpip_socket *sock = &udp_sock->socket;

	uint32_t hash = ndpip_socket_established_hash(&sock->local, &sock->remote);
	ndpip_hashtable_del(ndpip_udp_established_sockets, hash);

	return 0;
}

int ndpip_udp_build_xmit_template(struct ndpip_udp_socket *udp_sock) {
	struct ndpip_socket *sock = &udp_sock->socket;

	struct ethhdr *eth = (void *) udp_sock->xmit_template;

	struct ether_addr *eth_src = ndpip_iface_get_ethaddr(sock->iface);
	struct ether_addr *eth_dst = ndpip_iface_resolve_arp(sock->iface, sock->remote.sin_addr);

	if ((eth_dst == NULL) || (eth_src == NULL))
		return -1;

	memcpy(eth->h_dest, eth_dst, ETH_ALEN);
	memcpy(eth->h_source, eth_src, ETH_ALEN);

	eth->h_proto = htons(ETH_P_IP);

	struct iphdr *iph = ((void *) eth) + sizeof(struct ethhdr);
	*iph = (struct iphdr) {
		.version = 4,
		.ihl = 5,
		.tos = 0,
		.tot_len = 0,
		.id = 0,
		.frag_off = 0,
		.ttl = 32,
		.protocol = IPPROTO_UDP,
		.check = 0,
		.saddr = sock->local.sin_addr.s_addr,
		.daddr = sock->remote.sin_addr.s_addr
	};

	struct udphdr *uh = ((void *) iph) + sizeof(struct iphdr);
	*uh = (struct udphdr) {
		.uh_sport = sock->local.sin_port,
		.uh_dport = sock->remote.sin_port
	};

	return 0;
}

int ndpip_udp_connect(struct ndpip_udp_socket *udp_sock)
{
	if (ndpip_udp_build_xmit_template(udp_sock) < 0) {
		errno = EFAULT;
		return -1;
	}

	struct ndpip_socket *sock = &udp_sock->socket;

	uint32_t hash1 = ndpip_socket_listening_hash(&sock->local);
	ndpip_hashtable_del(ndpip_udp_listening_sockets, hash1);

	uint32_t hash2 = ndpip_socket_established_hash(&sock->local, &sock->remote);
	ndpip_hashtable_put(ndpip_udp_established_sockets, hash2, sock);

	return 0;
}

void ndpip_udp_flush(struct ndpip_udp_socket *udp_sock)
{
	struct ndpip_socket *sock = &udp_sock->socket;

	ndpip_ring_push(sock->recv_ring, sock->recv_tmp, sock->recv_tmp_len);

	udp_sock->socket.feed_tmp_len = 0;
	udp_sock->socket.recv_tmp_len = 0;

	sock->rx_loop_seen = false;
}

void ndpip_udp_feed(struct ndpip_udp_socket *udp_sock, struct sockaddr_in *remote, struct ndpip_pbuf *pb)
{
	struct ndpip_socket *sock = &udp_sock->socket;
	sock->recv_tmp[sock->recv_tmp_len++] = pb;
}

uint16_t ndpip_udp_max_xmit(struct ndpip_udp_socket *udp_sock, struct ndpip_pbuf **pb, uint16_t cnt)
{
	uint16_t burst_size = ndpip_iface_get_burst_size(udp_sock->socket.iface);
	cnt = cnt < burst_size ? cnt : burst_size;

#ifdef NDPIP_GRANTS_ENABLE
	if (sock->grants_overhead < 0)
		return 0;
#endif

#ifdef NDPIP_GRANTS_ENABLE
	int64_t grants_left = sock->grants;

	for (uint16_t idx = 0; idx < cnt; idx++) {
		grants_left -= sock->grants_overhead + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + ndpip_pbuf_metadata(pb[idx])->data_len;

		if (grants_left < 0)
			return idx;
	}
#endif

	return cnt;
}

void ndpip_udp_prepare_send(struct ndpip_udp_socket *udp_sock, struct ndpip_pbuf *pb)
{
	uint16_t data_len = ndpip_pbuf_length(pb);

	assert(ndpip_pbuf_offset(pb, sizeof(udp_sock->xmit_template)) >= 0);
	memcpy(ndpip_pbuf_data(pb), udp_sock->xmit_template, sizeof(udp_sock->xmit_template));

	struct ethhdr *eth = ndpip_pbuf_data(pb);
	struct iphdr *iph = (void *) (eth + 1);
	struct udphdr *uh = (void *) (iph + 1);

	uint16_t tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + data_len;
	iph->tot_len = htons(tot_len);
	uh->uh_ulen = htons(sizeof(struct udphdr) + data_len);

#ifndef NDPIP_DEBUG_NO_TX_HW_CKSUM
	ndpip_udp_prepare_pbuf(udp_sock, pb, iph, uh);
#endif
}

int ndpip_udp_write(struct ndpip_udp_socket *udp_sock, struct ndpip_pbuf **pb, uint16_t cnt)
{
	struct ndpip_socket *sock = &udp_sock->socket;
	ndpip_iface_xmit(sock->iface, pb, cnt, true);
	return 0;
}

int ndpip_udp_send(struct ndpip_udp_socket *udp_sock, struct ndpip_pbuf **pb, uint16_t cnt)
{
	struct ndpip_socket *sock = &udp_sock->socket;

	if (cnt == 0)
		return 0;

	cnt = ndpip_udp_max_xmit(udp_sock, pb, cnt);
	if (cnt == 0)
		return 0;

#ifdef NDPIP_GRANTS_ENABLE
	for (uint16_t idx = 0; idx < cnt; idx++)
		sock->grants -= sock->grants_overhead + ndpip_pbuf_length(pb[idx]);
#endif

	ndpip_iface_xmit(sock->iface, pb, cnt, true);

	//printf("UDP-send: xmit_ring_size=%lu;\n", ndpip_ring_size(sock->xmit_ring));

	return cnt;
}

#ifndef NDPIP_DEBUG_NO_TX_HW_CKSUM
static void ndpip_udp_prepare_pbuf(struct ndpip_udp_socket *udp_sock, struct ndpip_pbuf *pb, struct iphdr *iph, struct udphdr *uh)
{
	struct ndpip_socket *sock = &udp_sock->socket;

	ndpip_pbuf_set_l2_len(pb, sizeof(struct ethhdr));
	ndpip_pbuf_set_l3_len(pb, sizeof(struct iphdr));

	ndpip_pbuf_set_flag(pb, NDPIP_PBUF_F_TX_IPV4, true);

	if (ndpip_iface_has_offload(sock->iface, NDPIP_IFACE_OFFLOAD_TX_IPV4_CSUM))
		ndpip_pbuf_set_flag(pb, NDPIP_PBUF_F_TX_IP_CKSUM, true);
	/*
	else
		iph->check = ndpip_ipv4_cksum(iph);
	*/

	if (ndpip_iface_has_offload(sock->iface, NDPIP_IFACE_OFFLOAD_TX_UDPV4_CSUM))
		ndpip_pbuf_set_flag(pb, NDPIP_PBUF_F_TX_UDP_CKSUM, true);
	/*
	else {
		uh->uh_sum = 0;
		uh->uh_sum = ndpip_ipv4_udptcp_cksum(iph, uh);
	}
	*/
}
#endif

size_t ndpip_udp_can_send(struct ndpip_udp_socket *udp_sock)
{
	uint16_t burst_size = ndpip_iface_get_burst_size(udp_sock->socket.iface);
	struct ndpip_socket *sock = &udp_sock->socket;
	return burst_size * sock->tx_mss;
}
