#include <time.h>

#include "ndpip/util.h"
#include "ndpip/tcp.h"

#include <string.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>


#define NDPIP_TODO_TCP_RETRANSMIT_COUNT 3
#define NDPIP_TODO_TCP_RETRANSMIT_TIMEOUT ((struct timespec) { .tv_sec = 0, .tv_nsec = 250000000 })


int ndpip_tcp_build_xmit_template(struct ndpip_socket *sock)
{
	struct ethhdr *eth = (void *) sock->xmit_template;

	struct ether_addr *eth_src = ndpip_iface_get_ethaddr(sock->socket_iface);
	struct ether_addr *eth_dst = ndpip_iface_resolve_arp(sock->socket_iface, sock->remote.sin_addr);

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
		.protocol = IPPROTO_TCP,
		.check = 0,
		.saddr = sock->local.sin_addr.s_addr,
		.daddr = sock->remote.sin_addr.s_addr
	};

	struct tcphdr *th = ((void *) iph) + sizeof(struct iphdr);
	*th = (struct tcphdr) {
		.th_sport = htons(sock->local.sin_port),
		.th_dport = htons(sock->remote.sin_port),
		.th_seq = 0,
		.th_ack = 0,
		.th_x2 = 0,
		.th_off = sizeof(struct tcphdr) / 4,
		.th_flags = 0,
		.th_win = 0,
		.th_sum = 0,
		.th_urp = 0
	};

	return 0;
}

int ndpip_tcp_send_meta(struct ndpip_socket *sock, uint8_t flags)
{
	uint16_t cnt = 1;
	struct ndpip_pbuf **syn = malloc(sizeof(struct ndpip_pbuf *) * 1);

	struct ndpip_pbuf_pool *pool = ndpip_iface_get_pbuf_pool_tx(sock->socket_iface);

	if (ndpip_pbuf_pool_request(pool, syn, &cnt) < 0)
		return -1;

	if (cnt != 1)
		return -1;

	ndpip_pbuf_resize(*syn, sizeof(sock->xmit_template));

	struct ethhdr *eth = ndpip_pbuf_data(*syn);
	struct iphdr *iph = ((void *) eth) + sizeof(struct ethhdr);
	struct tcphdr *th = ((void *) iph) + sizeof(struct iphdr);

	memcpy((void *) eth, sock->xmit_template, sizeof(sock->xmit_template));

	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
	th->th_flags = flags;
	th->th_seq = htonl(sock->tcp_seq);
	th->th_ack = htonl(sock->tcp_ack);

	if (ndpip_tcp_send(sock, syn, 1) < 0)
		return -1;

	return 0;
}

void ndpip_tcp_rto_handler(void *argp) {
	struct ndpip_socket *sock = argp;

	struct ndpip_pbuf **pb;
	size_t cnt;

	if (ndpip_pbuf_ring_peek(sock->xmit_ring, 0, &pb, &cnt) < 0)
		return;

	if (cnt < 1)
		return;

	ndpip_tcp_send(sock, pb, 1);
}

uint16_t ndpip_tcp_max_xmit(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t cnt)
{
	(void) sock;
	(void) pb;

	return cnt;
}

int ndpip_tcp_send(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t cnt)
{
	ndpip_pbuf_ring_append(sock->xmit_ring, pb, cnt);

	uint16_t cnt2 = ndpip_tcp_max_xmit(sock, pb, cnt);
	if (cnt2 == 0)
		return 0;

	if (cnt2 == cnt) {
		sock->xmit_ring_unsent_off++;
		sock->xmit_ring_unsent_train_off = 0;
	} else
		sock->xmit_ring_unsent_train_off = cnt2;

	ndpip_iface_xmit(sock->socket_iface, pb, cnt2);

	struct timespec expire;
	clock_gettime(CLOCK_MONOTONIC, &expire);

	ndpip_timespec_add(&expire, NDPIP_TODO_TCP_RETRANSMIT_TIMEOUT);

	if (!ndpip_timer_armed(sock->socket_timer_rto))
		ndpip_timer_arm(sock->socket_timer_rto, &expire);

	return 0;
}

struct tcphdr *ndpip_tcp_recv_one(struct ndpip_socket *sock)
{
	(void) sock;

	return NULL;
}

int ndpip_tcp_feed(struct ndpip_socket *sock, struct sockaddr_in *remote, struct tcphdr *th, uint16_t th_len)
{
	if (sock->state == LISTENING) {
		if (th->th_flags == TH_SYN) {
			struct ndpip_socket *asock = ndpip_socket_new(remote->sin_family, SOCK_NDPIP, IPPROTO_TCP);
			if (asock == NULL)
				return -1;

			asock->local = sock->local;
			asock->remote = *remote;
			asock->tcp_ack = ntohl(th->th_seq) + 1;
			asock->socket_iface = ndpip_iface_get_by_inaddr(asock->local.sin_addr);
			asock->state = ACCEPTING;

		        if (ndpip_tcp_build_xmit_template(asock) < 0)
		                return -1;

			ndpip_tcp_send_meta(asock, TH_SYN | TH_ACK);
		} else
			return -1;
	}

	if (sock->state == CONNECTING) {
		if (th->th_flags == (TH_SYN | TH_ACK)) {
			sock->state = CONNECTED;

			ndpip_tcp_send_meta(sock, TH_ACK);
		} else
			return -1;
	}

	if (sock->state == ACCEPTING) {
		if (th->th_flags == TH_ACK) {
			sock->state = CONNECTED;
		} else
			return -1;
	}

	return 0;
}
