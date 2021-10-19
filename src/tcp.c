#include <time.h>

#include "ndpip/util.h"
#include "ndpip/tcp.h"

#include <string.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <dnet/ip.h>


#define NDPIP_TODO_TCP_RETRANSMIT_COUNT 3
#define NDPIP_TODO_TCP_WIN_SIZE 65535
#define NDPIP_TODO_TCP_WIN_SCALE 5
#define NDPIP_TODO_TCP_MSS 1400
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

int ndpip_tcp_build_meta(struct ndpip_socket *sock, uint8_t flags, struct ndpip_pbuf *pb)
{
	ndpip_pbuf_resize(pb, sizeof(sock->xmit_template));

	struct ethhdr *eth = ndpip_pbuf_data(pb);
	struct iphdr *iph = ((void *) eth) + sizeof(struct ethhdr);
	struct tcphdr *th = ((void *) iph) + sizeof(struct iphdr);

	memcpy((void *) eth, sock->xmit_template, sizeof(sock->xmit_template));

	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));

	th->th_flags = flags;
	th->th_seq = htonl(sock->tcp_seq);
	th->th_ack = htonl(sock->tcp_ack);
	th->th_win = htons(NDPIP_TODO_TCP_WIN_SIZE);

	tcpip_checksum(iph);

	return 0;
}

int ndpip_tcp_build_syn(struct ndpip_socket *sock, bool ack, struct ndpip_pbuf *pb)
{
	ndpip_pbuf_resize(pb, sizeof(struct ethhdr) + sizeof(struct iphdr) +
			sizeof(struct tcphdr) + sizeof(struct ndpip_tcp_option_mss) +
			sizeof(struct ndpip_tcp_option_scale) + sizeof(struct ndpip_tcp_option_nop));

	struct ethhdr *eth = ndpip_pbuf_data(pb);
	struct iphdr *iph = ((void *) eth) + sizeof(struct ethhdr);
	struct tcphdr *th = ((void *) iph) + sizeof(struct iphdr);

	struct ndpip_tcp_option_mss *th_mss = (void *) (th + 1);
	struct ndpip_tcp_option_scale *th_scale = (void *) (th_mss + 1);
	struct ndpip_tcp_option_nop *th_nop1 = (void *) (th_scale + 1);

	memcpy((void *) eth, sock->xmit_template, sizeof(sock->xmit_template));

	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) +
		sizeof(struct ndpip_tcp_option_mss) + sizeof(struct ndpip_tcp_option_scale) +
		sizeof(struct ndpip_tcp_option_nop));

	th->th_flags = TH_SYN | (ack ? TH_ACK : 0);
	th->th_seq = htonl(sock->tcp_seq);
	th->th_ack = htonl(sock->tcp_ack);
	th->th_win = htons(NDPIP_TODO_TCP_WIN_SIZE);

	th_mss->opt.kind = TCPOPT_MAXSEG;
	th_mss->opt.len = TCPOLEN_MAXSEG;
	th_mss->mss = htons(NDPIP_TODO_TCP_MSS);
	
	th_scale->opt.kind = TCPOPT_WINDOW;
	th_scale->opt.len = TCPOLEN_WINDOW;
	th_scale->scale = NDPIP_TODO_TCP_WIN_SCALE;

	th_nop1->kind = 1;

	th->th_off += (sizeof(struct ndpip_tcp_option_mss) + sizeof(struct ndpip_tcp_option_scale) + sizeof(struct ndpip_tcp_option_nop)) >> 2;

	tcpip_checksum(iph);

	return 0;
}

void ndpip_tcp_rto_handler(void *argp) {
	return;
	struct ndpip_socket *sock = argp;

	struct ndpip_pbuf_train pbt;
	size_t pbt_count = 1;

	if (ndpip_ring_pop(sock->xmit_ring, &pbt_count, &pbt) < 0)
		return;

	if ((&pbt)->train_pbuf_count != 1)
		return;

	ndpip_tcp_send(sock, &((&pbt)->train_pbufs)[0], 1);
}

uint16_t ndpip_tcp_max_xmit(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t cnt)
{
	(void) sock;
	(void) pb;

	return cnt;
}

int ndpip_tcp_send(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t cnt)
{
	/*
	struct ndpip_pbuf_train pbt = {
		.train_pbufs = pb,
		.train_pbuf_count = cnt
	};

	ndpip_ring_push(sock->xmit_ring, &pbt);
	*/

	uint16_t cnt2 = ndpip_tcp_max_xmit(sock, pb, cnt);
	if (cnt2 == 0)
		return 0;

	/*
	if (cnt2 == cnt) {
		sock->xmit_ring_unsent_off++;
		sock->xmit_ring_unsent_train_off = 0;
	} else
		sock->xmit_ring_unsent_train_off = cnt2;
	*/

	// ndpip_iface_xmit(sock->socket_iface, pb, cnt2);

	/*
	struct timespec expire;
	clock_gettime(CLOCK_MONOTONIC, &expire);

	ndpip_timespec_add(&expire, NDPIP_TODO_TCP_RETRANSMIT_TIMEOUT);

	if (!ndpip_timer_armed(sock->socket_timer_rto) && (sock->tcp_seq < sock->tcp_last_ack))
		ndpip_timer_arm(sock->socket_timer_rto, &expire);
	*/

	return 0;
}

struct tcphdr *ndpip_tcp_recv_one(struct ndpip_socket *sock)
{
	(void) sock;

	return NULL;
}

int ndpip_tcp_feed(struct ndpip_socket *sock, struct sockaddr_in *remote, struct ndpip_pbuf *pb, struct ndpip_pbuf *rpb)
{
	struct tcphdr *th = ndpip_pbuf_data(pb);
	uint16_t th_len = ndpip_pbuf_length(pb);
	uint8_t th_flags = th->th_flags & ~TH_PUSH;

	uint32_t tcp_seq = ntohl(th->th_seq);
	uint32_t tcp_ack = ntohl(th->th_ack);

	uint16_t th_hlen = th->th_off << 2;
	uint16_t data_len = th_len - th_hlen;

	if ((sock->state != LISTENING) && (th_flags & TH_ACK)) {
		if ((tcp_ack > (sock->tcp_seq + 1)) || (tcp_ack < sock->tcp_last_ack))
			goto err;

		if (tcp_seq != sock->tcp_ack) {
			printf("TCPERR: %u != %u\n", tcp_seq, sock->tcp_ack);
			goto err;
		}

		sock->tcp_last_ack = tcp_ack;
		if (sock->tcp_last_ack == (sock->tcp_seq + 1))
			ndpip_timer_disarm(sock->socket_timer_rto);
	}

	uint32_t ack_inc;

	if (data_len == 0) {
		if (th_flags != TH_ACK)
			ack_inc = 1;
		else
			ack_inc = 0;
	} else
		ack_inc = data_len;

	sock->tcp_ack = tcp_seq + ack_inc;

	if (sock->state == LISTENING) {
		if (th_flags != TH_SYN)
			goto err;

		struct ndpip_socket *asock = ndpip_socket_new(remote->sin_family, SOCK_NDPIP, IPPROTO_TCP);
		if (asock == NULL)
			goto err;

		asock->local = sock->local;
		asock->remote = *remote;
		asock->socket_iface = ndpip_iface_get_by_inaddr(asock->local.sin_addr);
		asock->state = ACCEPTING;

		ndpip_list_add(&sock->accept_queue, &asock->accept_queue);

	        if (ndpip_tcp_build_xmit_template(asock) < 0)
			goto err;

		asock->tcp_ack = tcp_seq + 1;
		ndpip_tcp_build_syn(asock, true, rpb);
		asock->tcp_seq++;
		return 1;
	}

	if (sock->state == CONNECTING) {
		if (th_flags != (TH_SYN | TH_ACK))
			goto err;

		sock->state = CONNECTED;

		ndpip_tcp_build_meta(sock, TH_ACK, rpb);
		sock->tcp_seq++;
		return 1;
	}

	if (sock->state == ACCEPTING) {
		if (th_flags != TH_ACK)
			goto err;

		sock->state = CONNECTED;
		return 0;
	}

	if (sock->state == CONNECTED) {
		if (th_flags == (TH_FIN | TH_ACK)) {
			sock->state = CLOSED;

			ndpip_tcp_build_meta(sock, TH_ACK, rpb);
			return 1;
		}

		if (th_flags == TH_FIN) {
			sock->state = CLOSING;

			ndpip_tcp_build_meta(sock, TH_FIN | TH_ACK, rpb);
			return 1;
		}

		if (data_len == 0) {
			if (!(th_flags & TH_ACK))
				goto err;
			else
				return 0;
		}

		ndpip_pbuf_offset(pb, -th_hlen);
		//ndpip_ring_push(sock->recv_ring, &pb);

		ndpip_tcp_build_meta(sock, TH_ACK, rpb);
		return 1;
	}

	if (sock->state == CLOSING) {
		if (th_flags == (TH_FIN | TH_ACK)) {
			sock->state = CLOSED;

			ndpip_tcp_build_meta(sock, TH_ACK, rpb);
			return 1;
		}
	}

err:
	sock->state = CLOSED;
	ndpip_tcp_build_meta(sock, TH_RST, rpb);
	return 1;
}
