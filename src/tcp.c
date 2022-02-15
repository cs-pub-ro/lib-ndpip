#include <time.h>

#include "ndpip/util.h"
#include "ndpip/tcp.h"

#include <assert.h>
#include <string.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <dnet/ip.h>


#define NDPIP_TODO_TCP_RETRANSMIT_COUNT 3
#define NDPIP_TODO_TCP_WIN_SIZE 65535
#define NDPIP_TODO_TCP_MSS 1460
#define NDPIP_TODO_TCP_RETRANSMIT_TIMEOUT ((struct timespec) { .tv_sec = 0, .tv_nsec = 25000000 })


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
		.th_win = htons(NDPIP_TODO_TCP_WIN_SIZE),
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
	th_scale->scale = sock->tcp_recv_win_scale;

	th_nop1->kind = 1;

	th->th_off += (sizeof(struct ndpip_tcp_option_mss) + sizeof(struct ndpip_tcp_option_scale) + sizeof(struct ndpip_tcp_option_nop)) >> 2;

	tcpip_checksum(iph);

	return 0;
}

void ndpip_tcp_rto_handler(void *argp) {
	struct ndpip_socket *sock = argp;

	struct ndpip_pbuf *pb;
	size_t cnt = 1;

	struct timespec now;
	ndpip_time_now(&now);

	struct timespec expire = now;

//	printf("TCP-rto: xmit_ring_size=%lu;\n", ndpip_ring_size(sock->xmit_ring));

	if (ndpip_ring_peek(sock->xmit_ring, &cnt, &pb) < 0)
		goto ret_no_rto;

	if (cnt != 1)
		goto ret_no_rto;

	struct timespec exp1;
	struct ndpip_pbuf_meta *pm = ndpip_pbuf_metadata(pb);
	ndpip_tsc2time(pm->xmit_tsc, &exp1);
	ndpip_timespec_add(&exp1, NDPIP_TODO_TCP_RETRANSMIT_TIMEOUT);

	if ((&now)->tv_sec < (&exp1)->tv_sec)
		goto ret_no_rto;

	if (((&now)->tv_sec == (&exp1)->tv_sec) &&
		((&now)->tv_nsec < (&exp1)->tv_nsec))
		goto ret_no_rto;

	sock->tcp_rto = true;

	ndpip_iface_xmit(sock->socket_iface, &pb, 1, false);
	goto ret_rto;

ret_no_rto:
	sock->tcp_rto = false;

ret_rto:
	ndpip_timespec_add(&expire, NDPIP_TODO_TCP_RETRANSMIT_TIMEOUT);
	ndpip_timer_arm(sock->socket_timer_rto, &expire);
}

void ndpip_tcp_parse_opts(struct ndpip_socket *sock, struct tcphdr *th, uint16_t th_hlen)
{
	for (size_t idx = sizeof(struct tcphdr); idx < th_hlen;) {
		struct ndpip_tcp_option *th_opt = ((void *) th) + idx;
		if (th_opt->kind == TCPOPT_WINDOW) {
			struct ndpip_tcp_option_scale *th_scale = (void *) th_opt;
			sock->tcp_send_win_scale = th_scale->scale;
		}

		if (th_opt->kind == TCPOPT_NOP)
			idx += 1;
		else
			idx += th_opt->len == 0 ? 1 : th_opt->len;
	}
}

uint16_t ndpip_tcp_max_xmit(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t cnt)
{
	/*
	static size_t xmit_ring_size_sum = 0;
	static size_t xmit_ring_size_iter = 0;

	xmit_ring_size_sum += ndpip_ring_size(sock->xmit_ring);
	xmit_ring_size_iter++;

	if (xmit_ring_size_iter > 1000000000UL) {
		xmit_ring_size_sum = 0;
		xmit_ring_size_iter = 0;
		printf("TCP-max_xmit: xmit_ring_size_sum=%lu;\n", xmit_ring_size_sum);
	}

        if (ndpip_ring_size(sock->xmit_ring) != 0)
                return 0;
	*/
	
	if (sock->paused || sock->tcp_rto)
		return 0;

	uint16_t burst_size = ndpip_iface_get_burst_size(sock->socket_iface);
	cnt = cnt < burst_size ? cnt : burst_size;

	uint32_t max_data = sock->tcp_max_seq - sock->tcp_seq;
	uint32_t seq = 0;
	for (uint16_t idx = 0; idx < cnt; idx++) {
		seq += ndpip_pbuf_length(pb[idx]);

		if (seq > max_data)
			return idx;
	}

	return cnt;
}

int ndpip_tcp_send_data(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t cnt)
{
	if (cnt == 0)
		return 0;

	cnt = ndpip_tcp_max_xmit(sock, pb, cnt);

	if (cnt == 0)
		return 0;

	uint64_t tsc_now = ndpip_tsc();

	for (uint16_t idx = 0; idx < cnt; idx++) {
		uint16_t data_len = ndpip_pbuf_length(pb[idx]);

		ndpip_pbuf_offset(pb[idx], sizeof(sock->xmit_template));
		memcpy(ndpip_pbuf_data(pb[idx]), sock->xmit_template, sizeof(sock->xmit_template));

		struct iphdr *iph = ndpip_pbuf_data(pb[idx]) + sizeof(struct ethhdr);
		struct tcphdr *th = (void *) (iph + 1);

		iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);

		th->th_seq = htonl(sock->tcp_seq);
		th->th_ack = htonl(sock->tcp_ack);
		th->th_flags = TH_ACK;

//		printf("tcp_seq=%u;\n", sock->tcp_seq);
		sock->tcp_seq += data_len;

		tcpip_checksum(iph);

		struct ndpip_pbuf_meta *pm = ndpip_pbuf_metadata(pb[idx]);
		pm->xmit_tsc = tsc_now;
	}

	ndpip_ring_push(sock->xmit_ring, pb, cnt);
	ndpip_iface_xmit(sock->socket_iface, pb, cnt, false);

//	printf("TCP-send: xmit_ring_size=%lu;\n", ndpip_ring_size(sock->xmit_ring));

	return cnt;
}

int ndpip_tcp_send(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t cnt)
{
	uint64_t tsc_now = ndpip_tsc();

	for (uint16_t idx = 0; idx < cnt; idx++) {
		struct ndpip_pbuf_meta *pm = ndpip_pbuf_metadata(pb[idx]);
		pm->xmit_tsc = tsc_now;
	}

	ndpip_ring_push(sock->xmit_ring, pb, cnt);
	ndpip_iface_xmit(sock->socket_iface, pb, cnt, false);

	return 0;
}

void ndpip_tcp_free_acked(struct ndpip_socket *sock)
{
	static uint64_t xmit_ring_size_acc = 0;
	static uint64_t xmit_ring_size_acc_iter = 0;
	static uint64_t xmit_ring_size_acc_before = 0;

	size_t xmit_ring_size = ndpip_ring_size(sock->xmit_ring);

	xmit_ring_size_acc += xmit_ring_size;
	xmit_ring_size_acc_iter++;
	if ((rdtsc() - xmit_ring_size_acc_before) > 1000000000UL) {
		printf("xmit_ring_size_acc=%lu;\n", xmit_ring_size_acc / xmit_ring_size_acc_iter);

		xmit_ring_size_acc = 0;
		xmit_ring_size_acc_iter = 0;
		xmit_ring_size_acc_before = rdtsc();
	}

	if (xmit_ring_size == 0)
		return;

	struct ndpip_pbuf **free_pbs = malloc(xmit_ring_size * sizeof(struct ndpip_pbuf *));
	struct ndpip_pbuf *pb;
	size_t cnt = 1;

	ndpip_ring_peek(sock->xmit_ring, &cnt, &pb);
	struct tcphdr *th = ndpip_pbuf_data(pb) + sizeof(struct ethhdr) + sizeof(struct iphdr);

	ssize_t max_data = sock->tcp_last_ack - ntohl(th->th_seq);

	size_t idx;
	for (idx = 0; idx < xmit_ring_size; idx++) {
		struct ndpip_pbuf *pb;
		size_t cnt = 1;

		ndpip_ring_peek(sock->xmit_ring, &cnt, &pb);
		struct iphdr *iph = ndpip_pbuf_data(pb) + sizeof(struct ethhdr);
		struct tcphdr *th = (void *)(iph + 1);

		uint16_t data_len = ntohs(iph->tot_len) - (iph->ihl << 2) - (th->th_off << 2);
		max_data -= data_len;

		if (max_data >= 0) {
			free_pbs[idx] = pb;
			ndpip_ring_flush(sock->xmit_ring, 1);
		} else
			break;
	}

	ndpip_sock_free(sock, free_pbs, idx, false);
	free(free_pbs);

//	printf("TCP-free_acked: xmit_ring_size=%lu;\n", ndpip_ring_size(sock->xmit_ring));
}

void ndpip_tcp_close(struct ndpip_socket *sock)
{
	struct sockaddr_in key[2] = { sock->local, sock->remote };

	if ((sock->state != CLOSED) && (sock->state != LISTENING))
		ndpip_hashtable_del(ndpip_established_sockets, key, sizeof(key));

	if (sock->state == LISTENING)
		ndpip_hashtable_del(ndpip_listening_sockets, key, sizeof(key));

	sock->state = CLOSED;
}

int ndpip_tcp_feed(struct ndpip_socket *sock, struct sockaddr_in *remote, struct ndpip_pbuf *pb, struct ndpip_pbuf *rpb)
{
	if (pb == NULL) {
		if ((sock->state == CONNECTED) && (sock->tcp_rsp_ack)) {
			ndpip_tcp_build_meta(sock, TH_ACK, rpb);
			sock->tcp_rsp_ack = false;
			return 1;
		}

		return 0;
	}

	struct tcphdr *th = ndpip_pbuf_data(pb);
	uint16_t th_len = ndpip_pbuf_length(pb);
	uint8_t th_flags = th->th_flags & ~TH_PUSH;

	uint32_t tcp_seq = ntohl(th->th_seq);
	uint32_t tcp_ack = ntohl(th->th_ack);

	uint16_t th_hlen = th->th_off << 2;
	uint16_t data_len = th_len - th_hlen;

	sock->tcp_retransmission = false;

	if (sock->state != LISTENING) {
		if (th_flags & TH_ACK) {
			sock->tcp_last_ack = tcp_ack;
			ndpip_tcp_free_acked(sock);
			sock->tcp_max_seq = tcp_ack + (ntohs(th->th_win) << sock->tcp_send_win_scale);

			if (tcp_ack != sock->tcp_last_ack) {
				struct timespec expire;
				ndpip_time_now(&expire);
				ndpip_timespec_add(&expire, NDPIP_TODO_TCP_RETRANSMIT_TIMEOUT);
				ndpip_timer_arm(sock->socket_timer_rto, &expire);
			}
		}

		if (sock->state != CONNECTING) {
			if (tcp_seq < sock->tcp_good_ack)
				sock->tcp_retransmission = true;

			if (tcp_seq > sock->tcp_good_ack)
				sock->tcp_recovery = true;

			if (tcp_seq == sock->tcp_good_ack)
				sock->tcp_recovery = false;
		}
	}

	if (sock->tcp_recovery)
		return 0;

	uint32_t ack_inc;

	if (data_len == 0) {
		if (th_flags != TH_ACK)
			ack_inc = 1;
		else
			ack_inc = 0;
	} else
		ack_inc = data_len;

	sock->tcp_ack = tcp_seq + ack_inc;

	if (!sock->tcp_retransmission && !sock->tcp_recovery)
		sock->tcp_good_ack = sock->tcp_ack;

	if (sock->state == LISTENING) {
		if (th_flags != TH_SYN)
			goto err;

		if (data_len != 0)
			goto err;

		struct ndpip_socket *asock = ndpip_socket_new(remote->sin_family, SOCK_NDPIP, IPPROTO_TCP);
		if (asock == NULL)
			goto err;

		asock->local = sock->local;
		asock->remote = *remote;
		asock->socket_iface = ndpip_iface_get_by_inaddr(asock->local.sin_addr);
		asock->tcp_recv_win_scale = sock->tcp_recv_win_scale;
		asock->state = ACCEPTING;

		ndpip_tcp_parse_opts(asock, th, th_hlen);

	        if (ndpip_tcp_build_xmit_template(asock) < 0)
			goto err;

		asock->tcp_ack = sock->tcp_ack;
		asock->tcp_good_ack = asock->tcp_ack;
		ndpip_tcp_build_syn(asock, true, rpb);
		asock->tcp_seq++;

        	struct sockaddr_in key[2] = { asock->local, asock->remote };
	        ndpip_hashtable_put(ndpip_established_sockets, key, sizeof(key), asock);

		ndpip_list_add(&sock->accept_queue, &asock->accept_queue);

		return 1;
	}

	if (sock->state == CONNECTING) {
		if (th_flags != (TH_SYN | TH_ACK))
			goto err;

		if (data_len != 0)
			goto err;

		ndpip_tcp_parse_opts(sock, th, th_hlen);

		sock->state = CONNECTED;
		sock->tcp_rsp_ack = true;

		return 0;
	}

	if (sock->state == ACCEPTING) {
		if (th_flags != TH_ACK)
			goto err;

		sock->state = CONNECTED;
		return 0;
	}

	if (sock->state == CONNECTED) {
		if (th_flags == (TH_FIN | TH_ACK)) {
			ndpip_tcp_build_meta(sock, TH_ACK, rpb);
			ndpip_tcp_close(sock);

			return 1;
		}

		if (th_flags == TH_FIN) {
			sock->state = CLOSING;

			ndpip_tcp_build_meta(sock, TH_FIN | TH_ACK, rpb);
			return 1;
		}

		if (data_len == 0) {
			if (th_flags == TH_ACK)
				return 0;
			else
				goto err;
		}

		sock->tcp_rsp_ack = true;

		if (sock->tcp_retransmission)
			return 0;
		else {
			ndpip_pbuf_offset(pb, -th_hlen);
			ndpip_ring_push(sock->recv_ring, &pb, 1);

			return 2;
		}
	}

	if (sock->state == CLOSING) {
		if (th_flags == (TH_FIN | TH_ACK)) {
			ndpip_tcp_build_meta(sock, TH_ACK, rpb);
			ndpip_tcp_close(sock);

			return 1;
		}
	}

err:
	if (sock->state != LISTENING)
		ndpip_tcp_close(sock);

	ndpip_tcp_build_meta(sock, TH_RST, rpb);
	return 1;
}
