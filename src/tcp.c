#include <time.h>

#include "ndpip/util.h"
#include "ndpip/tcp.h"

#include <assert.h>
#include <string.h>


#define NDPIP_TODO_TCP_RETRANSMIT_COUNT 3
#define NDPIP_TODO_TCP_WIN_SIZE 65535
#define NDPIP_TODO_TCP_MSS 1460
#define NDPIP_TODO_TCP_RETRANSMIT_TIMEOUT ((struct timespec) { .tv_sec = 0, .tv_nsec = 25000000 })


extern bool ndpip_log_grants;

int64_t (*ndpip_log_grants_tcp)[3];
size_t ndpip_log_grants_tcp_idx;

char *ndpip_log_grants_tcp_logtags[3] = {
	"tcp_rto\0",
	"tcp_send_data\0"
	"tcp_send\0",
};

static void ndpip_tcp_prepare_pbuf(struct ndpip_tcp_socket *tcp_sock, struct ndpip_pbuf *pb, struct iphdr *iph, struct tcphdr *th);
static int ndpip_tcp_fin(struct ndpip_tcp_socket *tcp_sock);
static void ndpip_tcp_close_established(struct ndpip_tcp_socket *tcp_sock);
static void ndpip_tcp_close_listening(struct ndpip_tcp_socket *tcp_sock);
static int ndpip_tcp_send_one(struct ndpip_tcp_socket *tcp_sock, struct ndpip_pbuf *pb);
static void ndpip_tcp_free_acked(struct ndpip_tcp_socket *tcp_sock, uint32_t free_len);
static int ndpip_tcp_build_xmit_template(struct ndpip_tcp_socket *tcp_sock);
static int ndpip_tcp_build_meta(struct ndpip_tcp_socket *tcp_sock, uint8_t flags, struct ndpip_pbuf *pb);
static int ndpip_tcp_build_syn(struct ndpip_tcp_socket *tcp_sock, bool ack, struct ndpip_pbuf *pb);
static void ndpip_tcp_parse_opts(struct ndpip_tcp_socket *sock, struct tcphdr *th, uint16_t th_hlen);

static void ndpip_tcp_prepare_pbuf(struct ndpip_tcp_socket *tcp_sock, struct ndpip_pbuf *pb, struct iphdr *iph, struct tcphdr *th)
{
#ifndef NDPIP_DEBUG_NO_CKSUM
	struct ndpip_socket *sock = &tcp_sock->socket;

	ndpip_pbuf_set_l2_len(pb, sizeof(struct ethhdr));
	ndpip_pbuf_set_l3_len(pb, sizeof(struct iphdr));

	ndpip_pbuf_set_flag(pb, NDPIP_PBUF_F_TX_IPV4, true);

	if (ndpip_iface_has_offload(sock->iface, NDPIP_IFACE_OFFLOAD_TX_IPV4_CSUM))
		ndpip_pbuf_set_flag(pb, NDPIP_PBUF_F_TX_IP_CKSUM, true);
	else
		iph->check = ndpip_ipv4_cksum(iph);

	if (ndpip_iface_has_offload(sock->iface, NDPIP_IFACE_OFFLOAD_TX_TCPV4_CSUM))
		ndpip_pbuf_set_flag(pb, NDPIP_PBUF_F_TX_TCP_CKSUM, true);
	else {
		th->th_sum = 0;
		th->th_sum = ndpip_ipv4_udptcp_cksum(iph, th);
	}
#endif
}

struct ndpip_tcp_socket *ndpip_tcp_accept(struct ndpip_tcp_socket *tcp_sock)
{
	if (tcp_sock->state != LISTENING) {
		errno = EINVAL;
		return NULL;
	}

	if (tcp_sock->accept_queue.next == &tcp_sock->accept_queue) {
		errno = EAGAIN;
		return NULL;
	}

	struct ndpip_tcp_socket *asock = ((void *) tcp_sock->accept_queue.next) - offsetof(struct ndpip_tcp_socket, accept_queue);
	ndpip_list_del(tcp_sock->accept_queue.next);

	while (asock->state != CONNECTED)
		ndpip_usleep(1);

	return asock;
}

static int ndpip_tcp_fin(struct ndpip_tcp_socket *tcp_sock)
{
	struct ndpip_pbuf *pb;

	if (ndpip_sock_alloc(&tcp_sock->socket, &pb, 1, false) < 0) {
		errno = EFAULT;
		return -1;
	}

	if (ndpip_tcp_build_meta(tcp_sock, TH_FIN, pb) < 0) {
		errno = EFAULT;
		return -1;
	}

	ndpip_tcp_send_one(tcp_sock, pb);
	return 0;
}

int ndpip_tcp_connect(struct ndpip_tcp_socket *tcp_sock)
{
	if (tcp_sock->state != BOUND) {
		errno = EADDRINUSE;
		return -1;
	}

	struct ndpip_socket *sock = &tcp_sock->socket;

	if (ndpip_tcp_build_xmit_template(tcp_sock) < 0) {
		errno = EFAULT;
		return -1;
	}

	struct ndpip_pbuf *pb;
	
	if (ndpip_sock_alloc((struct ndpip_socket *) tcp_sock, &pb, 1, false) < 0) {
		errno = EFAULT;
		return -1;
	}

	if (ndpip_tcp_build_syn(tcp_sock, false, pb) < 0) {
		tcp_sock->state = CLOSED;
		errno = EFAULT;
		return -1;
	}

	tcp_sock->tcp_last_ack = tcp_sock->tcp_seq - 1;

	struct ndpip_established_key key = {
		.saddr = sock->remote.sin_addr.s_addr,
		.daddr = sock->local.sin_addr.s_addr,
		.sport = sock->remote.sin_port,
		.dport = sock->local.sin_port,
		.proto = IPPROTO_TCP
	};

	ndpip_hashtable_put(ndpip_established_sockets, &key, sizeof(key), tcp_sock);

	tcp_sock->state = CONNECTING;
	ndpip_tcp_send_one(tcp_sock, pb);

	while (tcp_sock->state == CONNECTING)
		ndpip_usleep(1);

	if (tcp_sock->state != CONNECTED) {
		errno = ECONNREFUSED;
		return -1;
	}

	return 0;
}

static int ndpip_tcp_build_xmit_template(struct ndpip_tcp_socket *tcp_sock)
{
	struct ndpip_socket *sock = &tcp_sock->socket;

	struct ethhdr *eth = (void *) tcp_sock->xmit_template;

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
		.protocol = IPPROTO_TCP,
		.check = 0,
		.saddr = sock->local.sin_addr.s_addr,
		.daddr = sock->remote.sin_addr.s_addr
	};

	struct tcphdr *th = ((void *) iph) + sizeof(struct iphdr);
	*th = (struct tcphdr) {
		.th_sport = sock->local.sin_port,
		.th_dport = sock->remote.sin_port,
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

static int ndpip_tcp_build_meta(struct ndpip_tcp_socket *tcp_sock, uint8_t flags, struct ndpip_pbuf *pb)
{
	ndpip_pbuf_resize(pb, sizeof(tcp_sock->xmit_template));

	struct ethhdr *eth = ndpip_pbuf_data(pb);
	struct iphdr *iph = ((void *) eth) + sizeof(struct ethhdr);
	struct tcphdr *th = ((void *) iph) + sizeof(struct iphdr);

	memcpy((void *) eth, tcp_sock->xmit_template, sizeof(tcp_sock->xmit_template));

	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));

	th->th_flags = flags;
	th->th_seq = htonl(tcp_sock->tcp_seq);
	th->th_ack = htonl(tcp_sock->tcp_ack);

	ndpip_tcp_prepare_pbuf(tcp_sock, pb, iph, th);

	if (flags != TH_ACK)
		tcp_sock->tcp_seq++;

	ndpip_pbuf_metadata(pb)->data_len = 1;

	return 0;
}

static int ndpip_tcp_build_syn(struct ndpip_tcp_socket *tcp_sock, bool ack, struct ndpip_pbuf *pb)
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

	memcpy((void *) eth, tcp_sock->xmit_template, sizeof(tcp_sock->xmit_template));

	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) +
		sizeof(struct ndpip_tcp_option_mss) + sizeof(struct ndpip_tcp_option_scale) +
		sizeof(struct ndpip_tcp_option_nop));

	th->th_flags = TH_SYN | (ack ? TH_ACK : 0);
	th->th_seq = htonl(tcp_sock->tcp_seq);
	th->th_ack = htonl(tcp_sock->tcp_ack);

	th_mss->opt.kind = TCPOPT_MAXSEG;
	th_mss->opt.len = TCPOLEN_MAXSEG;
	th_mss->mss = htons(NDPIP_TODO_TCP_MSS);
	
	th_scale->opt.kind = TCPOPT_WINDOW;
	th_scale->opt.len = TCPOLEN_WINDOW;
	th_scale->scale = tcp_sock->tcp_recv_win_scale;

	th_nop1->kind = 1;

	th->th_off += (sizeof(struct ndpip_tcp_option_mss) + sizeof(struct ndpip_tcp_option_scale) + sizeof(struct ndpip_tcp_option_nop)) >> 2;

	ndpip_tcp_prepare_pbuf(tcp_sock, pb, iph, th);

	tcp_sock->tcp_seq++;

	return 0;
}

void ndpip_tcp_rto_handler(void *argp) {
	struct ndpip_tcp_socket *tcp_sock = argp;
	struct ndpip_socket *sock = &tcp_sock->socket;

	struct ndpip_pbuf *pb;
	struct timespec expire;
	size_t cnt = 1;

	if (ndpip_ring_peek(sock->xmit_ring, &cnt, &pb) < 0)
		goto ret_no_rto;

	if (cnt != 1)
		goto ret_no_rto;

	//printf("TCP-rto: xmit_ring_size=%lu;\n", ndpip_ring_size(sock->xmit_ring));

	tcp_sock->tcp_rto = true;

	sock->grants -= ndpip_pbuf_length(pb) + sock->grants_overhead;
	if (ndpip_log_grants) {
		ndpip_log_grants_tcp[ndpip_log_grants_tcp_idx][0] = sock->grants;
		ndpip_log_grants_tcp[ndpip_log_grants_tcp_idx][1] = ndpip_pbuf_length(pb) + sock->grants_overhead;
		ndpip_log_grants_tcp[ndpip_log_grants_tcp_idx][2] = 0;

		ndpip_log_grants_tcp_idx++;
	}

	ndpip_iface_xmit(sock->iface, &pb, 1, false);
	goto ret_rto;

ret_no_rto:
	tcp_sock->tcp_rto = false;

ret_rto:
	ndpip_time_now(&expire);
	ndpip_timespec_add(&expire, NDPIP_TODO_TCP_RETRANSMIT_TIMEOUT);
	ndpip_timer_arm(tcp_sock->timer_rto, &expire);
}

static void ndpip_tcp_parse_opts(struct ndpip_tcp_socket *sock, struct tcphdr *th, uint16_t th_hlen)
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

static void ndpip_tcp_close_established(struct ndpip_tcp_socket *tcp_sock)
{
	struct ndpip_established_key key = {
		.saddr = tcp_sock->socket.remote.sin_addr.s_addr,
		.daddr = tcp_sock->socket.local.sin_addr.s_addr,
		.sport = tcp_sock->socket.remote.sin_port,
		.dport = tcp_sock->socket.local.sin_port,
		.proto = IPPROTO_TCP
	};

	ndpip_hashtable_del(ndpip_established_sockets, &key, sizeof(key));
}

static void ndpip_tcp_close_listening(struct ndpip_tcp_socket *tcp_sock)
{
	struct ndpip_listening_key key = {
		.daddr = tcp_sock->socket.local.sin_addr.s_addr,
		.dport = tcp_sock->socket.local.sin_port,
		.proto = IPPROTO_TCP
	};

	ndpip_hashtable_del(ndpip_listening_sockets, &key, sizeof(key));
}

int ndpip_tcp_close(struct ndpip_tcp_socket *tcp_sock)
{
	int ret = 0;

	printf("tcp_sock->state=%d;\n", tcp_sock->state);

	switch (tcp_sock->state) {
		case CONNECTING:
		case TIME_WAIT:
			ndpip_tcp_close_established(tcp_sock);

		case NEW:
		case BOUND:
			tcp_sock->state = CLOSED;
			break;

		case ACCEPTING:
		case CONNECTED:
			printf("%d -> FIN_WAIT_1\n", tcp_sock->state);
			tcp_sock->state = FIN_WAIT_1;
			ret = ndpip_tcp_fin(tcp_sock);

			while (tcp_sock->state != TIME_WAIT)
				ndpip_usleep(1);

			tcp_sock->state = CLOSED;

			break;

		case CLOSE_WAIT:
			tcp_sock->state = LAST_ACK;
			ret = ndpip_tcp_fin(tcp_sock);

			while (tcp_sock->state != CLOSED)
				ndpip_usleep(1);

			break;

		case LISTENING:
			tcp_sock->state = CLOSED;
			ndpip_tcp_close_listening(tcp_sock);
			break;

		case LAST_ACK:
		case FIN_WAIT_1:
		case FIN_WAIT_2:
		case CLOSING:
		case CLOSED:
		default:
	}

	if (ret < 0)
		return -1;

	return 0;
}

void ndpip_tcp_prepare_send(struct ndpip_tcp_socket *tcp_sock, struct ndpip_pbuf *pb)
{
	struct ndpip_socket *sock = &tcp_sock->socket;

	uint16_t data_len = ndpip_pbuf_length(pb);

	ndpip_pbuf_offset(pb, sizeof(tcp_sock->xmit_template));
	memcpy(ndpip_pbuf_data(pb), tcp_sock->xmit_template, sizeof(tcp_sock->xmit_template));

	struct iphdr *iph = ndpip_pbuf_data(pb) + sizeof(struct ethhdr);
	struct tcphdr *th = (void *) (iph + 1);

	uint16_t tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len;
	iph->tot_len = htons(tot_len);

	th->th_seq = htonl(tcp_sock->tcp_seq);
	th->th_ack = htonl(tcp_sock->tcp_ack);
	th->th_flags = TH_ACK;

	ndpip_tcp_prepare_pbuf(tcp_sock, pb, iph, th);

	tcp_sock->tcp_seq += data_len;

	sock->grants -= sock->grants_overhead + ndpip_pbuf_length(pb);

	ndpip_pbuf_metadata(pb)->data_len = data_len;

	if (ndpip_log_grants) {
		ndpip_log_grants_tcp[ndpip_log_grants_tcp_idx][0] = sock->grants;
		ndpip_log_grants_tcp[ndpip_log_grants_tcp_idx][1] = ndpip_pbuf_length(pb) + sock->grants_overhead;
		ndpip_log_grants_tcp[ndpip_log_grants_tcp_idx][2] = 1;

		ndpip_log_grants_tcp_idx++;
	}
}

int ndpip_tcp_send(struct ndpip_tcp_socket *tcp_sock, struct ndpip_pbuf **pb, uint16_t cnt)
{
	if (cnt == 0)
		return 0;

	struct ndpip_socket *sock = &tcp_sock->socket;

	/*
	if (sock->grants_overhead < 0)
		return 0;
	*/

	/*
	{
		static int64_t grants_acc_before = 0;
		static int64_t grants_acc_iter = 0;
		static int64_t grants_acc = 0;

		grants_acc += sock->grants;
		grants_acc_iter++;

		if ((rdtsc() - grants_acc_before) > 1000000000UL) {
			printf("grants=%ld;\n", grants_acc / grants_acc_iter);

			grants_acc = 0;
			grants_acc_iter = 0;
			grants_acc_before = rdtsc();
		}
	}
	*/

	if (tcp_sock->state != CONNECTED) {
		errno = EINVAL;
		return -1;
	}

	if (tcp_sock->tcp_rto)
		return 0;

	int64_t data_left = (uint32_t) (tcp_sock->tcp_max_seq - tcp_sock->tcp_seq);
	if ((sock->grants == 0) || (data_left == 0))
		return 0;

	uint16_t burst_size = ndpip_iface_get_burst_size(sock->iface);
	cnt = cnt < burst_size ? cnt : burst_size;

	if (!ndpip_timer_armed(tcp_sock->timer_rto)) {
		struct timespec expire;
		ndpip_time_now(&expire);
		ndpip_timespec_add(&expire, NDPIP_TODO_TCP_RETRANSMIT_TIMEOUT);
		ndpip_timer_arm(tcp_sock->timer_rto, &expire);
	}

	uint16_t idx;
	for (idx = 0; (idx < cnt) && (data_left > 0) && (sock->grants > 0); idx++) {
		int64_t data_left_tmp = data_left - ndpip_pbuf_length(pb[idx]);
		int64_t grants_left_tmp = sock->grants - (
				sock->grants_overhead + sizeof(struct ethhdr) +
				sizeof(struct iphdr) + sizeof(struct tcphdr) +
				ndpip_pbuf_length(pb[idx]));

		if ((grants_left_tmp < 0) || (data_left_tmp < 0))
			break;

		ndpip_tcp_prepare_send(tcp_sock, pb[idx]);
		data_left = data_left_tmp;
	}

	struct ndpip_pbuf *split_pb = NULL;
	int64_t grants_left_tmp = sock->grants - (
			sock->grants_overhead + sizeof(struct ethhdr) +
			sizeof(struct iphdr) + sizeof(struct tcphdr));

	if ((idx != cnt) && (data_left != 0) && (grants_left_tmp != 0)) {
		int64_t seg_len = data_left < grants_left_tmp ? data_left : grants_left_tmp;

		split_pb = ndpip_pbuf_copy(pb[idx], ndpip_iface_get_pbuf_pool_tx(sock->iface), 0, seg_len);
		ndpip_tcp_prepare_send(tcp_sock, split_pb);
		ndpip_pbuf_offset(pb[idx], -seg_len);

		cnt = idx + 1;

		struct ndpip_pbuf **pb2 = malloc(sizeof(struct ndpip_bpuf *) * cnt);
		memcpy(pb2, pb, sizeof(struct ndpip_pbuf *) * cnt);
		pb = pb2;
		pb[idx] = split_pb;
	}

	ndpip_ring_push(sock->xmit_ring, pb, cnt);
	ndpip_iface_xmit(sock->iface, pb, cnt, false);

	//printf("TCP-send: xmit_ring_size=%lu;\n", ndpip_ring_size(sock->xmit_ring));

	return idx;
}

static int ndpip_tcp_send_one(struct ndpip_tcp_socket *tcp_sock, struct ndpip_pbuf *pb)
{
	struct ndpip_socket *sock = &tcp_sock->socket;

	if (!ndpip_timer_armed(tcp_sock->timer_rto)) {
		struct timespec expire;
		ndpip_time_now(&expire);
		ndpip_timespec_add(&expire, NDPIP_TODO_TCP_RETRANSMIT_TIMEOUT);
		ndpip_timer_arm(tcp_sock->timer_rto, &expire);
	}

	sock->grants -= ndpip_pbuf_length(pb) + sock->grants_overhead;

	if (ndpip_log_grants) {
		ndpip_log_grants_tcp[ndpip_log_grants_tcp_idx][0] = sock->grants;
		ndpip_log_grants_tcp[ndpip_log_grants_tcp_idx][1] = ndpip_pbuf_length(pb) + sock->grants_overhead;
		ndpip_log_grants_tcp[ndpip_log_grants_tcp_idx][2] = 2;

		ndpip_log_grants_tcp_idx++;
	}

	ndpip_ring_push(sock->xmit_ring, &pb, 1);
	ndpip_iface_xmit(sock->iface, &pb, 1, false);

	return 0;
}

static void ndpip_tcp_free_acked(struct ndpip_tcp_socket *tcp_sock, uint32_t free_len)
{
	struct ndpip_socket *sock = &tcp_sock->socket;

	static uint64_t xmit_ring_size_acc = 0;
	static uint64_t xmit_ring_size_acc_iter = 0;
	static uint64_t xmit_ring_size_acc_before = 0;

	size_t xmit_ring_size = ndpip_ring_size(sock->xmit_ring);

	xmit_ring_size_acc += xmit_ring_size;
	xmit_ring_size_acc_iter++;
	if ((rdtsc() - xmit_ring_size_acc_before) > 1000000000UL) {
		//printf("xmit_ring_size_acc=%lu;\n", xmit_ring_size_acc / xmit_ring_size_acc_iter);

		xmit_ring_size_acc = 0;
		xmit_ring_size_acc_iter = 0;
		xmit_ring_size_acc_before = rdtsc();
	}

	if (xmit_ring_size == 0)
		return;

	struct ndpip_pbuf **free_pbs = malloc(xmit_ring_size * sizeof(struct ndpip_pbuf *));

	size_t idx, freed_len;
	for (idx = 0, freed_len = 0; idx < xmit_ring_size; idx++) {
		struct ndpip_pbuf *pb;
		size_t cnt = 1;

		ndpip_ring_peek(sock->xmit_ring, &cnt, &pb);
		if ((freed_len + ndpip_pbuf_metadata(pb)->data_len) <= free_len) {
			freed_len += ndpip_pbuf_metadata(pb)->data_len;
			free_pbs[idx] = pb;
			ndpip_ring_flush(sock->xmit_ring, 1);
		} else
			break;
	}

	ndpip_sock_free(sock, free_pbs, idx, false);
	free(free_pbs);
}

int ndpip_tcp_feed(struct ndpip_tcp_socket *tcp_sock, struct sockaddr_in *remote, struct ndpip_pbuf *pb, struct ndpip_pbuf *rpb)
{
	//printf("TCP-feed\n");
	struct ndpip_socket *sock = &tcp_sock->socket;

	if (pb == NULL) {
		if ((tcp_sock->state == CONNECTED) && tcp_sock->tcp_rsp_ack) {
			ndpip_tcp_build_meta(tcp_sock, TH_ACK, rpb);
			tcp_sock->tcp_rsp_ack = false;
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

	if (tcp_sock->state != LISTENING) {
		if (tcp_sock->state != CONNECTING) {
			// Out of order or unseen packet
			if (tcp_seq != tcp_sock->tcp_ack) {
				tcp_sock->tcp_rsp_ack = true;
				return 0;
			}
		}

		if (th_flags & TH_ACK) {
			// Back ACK
			if (
				((tcp_sock->tcp_last_ack <= tcp_sock->tcp_seq) && ((tcp_ack < tcp_sock->tcp_last_ack) || (tcp_ack > tcp_sock->tcp_seq))) ||
				((tcp_sock->tcp_last_ack > tcp_sock->tcp_seq) && ((tcp_ack > tcp_sock->tcp_last_ack) && (tcp_ack < tcp_sock->tcp_seq)))
			   )
				return 0;

			// All data ACKed
			if (tcp_ack == tcp_sock->tcp_seq) {
				ndpip_timer_disarm(tcp_sock->timer_rto);
				tcp_sock->tcp_rto = false;
			} else {
				struct timespec expire;
				ndpip_time_now(&expire);
				ndpip_timespec_add(&expire, NDPIP_TODO_TCP_RETRANSMIT_TIMEOUT);
				ndpip_timer_arm(tcp_sock->timer_rto, &expire);
			}

			ndpip_tcp_free_acked(tcp_sock, tcp_ack - tcp_sock->tcp_last_ack);
			tcp_sock->tcp_last_ack = tcp_ack;

			tcp_sock->tcp_max_seq = tcp_ack + (ntohs(th->th_win) << tcp_sock->tcp_send_win_scale);
		}
	}

	uint32_t ack_inc;

	if (data_len == 0) {
		if (th_flags != TH_ACK)
			ack_inc = 1;
		else
			ack_inc = 0;
	} else
		ack_inc = data_len;

	tcp_sock->tcp_ack = tcp_seq + ack_inc;

	if (tcp_sock->state == LISTENING) {
		if (th_flags != TH_SYN)
			goto err_l;

		if (data_len != 0)
			goto err_l;

		struct ndpip_socket *asock = ndpip_socket_new(remote->sin_family, SOCK_NDPIP, IPPROTO_TCP);
		if (asock == NULL)
			goto err_l;

		struct ndpip_tcp_socket *tcp_asock = (struct ndpip_tcp_socket *) asock;

		asock->local = sock->local;
		asock->remote = *remote;
		asock->iface = ndpip_iface_get_by_inaddr(asock->local.sin_addr);
		tcp_asock->tcp_recv_win_scale = tcp_sock->tcp_recv_win_scale;
		tcp_asock->state = ACCEPTING;

		ndpip_tcp_parse_opts(tcp_asock, th, th_hlen);

		if (ndpip_tcp_build_xmit_template(tcp_asock) < 0) {
			free(asock);
			goto err_l;
		}

		tcp_asock->tcp_ack = tcp_sock->tcp_ack;

		struct ndpip_established_key key = {
			.saddr = asock->remote.sin_addr.s_addr,
			.daddr = asock->local.sin_addr.s_addr,
			.sport = asock->remote.sin_port,
			.dport = asock->local.sin_port,
			.proto = IPPROTO_TCP
		};

		ndpip_hashtable_put(ndpip_established_sockets, &key, sizeof(key), asock);

		ndpip_list_add(&tcp_sock->accept_queue, &tcp_asock->accept_queue);

		struct ndpip_pbuf *pb;
		if (ndpip_sock_alloc((struct ndpip_socket *) tcp_asock, &pb, 1, false) < 0) {
			tcp_sock = tcp_asock;
			goto err;
		}

		ndpip_tcp_build_syn(tcp_asock, true, pb);
		ndpip_tcp_send_one(tcp_asock, pb);

		return 0;
	}

	if (tcp_sock->state == CONNECTING) {
		if (th_flags != (TH_SYN | TH_ACK))
			goto err;

		if (data_len != 0)
			goto err;

		ndpip_tcp_parse_opts(tcp_sock, th, th_hlen);

		ndpip_tcp_build_meta(tcp_sock, TH_ACK, rpb);
		tcp_sock->tcp_rsp_ack = false;
		tcp_sock->state = CONNECTED;

		return 1;
	}

	if (tcp_sock->state == ACCEPTING) {
		if (th_flags != TH_ACK)
			goto err;

		tcp_sock->state = CONNECTED;
		return 0;
	}

	if (tcp_sock->state == CONNECTED) {
		if ((th_flags == TH_FIN) || (th_flags == (TH_FIN | TH_ACK))) {
			printf("CONNECTED -> CLOSE_WAIT\n");
			tcp_sock->state = CLOSE_WAIT;
			tcp_sock->tcp_rsp_ack = true;

			return 0;
		}

		if (data_len == 0) {
			if (th_flags != TH_ACK)
				goto err;

			return 0;
		}

		tcp_sock->tcp_rsp_ack = true;

		ndpip_pbuf_offset(pb, -th_hlen);
		ndpip_ring_push(sock->recv_ring, &pb, 1);

		return 2;
	}

	if (tcp_sock->state == CLOSE_WAIT) {
		if (data_len != 0)
			goto err;

		if (th_flags != TH_ACK)
			goto err;

		return 0;
	}

	if (tcp_sock->state == LAST_ACK) {
		if (data_len != 0)
			goto err;

		if (th_flags != TH_ACK)
			goto err;

		tcp_sock->state = CLOSED;
		ndpip_tcp_close_established(tcp_sock);
		return 0;
	}

	if (tcp_sock->state == FIN_WAIT_1) {
		if (data_len != 0)
			goto err;

		if (th_flags == TH_ACK) {
			if (tcp_ack != tcp_sock->tcp_seq) {
				tcp_sock->tcp_rsp_ack = true;
				return 0;
			}

			tcp_sock->state = FIN_WAIT_2;
			return 0;
		} else if (th_flags == (TH_FIN | TH_ACK)) {
			tcp_sock->tcp_rsp_ack = true;
			tcp_sock->state = TIME_WAIT;
			return 0;
		} else if (th_flags == TH_FIN) {
			tcp_sock->tcp_rsp_ack = true;
			tcp_sock->state = CLOSING;
			return 0;
		} else
			goto err;
	}

	if (tcp_sock->state == FIN_WAIT_2) {
		if (data_len != 0)
			goto err;

		if (th_flags != TH_FIN)
			goto err;

		tcp_sock->tcp_rsp_ack = true;
		tcp_sock->state = TIME_WAIT;
		return 0;
	}

	if (tcp_sock->state == CLOSING) {
		if (data_len != 0)
			goto err;

		if (th_flags != TH_ACK)
			goto err;

		tcp_sock->state = TIME_WAIT;
		return 0;
	}

err:
	tcp_sock->state = CLOSED;
	ndpip_tcp_close_established(tcp_sock);

err_l:
	ndpip_tcp_build_meta(tcp_sock, TH_RST, rpb);
	return 1;
}
