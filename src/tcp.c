#include "ndpip/util.h"
#include "ndpip/tcp.h"

#include <assert.h>
#include <string.h>
#include <time.h>


#define NDPIP_TODO_TCP_RETRANSMIT_COUNT 3
#define NDPIP_TODO_TCP_WIN_SIZE ((1 << 16) - 1)
#define NDPIP_TODO_TCP_RETRANSMIT_TIMEOUT ((struct timespec) { .tv_sec = 0, .tv_nsec = 250000000L })


#ifdef NDPIP_GRANTS_ENABLE
extern bool ndpip_log_grants;

int64_t (*ndpip_log_grants_tcp)[3];
size_t ndpip_log_grants_tcp_idx;

char *ndpip_log_grants_tcp_logtags[3] = {
	"tcp_rto\0",
	"tcp_send_data\0"
	"tcp_send\0",
};
#endif

#ifndef NDPIP_DEBUG_NO_CKSUM
static void ndpip_tcp_prepare_pbuf(struct ndpip_tcp_socket *tcp_sock, struct ndpip_pbuf *pb, struct iphdr *iph, struct tcphdr *th);
#endif
static int ndpip_tcp_fin(struct ndpip_tcp_socket *tcp_sock);
static void ndpip_tcp_close_established(struct ndpip_tcp_socket *tcp_sock);
static void ndpip_tcp_close_listening(struct ndpip_tcp_socket *tcp_sock);
static int ndpip_tcp_send_one(struct ndpip_tcp_socket *tcp_sock, struct ndpip_pbuf *pb);
static int ndpip_tcp_build_xmit_template(struct ndpip_tcp_socket *tcp_sock);
static int ndpip_tcp_build_meta(struct ndpip_tcp_socket *tcp_sock, uint8_t th_flags, struct ndpip_pbuf *pb);
static void ndpip_tcp_parse_opts(struct ndpip_tcp_socket *sock, struct tcphdr *th, uint16_t th_hlen);
static void ndpip_tcp_prepare_send(struct ndpip_tcp_socket *tcp_sock, struct ndpip_pbuf *pb, uint16_t data_len, uint32_t tcp_seq);

#ifndef NDPIP_DEBUG_NO_CKSUM
static void ndpip_tcp_prepare_pbuf(struct ndpip_tcp_socket *tcp_sock, struct ndpip_pbuf *pb, struct iphdr *iph, struct tcphdr *th)
{
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
}
#endif

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

	if (ndpip_sock_alloc(&tcp_sock->socket, &pb, 1, false) < 0)
		return -1;

	if (ndpip_tcp_build_meta(tcp_sock, TH_FIN, pb) < 0)
		return -1;

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

	tcp_sock->tcp_last_ack = tcp_sock->tcp_seq;

	if (ndpip_tcp_build_meta(tcp_sock, TH_SYN, pb) < 0) {
		tcp_sock->state = CLOSED;
		errno = EFAULT;
		return -1;
	}

	uint64_t hash = ndpip_socket_established_hash(sock->local, sock->remote);
	ndpip_hashtable_put(ndpip_tcp_established_sockets, hash, sock);

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

static int ndpip_tcp_build_meta(struct ndpip_tcp_socket *tcp_sock, uint8_t th_flags, struct ndpip_pbuf *pb)
{
	struct ndpip_socket *sock = &tcp_sock->socket;

	if (th_flags & TH_SYN) {
		assert(ndpip_pbuf_resize(pb, sizeof(struct ethhdr) + sizeof(struct iphdr) +
			sizeof(struct tcphdr) + sizeof(struct ndpip_tcp_option_mss) +
			sizeof(struct ndpip_tcp_option_nop) + sizeof(struct ndpip_tcp_option_scale)) >= 0);
	} else
		assert(ndpip_pbuf_resize(pb, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)) >= 0);

	struct ethhdr *eth = ndpip_pbuf_data(pb);
	memcpy((void *) eth, tcp_sock->xmit_template, sizeof(tcp_sock->xmit_template));

	struct iphdr *iph = ((void *) eth) + sizeof(struct ethhdr);
	if (th_flags & TH_SYN) {
		iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) +
			sizeof(struct ndpip_tcp_option_mss) + sizeof(struct ndpip_tcp_option_nop) +
			sizeof(struct ndpip_tcp_option_scale));
	} else
		iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));

	struct tcphdr *th = ((void *) iph) + sizeof(struct iphdr);
	th->th_flags = th_flags;
	th->th_seq = htonl(tcp_sock->tcp_seq);
	th->th_ack = htonl(tcp_sock->tcp_ack);

	if (th_flags & TH_SYN) {
		struct ndpip_tcp_option_mss *th_mss = (void *) (th + 1);
		th_mss->opt.kind = TCPOPT_MAXSEG;
		th_mss->opt.len = TCPOLEN_MAXSEG;
		th_mss->mss = htons(sock->mss);
	
		struct ndpip_tcp_option_nop *th_nop1 = (void *) (th_mss + 1);
		th_nop1->kind = TCPOPT_NOP;

		struct ndpip_tcp_option_scale *th_scale = (void *) (th_nop1 + 1);
		th_scale->opt.kind = TCPOPT_WINDOW;
		th_scale->opt.len = TCPOLEN_WINDOW;
		th_scale->scale = tcp_sock->tcp_recv_win_scale;

		th->th_off = (sizeof(struct tcphdr) + sizeof(struct ndpip_tcp_option_mss) +
			sizeof(struct ndpip_tcp_option_nop) + sizeof(struct ndpip_tcp_option_scale)) >> 2;
	} else
		th->th_off = sizeof(struct tcphdr) >> 2;

#ifndef NDPIP_DEBUG_NO_CKSUM
	ndpip_tcp_prepare_pbuf(tcp_sock, pb, iph, th);
#endif
	uint16_t data_len;
	if (th_flags == TH_ACK)
		data_len = 0;
	else
		data_len = 1;

	ndpip_pbuf_metadata(pb)->data_len = data_len;

	return 0;
}

void ndpip_tcp_rto_handler(void *argp) {
	struct ndpip_tcp_socket *tcp_sock = argp;
	struct ndpip_socket *sock = &tcp_sock->socket;

	struct ndpip_pbuf *pb;
	size_t cnt = 1;

	if (tcp_sock->tcp_seq == tcp_sock->tcp_last_ack)
		goto ret_no_rto;

	ndpip_tcp_free_acked(tcp_sock);
	if (ndpip_ring_peek(sock->xmit_ring, &cnt, &pb) < 0)
		goto ret_no_rto;

	//printf("rto2: xmit_ring_size=%lu;\n", ndpip_ring_size(sock->xmit_ring));
	tcp_sock->tcp_rto = true;

#ifdef NDPIP_GRANTS_ENABLE
	uint16_t pbuf_len = ndpip_pbuf_length(pb);
	sock->grants -= pbuf_len + sock->grants_overhead;

	if (ndpip_log_grants) {
		ndpip_log_grants_tcp[ndpip_log_grants_tcp_idx][0] = sock->grants;
		ndpip_log_grants_tcp[ndpip_log_grants_tcp_idx][1] = pbuf_len + sock->grants_overhead;
		ndpip_log_grants_tcp[ndpip_log_grants_tcp_idx][2] = 0;

		ndpip_log_grants_tcp_idx++;
	}
#endif
	ndpip_iface_xmit(sock->iface, &pb, 1, false);
	//ndpip_iface_xmit(sock->iface, &pb, 1, true);

	if (!ndpip_timer_armed(tcp_sock->timer_rto))
		ndpip_timer_arm_after(tcp_sock->timer_rto, NDPIP_TODO_TCP_RETRANSMIT_TIMEOUT);

	return;

ret_no_rto:
	tcp_sock->tcp_rto = false;
}

static void ndpip_tcp_parse_opts(struct ndpip_tcp_socket *tcp_sock, struct tcphdr *th, uint16_t th_hlen)
{
	struct ndpip_socket *sock = &tcp_sock->socket;

	for (size_t idx = sizeof(struct tcphdr); idx < th_hlen;) {
		struct ndpip_tcp_option *th_opt = ((void *) th) + idx;

		if (th_opt->kind == TCPOPT_WINDOW) {
			struct ndpip_tcp_option_scale *th_scale = (void *) th_opt;
			tcp_sock->tcp_send_win_scale = th_scale->scale;
		}

		if (th_opt->kind == TCPOPT_MAXSEG) {
			struct ndpip_tcp_option_mss *th_mss = (void *) th_opt;
			sock->mss = th_mss->mss;
		}

		if (th_opt->kind == TCPOPT_NOP)
			idx += 1;
		else
			idx += th_opt->len == 0 ? 1 : th_opt->len;
	}
}

static void ndpip_tcp_close_established(struct ndpip_tcp_socket *tcp_sock)
{
	struct ndpip_socket *sock = &tcp_sock->socket;

	uint64_t hash = ndpip_socket_established_hash(sock->local, sock->remote);
	ndpip_hashtable_del(ndpip_tcp_established_sockets, hash);
}

static void ndpip_tcp_close_listening(struct ndpip_tcp_socket *tcp_sock)
{
	struct ndpip_socket *sock = &tcp_sock->socket;

	uint64_t hash = ndpip_socket_listening_hash(sock->local);
	ndpip_hashtable_del(ndpip_tcp_listening_sockets, hash);
}

int ndpip_tcp_close(struct ndpip_tcp_socket *tcp_sock)
{
	int ret = 0;

	//printf("tcp_sock->state=%d;\n", tcp_sock->state);

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
			tcp_sock->state = FIN_WAIT_1;
			ret = ndpip_tcp_fin(tcp_sock);
			if (ret < 0)
				return -1;

			while (tcp_sock->state != TIME_WAIT)
				ndpip_usleep(1);

			tcp_sock->state = CLOSED;

			break;

		case CLOSE_WAIT:
			tcp_sock->state = LAST_ACK;
			ret = ndpip_tcp_fin(tcp_sock);
			if (ret < 0)
				return -1;

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
			break;
	}


	return 0;
}

static void ndpip_tcp_prepare_send(struct ndpip_tcp_socket *tcp_sock, struct ndpip_pbuf *pb, uint16_t data_len, uint32_t tcp_seq)
{
	assert(ndpip_pbuf_offset(pb, sizeof(tcp_sock->xmit_template)) >= 0);
	memcpy(ndpip_pbuf_data(pb), tcp_sock->xmit_template, sizeof(tcp_sock->xmit_template));

	struct iphdr *iph = ndpip_pbuf_data(pb) + sizeof(struct ethhdr);
	struct tcphdr *th = (void *) (iph + 1);

	uint16_t tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len;
	iph->tot_len = htons(tot_len);

	th->th_seq = htonl(tcp_seq);
	th->th_ack = htonl(tcp_sock->tcp_ack);
	th->th_flags = TH_ACK;

#ifndef NDPIP_DEBUG_NO_CKSUM
	ndpip_tcp_prepare_pbuf(tcp_sock, pb, iph, th);
#endif

	ndpip_pbuf_metadata(pb)->data_len = data_len;

#ifdef NDPIP_GRANTS_ENABLE
	sock->grants -= sock->grants_overhead + data_len;

	if (ndpip_log_grants) {
		ndpip_log_grants_tcp[ndpip_log_grants_tcp_idx][0] = sock->grants;
		ndpip_log_grants_tcp[ndpip_log_grants_tcp_idx][1] = data_len + sock->grants_overhead;
		ndpip_log_grants_tcp[ndpip_log_grants_tcp_idx][2] = 1;

		ndpip_log_grants_tcp_idx++;
	}
#endif
}

int ndpip_tcp_send(struct ndpip_tcp_socket *tcp_sock, struct ndpip_pbuf **pb, uint16_t cnt)
{
	if (cnt == 0)
		return 0;

	struct ndpip_socket *sock = &tcp_sock->socket;

#ifdef NDPIP_GRANTS_ENABLE
	if (sock->grants_overhead < 0)
		return 0;

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
#endif

	if (tcp_sock->state != CONNECTED) {
		errno = EINVAL;
		return -1;
	}

	if (tcp_sock->tcp_rto)
		return 0;

	uint32_t data_left = tcp_sock->tcp_max_seq - tcp_sock->tcp_seq;

#ifdef NDPIP_GRANTS_ENABLE
	if ((sock->grants == 0) || (data_left == 0))
		return 0;
#else
	if (data_left == 0)
		return 0;
#endif

	uint16_t burst_size = ndpip_iface_get_burst_size(sock->iface);
	cnt = cnt < burst_size ? cnt : burst_size;

	struct ndpip_ring *xmit_ring = sock->xmit_ring;
	size_t xmit_ring_free = ndpip_ring_free(xmit_ring);
	if (xmit_ring_free == 0) {
		ndpip_tcp_free_acked(tcp_sock);
		return 0;
	}

	cnt = cnt < xmit_ring_free ? cnt : xmit_ring_free;
	if (!ndpip_timer_armed(tcp_sock->timer_rto))
		ndpip_timer_arm_after(tcp_sock->timer_rto, NDPIP_TODO_TCP_RETRANSMIT_TIMEOUT);

	uint16_t idx;
	uint32_t tcp_seq = tcp_sock->tcp_seq;
	for (idx = 0; idx < cnt; idx++) {
		uint16_t data_len = ndpip_pbuf_length(pb[idx]);

#ifdef NDPIP_GRANTS_ENABLE
		if (sock->grants < ndpip_socket_pbuf_cost(sock, pb[idx]))
			break;
#endif
		if (data_left < data_len)
			break;

		ndpip_tcp_prepare_send(tcp_sock, pb[idx], data_len, tcp_seq);
		tcp_seq += data_len;
		data_left -= data_len;
	}

	/*
	struct ndpip_pbuf *split_pb = NULL;
#ifdef NDPIP_GRANTS_ENABLE
	if ((idx != cnt) && (data_left > 0) && (sock->grants > ndpip_socket_pbuf_cost(sock, NULL))) {
		uint32_t grants_left_tmp = sock->grants - ndpip_socket_pbuf_cost(sock, NULL);
		uint16_t seg_len = data_left < grants_left_tmp ? data_left : grants_left_tmp;
#else
	if ((idx != cnt) && (data_left != 0)) {
		int64_t seg_len = data_left;
#endif
		printf("%hu\n", seg_len);
		split_pb = ndpip_pbuf_copy(pb[idx], ndpip_iface_get_pbuf_pool_tx(sock->iface), 0, seg_len);
		ndpip_tcp_prepare_send(tcp_sock, split_pb);
		assert(ndpip_pbuf_offset(pb[idx], -seg_len) >= 0);

		idx++;

		struct ndpip_pbuf **pb2 = malloc(sizeof(struct ndpip_bpuf *) * idx);
		memcpy(pb2, pb, sizeof(struct ndpip_pbuf *) * idx);
		pb = pb2;
		pb[idx] = split_pb;
	}
	*/

	if (idx > 0) {
		assert(ndpip_ring_push(xmit_ring, pb, idx) >= 0);
		ndpip_iface_xmit(sock->iface, pb, idx, false);
		//ndpip_iface_xmit(sock->iface, pb, idx, true);
		tcp_sock->tcp_seq = tcp_seq;

	}

	//printf("TCP-send: xmit_ring_size=%lu;\n", ndpip_ring_size(xmit_ring));
	return idx;
}

static int ndpip_tcp_send_one(struct ndpip_tcp_socket *tcp_sock, struct ndpip_pbuf *pb)
{
	struct ndpip_socket *sock = &tcp_sock->socket;

	if (!ndpip_timer_armed(tcp_sock->timer_rto))
		ndpip_timer_arm_after(tcp_sock->timer_rto, NDPIP_TODO_TCP_RETRANSMIT_TIMEOUT);

#ifdef NDPIP_GRANTS_ENABLE
	uint16_t pbuf_len = ndpip_pbuf_length(pb);
	sock->grants -= pbuf_len + sock->grants_overhead;

	if (ndpip_log_grants) {
		ndpip_log_grants_tcp[ndpip_log_grants_tcp_idx][0] = sock->grants;
		ndpip_log_grants_tcp[ndpip_log_grants_tcp_idx][1] = pbuf_len(pb) + sock->grants_overhead;
		ndpip_log_grants_tcp[ndpip_log_grants_tcp_idx][2] = 2;

		ndpip_log_grants_tcp_idx++;
	}
#endif
	while (ndpip_ring_push_one(sock->xmit_ring, pb) < 0) {
		ndpip_tcp_free_acked(tcp_sock);
		ndpip_usleep(1);
	}

	ndpip_iface_xmit(sock->iface, &pb, 1, false);
	//ndpip_iface_xmit(sock->iface, &pb, 1, true);
	tcp_sock->tcp_seq++;

	return 0;
}

void ndpip_tcp_free_acked(struct ndpip_tcp_socket *tcp_sock)
{
	struct ndpip_socket *sock = &tcp_sock->socket;

	size_t tcp_can_free = tcp_sock->tcp_can_free;
	//printf("free_acked1: tcp_can_free=%lu;\n", tcp_sock->tcp_can_free);
	//printf("free_acked2: xmit_ring_size=%lu;\n", xmit_ring_size);
	if (tcp_can_free == 0)
		return;

	struct ndpip_ring *xmit_ring = sock->xmit_ring;
	size_t xmit_ring_size = ndpip_ring_size(sock->xmit_ring);
	if (xmit_ring_size == 0)
		return;

	//printf("free_acked3\n");
	struct ndpip_pbuf **pbs = malloc(xmit_ring_size * sizeof(struct ndpip_pbuf *));
	ndpip_ring_peek(xmit_ring, &xmit_ring_size, pbs);

	//printf("ndpip_tcp_free_acked: data_len=[");
	size_t idx, freed_len;
	for (idx = 0, freed_len = 0; idx < xmit_ring_size; idx++) {
		uint16_t data_len = ndpip_pbuf_metadata(pbs[idx])->data_len;
		//printf("%hu ", data_len);
		if ((freed_len + data_len) > tcp_can_free)
			break;

		freed_len += data_len;
	}
	/*
	printf("];\n");
	static int el = 0;
	if (el++ > 10)
		exit(0);
		*/

	//printf("free_acked4: %lu\n", idx);

	if (idx > 0) {
		/*
		static uint32_t ack;
		static bool init = false;
		for (size_t idx2 = 0; idx2 < idx; idx2++) {
			struct iphdr *iph = (struct iphdr *) (ndpip_pbuf_data(pbs[idx2]) + sizeof(struct ethhdr));
			struct tcphdr *th = (void *) (iph + 1);

			uint16_t data_len = ntohs(iph->tot_len) - (iph->ihl << 2) - (th->th_off << 2);
			uint32_t th_seq = ntohl(th->th_seq);

			if (init)
				init = true;
			else {
				if (th_seq != ack) {
					printf("ndpip_free_acked: at idx=%lu ack=%u != seq=%u\n", idx2, ack, th_seq);
					exit(-1);
				}
			}

			ack = th_seq + ((th->th_flags == TH_ACK) ? data_len : 1);
		}
		*/

		ndpip_sock_free(sock, pbs, idx, false);
		ndpip_ring_flush(xmit_ring, idx);
		tcp_sock->tcp_can_free -= freed_len;
	}

	free(pbs);
	//printf("free_acked5: xmit_ring_size=%lu; freed_len=%lu; tcp_can_free=%lu;\n", ndpip_ring_size(xmit_ring), freed_len, tcp_sock->tcp_can_free);
}

int ndpip_tcp_flush(struct ndpip_tcp_socket *tcp_sock, struct ndpip_pbuf *rpb)
{
	//printf("flush\n");
	if (tcp_sock->tcp_req_ack) {
		if (ndpip_timer_armed(tcp_sock->timer_rto))
			ndpip_timer_arm_after(tcp_sock->timer_rto, NDPIP_TODO_TCP_RETRANSMIT_TIMEOUT);

		tcp_sock->tcp_req_ack = false;
	}

	if (tcp_sock->tcp_rsp_ack) {
		ndpip_tcp_build_meta(tcp_sock, TH_ACK, rpb);
		tcp_sock->tcp_rsp_ack = false;
		return 1;
	}

	return 0;
}

int ndpip_tcp_feed(struct ndpip_tcp_socket *tcp_sock, struct sockaddr_in *remote, struct ndpip_pbuf *pb, uint16_t th_len)
{
	//printf("TCP-feed\n");
	struct ndpip_socket *sock = &tcp_sock->socket;

	struct tcphdr *th = ndpip_pbuf_data(pb);
	uint8_t th_flags = th->th_flags & ~TH_PUSH;

	uint32_t tcp_seq = ntohl(th->th_seq);
	uint32_t tcp_ack = ntohl(th->th_ack);

	uint16_t th_hlen = th->th_off << 2;
	uint16_t data_len = th_len - th_hlen;

	enum ndpip_tcp_socket_state tcp_state = tcp_sock->state;

	if (tcp_state != LISTENING) {
		if (tcp_state != CONNECTING) {
			// Out of order or unseen segment
			//printf("Segment sequence: seq=%u;\n", tcp_seq);
			if (tcp_seq != tcp_sock->tcp_ack) {
				//printf("ndpip_tcp_feed: Out of order or unseen segment: seq=%u; expected_seq=%u;\n", tcp_seq, tcp_sock->tcp_ack);
				tcp_sock->tcp_rsp_ack = true;
				return 0;
			}
		}

		if (th_flags & TH_ACK) {
			uint32_t tcp_last_ack = tcp_sock->tcp_last_ack;
			// Bad ACK
			if ((tcp_ack - tcp_last_ack) > (tcp_sock->tcp_seq - tcp_last_ack)) {
				//printf("ndpip_tcp_feed: Bad ACK\n");
				return 0;
			}

			// Data ACKed
			tcp_sock->tcp_req_ack = true;
			tcp_sock->tcp_can_free += tcp_ack - tcp_last_ack;
			tcp_sock->tcp_last_ack = tcp_ack;
			tcp_sock->tcp_max_seq = tcp_ack + (((uint32_t) ntohs(th->th_win)) << tcp_sock->tcp_send_win_scale);
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

	if (tcp_state == LISTENING) {
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
		asock->mss = sock->mss;
		tcp_asock->tcp_recv_win_scale = tcp_sock->tcp_recv_win_scale;
		tcp_asock->state = ACCEPTING;

		ndpip_tcp_parse_opts(tcp_asock, th, th_hlen);

		if (ndpip_tcp_build_xmit_template(tcp_asock) < 0) {
			free(asock);
			goto err_l;
		}

		tcp_asock->tcp_ack = tcp_sock->tcp_ack;

		uint64_t hash = ndpip_socket_established_hash(asock->local, asock->remote);
		ndpip_hashtable_put(ndpip_tcp_established_sockets, hash, asock);

		ndpip_list_add(&tcp_sock->accept_queue, &tcp_asock->accept_queue);

		struct ndpip_pbuf *pb;
		if (ndpip_sock_alloc((struct ndpip_socket *) tcp_asock, &pb, 1, false) < 0) {
			tcp_sock = tcp_asock;
			goto err;
		}

		ndpip_tcp_build_meta(tcp_asock, TH_SYN | TH_ACK, pb);
		ndpip_tcp_send_one(tcp_asock, pb);

		return 0;
	}

	if (tcp_state == CONNECTING) {
		if (th_flags != (TH_SYN | TH_ACK))
			goto err;

		if (data_len != 0)
			goto err;

		ndpip_tcp_parse_opts(tcp_sock, th, th_hlen);

		tcp_sock->tcp_rsp_ack = true;
		tcp_sock->state = CONNECTED;

		return 0;
	}

	if (tcp_state == ACCEPTING) {
		if (th_flags != TH_ACK)
			goto err;

		if (data_len != 0)
			goto err;

		tcp_sock->state = CONNECTED;
		return 0;
	}

	if (tcp_state == CONNECTED) {
		if ((th_flags == TH_FIN) || (th_flags == (TH_FIN | TH_ACK))) {
			if (data_len != 0)
				goto err;

			//printf("CONNECTED -> CLOSE_WAIT\n");
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

		assert(ndpip_pbuf_offset(pb, -th_hlen) >= 0);
		assert(ndpip_ring_push_one(sock->recv_ring, pb) >= 0);

		return 1;
	}

	if (tcp_state == CLOSE_WAIT) {
		if (data_len != 0)
			goto err;

		if (th_flags != TH_ACK)
			goto err;

		return 0;
	}

	if (tcp_state == LAST_ACK) {
		if (data_len != 0)
			goto err;

		if (th_flags != TH_ACK)
			goto err;

		tcp_sock->state = CLOSED;
		ndpip_tcp_close_established(tcp_sock);
		return 0;
	}

	if (tcp_state == FIN_WAIT_1) {
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

	if (tcp_state == FIN_WAIT_2) {
		if (data_len != 0)
			goto err;

		if (th_flags != TH_FIN)
			goto err;

		tcp_sock->tcp_rsp_ack = true;
		tcp_sock->state = TIME_WAIT;
		return 0;
	}

	if (tcp_state == CLOSING) {
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
	ndpip_tcp_build_meta(tcp_sock, TH_RST, pb);
	ndpip_tcp_send_one(tcp_sock, pb);

	return 0;
}
