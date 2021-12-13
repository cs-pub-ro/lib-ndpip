#ifndef _SRC_INCLUDE_NDPIP_SOCKET_H_
#define _SRC_INCLUDE_NDPIP_SOCKET_H_

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <sys/socket.h>

#include "../../../include/ndpip/socket.h"
#include "ndpip/util.h"

#ifdef NDPIP_UK
#include "ndpip/uk.h"
#endif

#ifdef NDPIP_LINUX_DPDK
#include "ndpip/linux_dpdk.h"
#endif

struct ndpip_socket {
	struct ndpip_list_head list;
	struct ndpip_list_head accept_queue;

	int socket_id;
	struct ndpip_iface *socket_iface;

	enum {
		NEW,
		BOUND,
		ACCEPTING,
		CONNECTING,
		CONNECTED,
		LISTENING,
		CLOSING,
		CLOSED
	} state;

	struct sockaddr_in local;
	struct sockaddr_in remote;

	uint8_t xmit_template[sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)];

	struct ndpip_ring *xmit_ring;
	struct ndpip_ring *recv_ring;

	struct ndpip_timer *socket_timer_rto;

	uint32_t tcp_seq, tcp_ack, tcp_last_ack, tcp_good_ack;

	uint32_t tcp_recv_win;
	uint32_t tcp_max_seq;

	uint8_t tcp_recv_win_scale;
	uint8_t tcp_send_win_scale;

	bool tcp_recovery;
	bool tcp_retransmission;

	bool tcp_rsp_ack;
	bool rx_loop_seen;
};

struct ndpip_socket *ndpip_socket_new(int domain, int type, int protocol);
struct ndpip_socket *ndpip_socket_accept(struct ndpip_socket *sock);
struct ndpip_socket *ndpip_socket_get_by_peer(struct sockaddr_in *local, struct sockaddr_in *peer);
int ndpip_sock_free(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t len, bool rx);
int ndpip_sock_alloc(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t len, bool rx);

#endif
