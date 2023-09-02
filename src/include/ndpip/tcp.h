#ifndef _SRC_INCLUDE_NDPIP_TCP_H_
#define _SRC_INCLUDE_NDPIP_TCP_H_

#include <time.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include "ndpip/pbuf.h"
#include "ndpip/socket.h"

struct ndpip_tcp_option {
	uint8_t kind;
	uint8_t len;
} __attribute__((packed));

struct ndpip_tcp_option_nop {
	uint8_t kind;
} __attribute__((packed));

struct ndpip_tcp_option_mss {
	struct ndpip_tcp_option opt;
	uint16_t mss;
} __attribute__((packed));

struct ndpip_tcp_option_scale {
	struct ndpip_tcp_option opt;
	uint8_t scale;
} __attribute__((packed));

struct ndpip_tcp_socket {
	struct ndpip_socket socket;

	struct ndpip_list_head accept_queue;

	enum {
		NEW,
		BOUND,
		ACCEPTING,
		CONNECTING,
		CONNECTED,
		LISTENING,
		CLOSING,
		CLOSE_WAIT,
		LAST_ACK,
		FIN_WAIT_1,
		FIN_WAIT_2,
		TIME_WAIT,
		CLOSED
	} state;

	uint8_t xmit_template[sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)];

	struct ndpip_timer *timer_rto;

	uint32_t tcp_seq;
	uint32_t tcp_ack;
	uint32_t tcp_last_ack;

	uint32_t tcp_recv_win;
	uint32_t tcp_max_seq;

	uint8_t tcp_recv_win_scale;
	uint8_t tcp_send_win_scale;

	bool tcp_rto;
	bool tcp_rsp_ack;
	bool rx_loop_seen;

	uint32_t tcp_can_free;
};

int ndpip_tcp_feed(struct ndpip_tcp_socket *tcp_sock, struct sockaddr_in *remote, struct ndpip_pbuf *pb, struct ndpip_pbuf *rpb);
int ndpip_tcp_flush(struct ndpip_tcp_socket *tcp_sock, struct ndpip_pbuf *rpb);
int ndpip_tcp_send(struct ndpip_tcp_socket *tcp_sock, struct ndpip_pbuf **pb, uint16_t cnt);
void ndpip_tcp_rto_handler(void *argp);
int ndpip_tcp_connect(struct ndpip_tcp_socket *tcp_sock);
struct ndpip_tcp_socket *ndpip_tcp_accept(struct ndpip_tcp_socket *tcp_sock);
int ndpip_tcp_close(struct ndpip_tcp_socket *tcp_sock);

extern struct ndpip_hashtable *ndpip_established_sockets;
extern struct ndpip_hashtable *ndpip_listening_sockets;

#endif
