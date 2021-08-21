#ifndef _SRC_INCLUDE_NDPIP_SOCKET_H_
#define _SRC_INCLUDE_NDPIP_SOCKET_H_

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <sys/socket.h>

#include "../../../include/ndpip/socket.h"
#include "ndpip/util.h"
#include "ndpip/uk.h"


struct ndpip_socket {
	struct ndpip_list_head list;

	int socket_id;
	struct ndpip_iface *socket_iface;

	enum {
		NEW,
		BOUND,
		CONNECTING,
		CONNECTED,
		LISTENING,
		CLOSED
	} state;

	struct in_addr local_inaddr;
	struct in_addr remote_inaddr;

	uint16_t local_port;
	uint16_t remote_port;

	uint8_t xmit_template[sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)];

	struct ndpip_pbuf_ring *xmit_ring;

	struct ndpip_timer *socket_timer_rto;

	size_t xmit_ring_unsent_off;
	uint16_t xmit_ring_unsent_train_off;

	uint32_t tcp_seq, tcp_ack;
};


struct ndpip_socket *ndpip_socket_get_by_peer(struct in_addr local_inaddr, uint16_t local_peer, struct in_addr remote_inaddr, uint16_t remote_peer);

#endif
