#ifndef _SRC_INCLUDE_NDPIP_TCP_H_
#define _SRC_INCLUDE_NDPIP_TCP_H_

#include <time.h>

#include <netinet/in.h>

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

int ndpip_tcp_build_xmit_template(struct ndpip_socket *sock);
int ndpip_tcp_build_meta(struct ndpip_socket *sock, uint8_t flags, struct ndpip_pbuf *pb);
int ndpip_tcp_build_syn(struct ndpip_socket *sock, bool ack, struct ndpip_pbuf *pb);
int ndpip_tcp_feed(struct ndpip_socket *sock, struct sockaddr_in *remote, struct ndpip_pbuf *pb, struct ndpip_pbuf *rpb);
int ndpip_tcp_send(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t cnt);
void ndpip_tcp_rto_handler(void *argp);

#endif
