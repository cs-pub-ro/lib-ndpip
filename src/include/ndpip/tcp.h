#ifndef _SRC_INCLUDE_NDPIP_TCP_H_
#define _SRC_INCLUDE_NDPIP_TCP_H_

#include <time.h>

#include <netinet/in.h>

#include "ndpip/pbuf.h"
#include "ndpip/socket.h"

int ndpip_tcp_build_xmit_template(struct ndpip_socket *sock);
int ndpip_tcp_send_meta(struct ndpip_socket *sock, uint8_t flags);
struct tcphdr *ndpip_tcp_recv_one(struct ndpip_socket *sock);
int ndpip_tcp_feed(struct ndpip_socket *sock, struct sockaddr_in *remote, struct ndpip_pbuf *pb);
int ndpip_tcp_send(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t cnt);
void ndpip_tcp_rto_handler(void *argp);

#endif
