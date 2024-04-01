#ifndef _SRC_INCLUDE_NDPIP_UDP_H_
#define _SRC_INCLUDE_NDPIP_UDP_H_

#include <time.h>

#include <netinet/in.h>
#include <netinet/udp.h>

#include "ndpip/pbuf.h"
#include "ndpip/socket.h"

struct ndpip_udp_socket {
    struct ndpip_socket socket;
    uint8_t xmit_template[sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr)];
};

int ndpip_udp_build_xmit_template(struct ndpip_udp_socket *sock);
void ndpip_udp_feed(struct ndpip_udp_socket *sock, struct sockaddr_in *remote, struct ndpip_pbuf *pb);
void ndpip_udp_flush(struct ndpip_udp_socket *sock);
int ndpip_udp_send(struct ndpip_udp_socket *sock, struct ndpip_pbuf **pb, uint16_t cnt);
void ndpip_udp_prepare_send(struct ndpip_udp_socket *sock, struct ndpip_pbuf *pb);
int ndpip_udp_close(struct ndpip_udp_socket *sock);
int ndpip_udp_connect(struct ndpip_udp_socket *udp_sock);
uint32_t ndpip_udp_poll(struct ndpip_udp_socket *udp_sock);

#endif
