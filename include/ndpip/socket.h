#ifndef _INCLUDE_NDPIP_SOCKET_H_
#define _INCLUDE_NDPIP_SOCKET_H_

#include "pbuf.h"

#define SOCK_NDPIP 42

#define SO_NDPIP_TCP_WIN_SCALE 100
#define SO_NDPIP_GRANTS 101
#define SO_NDPIP_BURST 102
#define SO_NDPIP_MAX_TX_SEG 103
#define SO_NDPIP_TCP_MAX_RX_SEG 104

int ndpip_socket(int domain, int type, int protocol);
int ndpip_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int ndpip_listen(int sockfd, int backlog);
int ndpip_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int ndpip_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int ndpip_close(int sockfd);

int ndpip_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int ndpip_getsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int ndpip_recv(int sockfd, struct ndpip_pbuf **pb, uint16_t count);
int ndpip_send(int sockfd, struct ndpip_pbuf **pb, uint16_t count);
int ndpip_free(int sockfd, struct ndpip_pbuf **pb, size_t len);
size_t ndpip_alloc(int sockfd, struct ndpip_pbuf **pb, size_t len);
#ifdef NDPIP_GRANTS_ENABLE
int ndpip_cost(int sockfd, struct ndpip_pbuf **pb, uint16_t len, uint16_t *pb_cost);
int ndpip_grants_get(int sockfd, uint32_t grants);
#endif

#endif
