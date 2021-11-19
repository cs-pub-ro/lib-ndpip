#ifndef _INCLUDE_NDPIP_SOCKET_H_
#define _INCLUDE_NDPIP_SOCKET_H_

#include "pbuf.h"

#define SOCK_NDPIP 42

#define SO_NDPIP_TCP_WIN_SCALE 100

int ndpip_socket(int domain, int type, int protocol);
int ndpip_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int ndpip_listen(int sockfd, int backlog);
int ndpip_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int ndpip_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

int ndpip_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
ssize_t ndpip_recv(int sockfd, struct ndpip_pbuf **pb, size_t count);
int ndpip_free(int sockfd, struct ndpip_pbuf **pb, size_t len);

#endif
