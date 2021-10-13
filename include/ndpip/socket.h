#ifndef _INCLUDE_NDPIP_SOCKET_H_
#define _INCLUDE_NDPIP_SOCKET_H_

#include "pbuf.h"

#define SOCK_NDPIP 42

ssize_t ndpip_recv(int sockfd, struct ndpip_pbuf **pb, size_t count);
int ndpip_free(int sockfd, struct ndpip_pbuf **pb, size_t len);

#endif
