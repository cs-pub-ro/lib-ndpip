#ifndef _INCLUDE_NDPIP_SOCKET_H_
#define _INCLUDE_NDPIP_SOCKET_H_

#include "pbuf.h"

#define SOCK_NDPIP 42

int ndpip_recv(int sockfd, struct ndpip_pbuf ***pb, size_t *len);

#endif
