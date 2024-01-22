#ifndef _SRC_INCLUDE_NDPIP_EPOLL_H_
#define _SRC_INCLUDE_NDPIP_EPOLL_H_

#include "../../../include/ndpip/epoll.h"

#include "ndpip/socket.h"

struct ndpip_epitem {
	struct ndpip_list_head list;

	struct ndpip_socket *socket;
	struct epoll_event event;
};

struct ndpip_eventpoll {
	struct ndpip_list_head epitems;
	struct ndpip_epitem *last_epitem;
};

void ndpip_epoll_init();

#endif
