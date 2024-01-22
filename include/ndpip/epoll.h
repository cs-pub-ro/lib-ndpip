#ifndef _INCLUDE_NDPIP_EPOLL_H_
#define _INCLUDE_NDPIP_EPOLL_H_

#include <sys/epoll.h>

int ndpip_epoll_create1(int flags);
int ndpip_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int ndpip_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);

#endif
