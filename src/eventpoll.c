#include "ndpip/epoll.h"


#define NDPIP_TODO_MAX_EPOLLFDS 1024


struct ndpip_eventpoll **epoll_table = NULL;

void ndpip_epoll_init()
{
	epoll_table = calloc(NDPIP_TODO_MAX_EPOLLFDS, sizeof(struct ndpip_eventpoll));
}

int ndpip_epoll_create1(int flags)
{
	if (flags != 0) {
		errno = EINVAL;
		return -1;
	}

	int epollfd = 0;
	for (; epollfd < NDPIP_TODO_MAX_EPOLLFDS; epollfd++) {
		if (epoll_table[epollfd] == NULL)
			break;
	}

	if (epollfd == NDPIP_TODO_MAX_EPOLLFDS) {
		errno = EMFILE;
		return -1;
	}

	epoll_table[epollfd] = malloc(sizeof(struct ndpip_eventpoll));
	epoll_table[epollfd]->epitems = (struct ndpip_list_head) { &epoll_table[epollfd]->epitems, &epoll_table[epollfd]->epitems };
	epoll_table[epollfd]->last_epitem = (void *) epoll_table[epollfd]->epitems.next;

	return epollfd;
}

int ndpip_epoll_ctl_del(struct ndpip_eventpoll *epoll, struct ndpip_socket *sock)
{
	ndpip_list_foreach(e, &epoll->epitems) {
		struct ndpip_epitem *epi = ((void *) e) - offsetof(struct ndpip_epitem, list);
		if (epi->socket == sock) {
			ndpip_list_del(&epi->list);
			free(epi);

			epoll->last_epitem = (void *) epoll->epitems.next;
			return 0;
		}
	}

	errno = ENOENT;
	return -1;
}

int ndpip_epoll_ctl_mod(struct ndpip_eventpoll *epoll, struct ndpip_socket *sock, struct epoll_event *event)
{
	ndpip_list_foreach(e, &epoll->epitems) {
		struct ndpip_epitem *epi = ((void *) e) - offsetof(struct ndpip_epitem, list);
		if (epi->socket == sock) {
			epi->event = *event;

			return 0;
		}
	}

	errno = ENOENT;
	return -1;
}

int ndpip_epoll_ctl_add(struct ndpip_eventpoll *epoll, struct ndpip_socket *sock, struct epoll_event *event)
{
	struct ndpip_epitem *epi = malloc(sizeof(struct ndpip_epitem));
	epi->list = (struct ndpip_list_head) { &epi->list, &epi->list };
	epi->event = *event;
	epi->event.events |= EPOLLHUP;
	epi->socket = sock;
	ndpip_list_add(&epoll->epitems, &epi->list);
	epoll->last_epitem = (void *) epoll->epitems.next;

	return 0;
}

int ndpip_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	if (epfd > NDPIP_TODO_MAX_EPOLLFDS) {
		errno = EBADF;
		return -1;
	}

	struct ndpip_eventpoll *epoll = epoll_table[epfd];
	if (epoll == NULL) {
		errno = EBADF;
		return -1;
	}

	if (fd > NDPIP_TODO_MAX_FDS) {
		errno = EBADF;
		return -1;
	}

	struct ndpip_socket *sock = socket_table[fd];
	if (sock == NULL) {
		errno = EBADF;
		return -1;
	}

	if (op == EPOLL_CTL_ADD)
		return ndpip_epoll_ctl_add(epoll, sock, event);

	else if (op == EPOLL_CTL_MOD)
		return ndpip_epoll_ctl_mod(epoll, sock, event);

	else if (op == EPOLL_CTL_DEL)
		return ndpip_epoll_ctl_del(epoll, sock);

	else {
		errno = EINVAL;
		return -1;
	}
}

int ndpip_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
	if (epfd > NDPIP_TODO_MAX_EPOLLFDS) {
		errno = EBADF;
		return -1;
	}

	struct ndpip_eventpoll *epoll = epoll_table[epfd];
	if (epoll == NULL) {
		errno = EBADF;
		return -1;
	}

	if (events == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (maxevents < 1) {
		errno = EINVAL;
		return -1;
	}

	if (timeout < 0) {
		errno = EINVAL;
		return -1;
	}

	struct timespec start;
	ndpip_time_now(&start);

	struct timespec end = start;
	struct timespec timeout_ts = {.tv_sec = timeout / 1000, .tv_nsec = (timeout % 1000) * 1000000 };
	ndpip_timespec_add(&end, &timeout_ts);

	int idx = 0;
	while (true) {
		for (
			struct ndpip_epitem *epi = epoll->last_epitem;
			((void *) epi) != ((void *) &epoll->epitems);
			epi = (void *) epi->list.next) {

			uint32_t mask = ndpip_socket_poll(epi->socket) & epi->event.events;
			if (mask) {
				events[idx] = epi->event;
				events[idx].events = mask;
				idx++;
			}

			if (idx >= maxevents) {
				epoll->last_epitem = epi;
				return idx;
			}
		}

		epoll->last_epitem = (void *) epoll->epitems.next;

		if (idx > 0)
			return idx;

		if (timeout > 0) {
			struct timespec now;
			ndpip_time_now(&now);

			if ((now.tv_sec > end.tv_sec) || ((now.tv_sec == end.tv_sec) && (now.tv_nsec > end.tv_nsec)))
				return 0;
		}
	}
}
