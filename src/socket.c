#include <string.h>
#include <time.h>

#include "ndpip/socket.h"
#include "ndpip/tcp.h"
#include "ndpip/util.h"


#define NDPIP_TODO_SOCKET_XMIT_RING_LENGTH 65536
#define NDPIP_TODO_SOCKET_RECV_RING_LENGTH 65536


static NDPIP_LIST_HEAD(ndpip_sockets_head);

static int last_socket_id = 0;


struct ndpip_socket *ndpip_socket_get_by_peer(struct sockaddr_in *local, struct sockaddr_in *remote)
{
	struct ndpip_socket *ret = NULL;

	ndpip_list_foreach(struct ndpip_socket, sock, &ndpip_sockets_head) {
		if ((sock->local.sin_addr.s_addr == local->sin_addr.s_addr) &&
			(sock->local.sin_port == local->sin_port)) {

			if (((sock->state == CONNECTING) || (sock->state == ACCEPTING) || (sock->state == CONNECTED)) &&
				(sock->remote.sin_addr.s_addr == remote->sin_addr.s_addr) &&
				(sock->remote.sin_port == remote->sin_port)) {

				ret = sock;
				break;
			}

			if (sock->state == LISTENING)
				ret = sock;
		}
	}

	return ret;
}

static struct ndpip_socket *ndpip_socket_get(int sockfd)
{
	ndpip_list_foreach(struct ndpip_socket, sock, &ndpip_sockets_head)
		if (sock->socket_id == sockfd)
			return sock;

	return NULL;
}

struct ndpip_socket *ndpip_socket_new(int domain, int type, int protocol)
{
	if (!((domain == AF_INET) && (type == SOCK_NDPIP) && (protocol == IPPROTO_TCP)))
			return NULL;

	struct ndpip_socket *sock = malloc(sizeof(struct ndpip_socket));

	sock->socket_id = ++last_socket_id;
	sock->socket_iface = NULL;

	sock->state = NEW;

	sock->local = (struct sockaddr_in) { .sin_addr.s_addr = 0, .sin_port = 0 };
	sock->remote = (struct sockaddr_in) { .sin_addr.s_addr = 0, .sin_port = 0 };

	sock->xmit_ring = ndpip_ring_alloc(NDPIP_TODO_SOCKET_XMIT_RING_LENGTH, sizeof(struct ndpip_pbuf_train));
	sock->xmit_ring_unsent_off = 0;
	sock->xmit_ring_unsent_train_off = 0;

	sock->recv_ring = ndpip_ring_alloc(NDPIP_TODO_SOCKET_RECV_RING_LENGTH, sizeof(struct ndpip_pbuf *));

	sock->socket_timer_rto = ndpip_timer_alloc(ndpip_tcp_rto_handler, (void *) sock);
	ndpip_timers_add(sock->socket_timer_rto);

	sock->tcp_seq = 0;
	sock->tcp_ack = 0;
	sock->tcp_last_ack = 0;

	sock->accept_queue = (struct ndpip_list_head) { &sock->accept_queue, &sock->accept_queue };

	ndpip_list_add(&ndpip_sockets_head, (void *) sock);

	return sock;
}

int socket(int domain, int type, int protocol)
{
	struct ndpip_socket *sock = ndpip_socket_new(domain, type, protocol);
	if (sock == NULL)
		return -1;

	return sock->socket_id;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	if (sockfd < 0) {
		errno = EBADF;
		return -1;
	}

	struct ndpip_socket *sock = ndpip_socket_get(sockfd);
	if (sock == NULL) {
		errno = ENOTSOCK;
		return -1;
	}

	if (sock->state != NEW) {
		errno = EINVAL;
		return -1;
	}

	if (addr->sa_family != AF_INET) {
		errno = EINVAL;
		return -1;
	}

	if (addrlen != sizeof(struct sockaddr_in)) {
		errno = EINVAL;
		return -1;
	}

	struct sockaddr_in *addr_in = (void *) addr;

	ndpip_list_foreach(struct ndpip_socket, sock, &ndpip_sockets_head)
		if ((memcmp(&sock->local.sin_addr, &addr_in->sin_addr, sizeof(struct sockaddr_in)) == 0)
			&& (sock->local.sin_port == addr_in->sin_port)) {

			errno = EADDRINUSE;
			return -1;
		}

	sock->local = *addr_in;
	sock->socket_iface = ndpip_iface_get_by_inaddr(sock->local.sin_addr);

	sock->state = BOUND;

	return 0;
}

int listen(int sockfd, int backlog)
{
	(void) backlog;

	if (sockfd < 0) {
		errno = EBADF;
		return -1;
	}

	struct ndpip_socket *sock = ndpip_socket_get(sockfd);
	if (sock == NULL) {
		errno = ENOTSOCK;
		return -1;
	}

	if (sock->state != BOUND) {
		errno = EADDRINUSE;
		return -1;
	}

	sock->state = LISTENING;

	return 0;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	if (sockfd < 0) {
		errno = EBADF;
		return -1;
	}

	struct ndpip_socket *sock = ndpip_socket_get(sockfd);
	if (sock == NULL) {
		errno = ENOTSOCK;
		return -1;
	}

	if (sock->state != BOUND) {
		errno = EADDRINUSE;
		return -1;
	}

	if (addrlen != sizeof(struct sockaddr_in)) {
		errno = EINVAL;
		return -1;
	}

	struct sockaddr_in *addr_in = (void *) addr;

	sock->remote.sin_addr = addr_in->sin_addr;
	sock->remote.sin_port = addr_in->sin_port;

	if (ndpip_tcp_build_xmit_template(sock) < 0) {
		errno = EFAULT;
		return -1;
	}

	sock->state = CONNECTING;

	struct ndpip_pbuf_pool *pool = ndpip_iface_get_pbuf_pool_rx(sock->socket_iface);
	if (pool == NULL) {
		sock->state = CLOSED;
		errno = EFAULT;
		return -1;
	}

	struct ndpip_pbuf **pb = malloc(sizeof(struct ndpip_pbuf *) * 1);
	uint16_t cnt = 1;

	if (ndpip_pbuf_pool_request(pool, pb, &cnt) < 0) {
		sock->state = CLOSED;
		errno = EFAULT;
		return -1;
	}

	if (cnt != 1) {
		sock->state = CLOSED;
		errno = EFAULT;
		return -1;
	}

	if (ndpip_tcp_build_syn(sock, false, pb[0]) < 0) {
		sock->state = CLOSED;
		errno = EFAULT;
		return -1;
	}

	ndpip_tcp_send(sock, pb, 1);

	while (sock->state != CONNECTED)
		uk_sched_thread_sleep(1000UL);

	return 0;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	if (sockfd < 0) {
		errno = EBADF;
		return -1;
	}

	struct ndpip_socket *sock = ndpip_socket_get(sockfd);
	if (sock == NULL) {
		errno = ENOTSOCK;
		return -1;
	}

	if (sock->state != LISTENING) {
		errno = EINVAL;
		return -1;
	}

	struct ndpip_socket *asock = ndpip_socket_accept(sock);
	if (asock == NULL) {
		errno = EAGAIN;
		return -1;
	}

	while (asock->state != CONNECTED)
		uk_sched_thread_sleep(1000UL);

	if ((addr != NULL) && (addrlen != NULL)) {
		*((struct sockaddr_in *) addr) = asock->remote;
		*addrlen = sizeof(struct sockaddr_in);
	}

	return asock->socket_id;
}

ssize_t ndpip_recv(int sockfd, struct ndpip_pbuf **pb, size_t count)
{
	if (sockfd < 0) {
		errno = EBADF;
		return -1;
	}

	struct ndpip_socket *sock = ndpip_socket_get(sockfd);
	if (sock == NULL) {
		errno = ENOTSOCK;
		return -1;
	}

	if ((sock->state != CONNECTED) && (ndpip_ring_size(sock->recv_ring) == 0)) {
		errno = EINVAL;
		return -1;
	}

	if (count == 0) {
		errno = EINVAL;
		return -1;
	}

	if (ndpip_ring_size(sock->recv_ring) == 0) {
		errno = EAGAIN;
		return -1;
	}

	if (ndpip_ring_pop(sock->recv_ring, &count, pb) < 0) {
		errno = EFAULT;
		return -1;
	}
	
	return count;
}

int ndpip_free(int sockfd, struct ndpip_pbuf **pb, size_t len) {
	if (sockfd < 0) {
		errno = EBADF;
		return -1;
	}

	struct ndpip_socket *sock = ndpip_socket_get(sockfd);
	if (sock == NULL) {
		errno = ENOTSOCK;
		return -1;
	}

	if (len == 0)
		return 0;

	return ndpip_sock_free(sock, pb, len, true);
}

int ndpip_sock_free(struct ndpip_socket *sock, struct ndpip_pbuf **pb, size_t len, bool rx)
{
	struct ndpip_pbuf_pool *pool = NULL;
	
	if (rx)
		pool = ndpip_iface_get_pbuf_pool_rx(sock->socket_iface);
	else
		pool = ndpip_iface_get_pbuf_pool_tx(sock->socket_iface);

	if (pool == NULL) {
		errno = EFAULT;
		return -1;
	}

	if (ndpip_pbuf_pool_release(pool, pb, len) < 0) {
		errno = EFAULT;
		return -1;
	}

	return 0;
}

struct ndpip_socket *ndpip_socket_accept(struct ndpip_socket *sock)
{
	if (sock->accept_queue.next == &sock->accept_queue)
		return NULL;

	struct ndpip_socket *asock = ((void *) sock->accept_queue.next) - offsetof(struct ndpip_socket, accept_queue);
	ndpip_list_del(sock->accept_queue.next);

	return asock;
}
