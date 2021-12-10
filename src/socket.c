#include <string.h>
#include <time.h>

#include "ndpip/socket.h"
#include "ndpip/tcp.h"
#include "ndpip/util.h"
#include "ndpip/workhorse.h"


#define NDPIP_TODO_SOCKET_XMIT_RING_LENGTH (1 << 20)
#define NDPIP_TODO_SOCKET_RECV_RING_LENGTH (1 << 20)


static NDPIP_LIST_HEAD(ndpip_sockets_head);

static int last_socket_id = 0;


struct ndpip_socket *ndpip_socket_get_by_peer(struct sockaddr_in *local, struct sockaddr_in *remote)
{
	struct ndpip_socket *ret = NULL;

	ndpip_list_foreach(struct ndpip_socket, sock, &ndpip_sockets_head) {
		if ((sock->local.sin_addr.s_addr == local->sin_addr.s_addr) &&
			(sock->local.sin_port == local->sin_port)) {

			if (!((sock->state == LISTENING) || (sock->state == CLOSED)) &&
				(sock->remote.sin_addr.s_addr == remote->sin_addr.s_addr) &&
				(sock->remote.sin_port == remote->sin_port)) {

				return sock;
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

	sock->xmit_ring = ndpip_ring_alloc(NDPIP_TODO_SOCKET_XMIT_RING_LENGTH, sizeof(struct ndpip_pbuf *));
	sock->recv_ring = ndpip_ring_alloc(NDPIP_TODO_SOCKET_RECV_RING_LENGTH, sizeof(struct ndpip_pbuf *));

	sock->socket_timer_rto = ndpip_timer_alloc(ndpip_tcp_rto_handler, (void *) sock);
	ndpip_timers_add(sock->socket_timer_rto);

	sock->tcp_seq = 0;
	sock->tcp_ack = 0;
	sock->tcp_recv_win = 0;
	sock->tcp_send_win = 0;
	sock->tcp_last_ack = 0;
	sock->tcp_good_ack = 0;
	sock->tcp_recv_win_scale = 0;
	sock->tcp_send_win_scale = 0;
	sock->tcp_recovery = false;
	sock->tcp_retransmission = false;
	sock->rx_loop_seen = false;

	sock->accept_queue = (struct ndpip_list_head) { &sock->accept_queue, &sock->accept_queue };

	ndpip_list_add(&ndpip_sockets_head, (void *) sock);

	return sock;
}

int ndpip_socket(int domain, int type, int protocol)
{
	struct ndpip_socket *sock = ndpip_socket_new(domain, type, protocol);
	if (sock == NULL)
		return -1;

	return sock->socket_id;
}

int ndpip_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
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
		if (memcmp(&sock->local, &addr_in, sizeof(struct sockaddr_in)) == 0) {

			errno = EADDRINUSE;
			return -1;
		}

	sock->local = *addr_in;
	sock->socket_iface = ndpip_iface_get_by_inaddr(sock->local.sin_addr);

	sock->state = BOUND;

	return 0;
}

int ndpip_listen(int sockfd, int backlog)
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

int ndpip_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
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

	sock->tcp_seq++;
	ndpip_tcp_send(sock, pb, 1);

	while (sock->state == CONNECTING)
		ndpip_nanosleep(1000UL);

	return 0;
}

int ndpip_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
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
		ndpip_nanosleep(1000UL);

	if ((addr != NULL) && (addrlen != NULL)) {
		*((struct sockaddr_in *) addr) = asock->remote;
		*addrlen = sizeof(struct sockaddr_in);
	}

	return asock->socket_id;
}

int ndpip_recv(int sockfd, struct ndpip_pbuf **pb, uint16_t count)
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

	if ((sock->state != CONNECTED) && (sock->state != CLOSING)
		&& (ndpip_ring_size(sock->recv_ring) == 0)) {

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

	size_t rcount = count;
	if (ndpip_ring_pop(sock->recv_ring, &rcount, pb) < 0) {
		errno = EFAULT;
		return -1;
	}
	
	return rcount;
}

int ndpip_send(int sockfd, struct ndpip_pbuf **pb, uint16_t count)
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

	if ((sock->state != CONNECTED) && (sock->state != CLOSING)) {
		errno = EINVAL;
		return -1;
	}

	if (count == 0) {
		errno = EINVAL;
		return -1;
	}

	return ndpip_tcp_send_data(sock, pb, count);
}

int ndpip_free(int sockfd, struct ndpip_pbuf **pb, uint16_t len) {
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

int ndpip_alloc(int sockfd, struct ndpip_pbuf **pb, uint16_t len) {
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

	return ndpip_sock_alloc(sock, pb, len, false);
}
int ndpip_sock_free(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t len, bool rx)
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

int ndpip_sock_alloc(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t len, bool rx)
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

	uint16_t tmp_len = len;

	if (ndpip_pbuf_pool_request(pool, pb, &tmp_len) < 0) {
		errno = EFAULT;
		return -1;
	}

	if (tmp_len != len) {
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

int ndpip_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
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

	if (level != SOL_SOCKET) {
		errno = ENOPROTOOPT;
		return -1;
	}

	switch (optname) {
		case SO_NDPIP_TCP_WIN_SCALE:
			if (optlen != 1) {
				errno = EINVAL;
				return -1;
			}

			if (sock->state != NEW) {
				errno = EINVAL;
				return -1;
			}

			sock->tcp_recv_win_scale = *((uint8_t *) optval);

			return 0;

		default:
			errno = EINVAL;
			return -1;
	}
}
