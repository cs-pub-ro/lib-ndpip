#include <string.h>
#include <time.h>

#include "ndpip/socket.h"
#include "ndpip/tcp.h"
#include "ndpip/util.h"


#define NDPIP_TODO_SOCKET_XMIT_RING_LENGTH 1024


static NDPIP_LIST_HEAD(ndpip_sockets_head);

static int last_socket_id = 0;


struct ndpip_socket *ndpip_socket_get_by_peer(struct sockaddr_in *local, struct sockaddr_in *remote)
{
	struct ndpip_socket *ret = NULL;

	ndpip_list_foreach(struct ndpip_socket, sock, &ndpip_sockets_head) {
		if ((sock->local.sin_addr.s_addr == local->sin_addr.s_addr) &&
			(sock->local.sin_port == local->sin_port)) {

			if (((sock->state == CONNECTING) || (sock->state == CONNECTED)) &&
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

	sock->xmit_ring = ndpip_pbuf_ring_alloc(NDPIP_TODO_SOCKET_XMIT_RING_LENGTH);
	sock->xmit_ring_unsent_off = 0;
	sock->xmit_ring_unsent_train_off = 0;

	sock->socket_timer_rto = ndpip_timer_alloc(ndpip_tcp_rto_handler, (void *) sock);
	ndpip_timers_add(sock->socket_timer_rto);

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
	if (sockfd < 0)
		return -EBADF;

	struct ndpip_socket *sock = ndpip_socket_get(sockfd);
	if (sock == NULL)
		return -ENOTSOCK;

	if (sock->state != NEW)
		return -EINVAL;

	if (addr->sa_family != AF_INET)
		return -EINVAL;

	if (addrlen != sizeof(struct sockaddr_in))
		return -EINVAL;

	struct sockaddr_in *addr_in = (void *) addr;

	ndpip_list_foreach(struct ndpip_socket, sock, &ndpip_sockets_head)
		if ((memcmp(&sock->local.sin_addr, &addr_in->sin_addr, sizeof(struct sockaddr_in)) == 0)
			&& (sock->local.sin_port == addr_in->sin_port))
			return -EADDRINUSE;

	sock->local.sin_addr = addr_in->sin_addr;
	sock->local.sin_port = addr_in->sin_port;

	sock->socket_iface = ndpip_iface_get_by_inaddr(sock->local.sin_addr);

	sock->state = BOUND;

	return 0;
}

int listen(int sockfd, int backlog)
{
	(void) backlog;

	if (sockfd < 0)
		return -EBADF;

	struct ndpip_socket *sock = ndpip_socket_get(sockfd);
	if (sock == NULL)
		return -ENOTSOCK;

	if (sock->state != BOUND)
		return -EADDRINUSE;

	sock->state = LISTENING;

	return 0;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	if (sockfd < 0)
		return -EBADF;

	struct ndpip_socket *sock = ndpip_socket_get(sockfd);
	if (sock == NULL)
		return -ENOTSOCK;

	if (sock->state != BOUND)
		return -EADDRINUSE;

	if (addrlen != sizeof(struct sockaddr_in))
		return -EINVAL;

	struct sockaddr_in *addr_in = (void *) addr;

	sock->remote.sin_addr = addr_in->sin_addr;
	sock->remote.sin_port = addr_in->sin_port;

	if (ndpip_tcp_build_xmit_template(sock) < 0)
		return -1;

	sock->state = CONNECTING;

	if (ndpip_tcp_send_meta(sock, TH_SYN) == 0)
		return 0;

	sock->state = CLOSED;

	return -1;
}
