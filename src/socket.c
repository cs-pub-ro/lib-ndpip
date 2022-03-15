#include <string.h>
#include <time.h>

#include "ndpip/socket.h"
#include "ndpip/tcp.h"
#include "ndpip/util.h"
#include "ndpip/workhorse.h"


#define NDPIP_TODO_ESTABLISHED_SOCKETS_BUCKETS 1024
#define NDPIP_TODO_LISTENING_SOCKETS_BUCKETS 32
#define NDPIP_TODO_SOCKET_XMIT_RING_LENGTH (1 << 20)
#define NDPIP_TODO_SOCKET_RECV_RING_LENGTH (1 << 20)


struct ndpip_hashtable *ndpip_established_sockets = NULL;
struct ndpip_hashtable *ndpip_listening_sockets = NULL;
struct ndpip_socket **socket_table = NULL;

static int ndpip_socket_grants_get(struct ndpip_socket *sock) {
	struct ndpip_pbuf *pb;
	
	if (ndpip_sock_alloc(sock, &pb, 1, false) < 0)
		return -1;

	ndpip_pbuf_resize(pb, sizeof(struct ethhdr) + sizeof(struct eqds_cn));

	struct ethhdr *eth = ndpip_pbuf_data(pb);

	struct ether_addr *eth_src = ndpip_iface_get_ethaddr(sock->socket_iface);
	if (eth_src == NULL)
		return -1;

	uint8_t eth_dst[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

        memcpy(eth->h_dest, eth_dst, ETH_ALEN);
        memcpy(eth->h_source, eth_src, ETH_ALEN);

	eth->h_proto = htons(ETH_P_EQDSCN);

	struct eqds_cn *cn = ((void *) eth) + sizeof(struct ether_header);
	cn->destination = sock->remote.sin_addr.s_addr;
	cn->operation = CN_GRANTS_GET;

	ndpip_iface_xmit(sock->socket_iface, &pb, 1, true);

	while (sock->grants_overhead == -1)
		ndpip_usleep(1);

	return 0;
}

struct ndpip_socket *ndpip_socket_get_by_peer(struct sockaddr_in *local, struct sockaddr_in *remote)
{
	if (ndpip_established_sockets == NULL)
		return NULL;

	struct sockaddr_in key[2] = { *local, *remote };
	struct ndpip_socket *ret = ndpip_hashtable_get(ndpip_established_sockets, key, sizeof(key));
	if (ret != NULL)
		return ret;

	if (ndpip_listening_sockets == NULL)
		return NULL;

	return ndpip_hashtable_get(ndpip_listening_sockets, local, sizeof(struct sockaddr_in));
}

static struct ndpip_socket *ndpip_socket_get(int sockfd)
{
	if (socket_table == NULL)
		return NULL;

	if (sockfd < NDPIP_TODO_MAX_FDS)
		return socket_table[sockfd];

	return NULL;
}

struct ndpip_socket *ndpip_socket_new(int domain, int type, int protocol)
{
	if (!((domain == AF_INET) && (type == SOCK_NDPIP) && (protocol == IPPROTO_TCP)))
		return NULL;

	int socket_id = 0;
	for (socket_id = 0; socket_id < NDPIP_TODO_MAX_FDS; socket_id++)
		if (socket_table[socket_id] == NULL)
			break;

	if (socket_id == NDPIP_TODO_MAX_FDS)
		return NULL;

	struct ndpip_socket *sock = malloc(sizeof(struct ndpip_socket));

	sock->socket_id = socket_id;
	sock->socket_iface = NULL;
	sock->grants = 0;
	sock->grants_overhead = -1;

	sock->state = NEW;

	sock->local = (struct sockaddr_in) { .sin_family = AF_INET, .sin_addr.s_addr = 0, .sin_port = 0 };
	sock->remote = (struct sockaddr_in) { .sin_family = AF_INET, .sin_addr.s_addr = 0, .sin_port = 0 };

	sock->xmit_ring = ndpip_ring_alloc(NDPIP_TODO_SOCKET_XMIT_RING_LENGTH, sizeof(struct ndpip_pbuf *));
	sock->recv_ring = ndpip_ring_alloc(NDPIP_TODO_SOCKET_RECV_RING_LENGTH, sizeof(struct ndpip_pbuf *));

	sock->socket_timer_rto = ndpip_timer_alloc(ndpip_tcp_rto_handler, (void *) sock);
	struct timespec expire;
	ndpip_time_now(&expire);
	ndpip_timer_arm(sock->socket_timer_rto, &expire);
	ndpip_timers_add(sock->socket_timer_rto);

	sock->tcp_seq = 0;
	sock->tcp_ack = 0;
	sock->tcp_recv_win = 0;
	sock->tcp_max_seq = 0;
	sock->tcp_last_ack = 0;
	sock->tcp_good_ack = 0;
	sock->tcp_recv_win_scale = 0;
	sock->tcp_send_win_scale = 0;
	sock->tcp_recovery = false;
	sock->tcp_retransmission = false;
	sock->tcp_rto = false;
	sock->tcp_rsp_ack = false;
	sock->rx_loop_seen = false;

	sock->accept_queue = (struct ndpip_list_head) { &sock->accept_queue, &sock->accept_queue };

	socket_table[socket_id] = sock;
	return sock;
}

int ndpip_socket(int domain, int type, int protocol)
{
	if (socket_table == NULL) {
		socket_table = calloc(NDPIP_TODO_MAX_FDS, sizeof(struct ndpip_socket *));
		ndpip_established_sockets = ndpip_hashtable_alloc(NDPIP_TODO_ESTABLISHED_SOCKETS_BUCKETS);
		ndpip_listening_sockets = ndpip_hashtable_alloc(NDPIP_TODO_LISTENING_SOCKETS_BUCKETS);
	}

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

	for (size_t idx = 0; idx < NDPIP_TODO_MAX_FDS; idx++) {
		if (socket_table[idx] == NULL)
			continue;

		if (memcmp(&socket_table[idx]->local, addr_in, sizeof(struct sockaddr_in)) == 0) {
			errno = EADDRINUSE;
			return -1;
		}
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
	ndpip_hashtable_put(ndpip_listening_sockets, &sock->local, sizeof(struct sockaddr_in), sock);

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

	/*
	if (ndpip_socket_grants_get(sock) < 0) {
		sock->state = CLOSED;
		errno = EFAULT;
		return -1;
	}
	*/

	sock->state = CONNECTING;

	struct ndpip_pbuf *pb;
	
	if (ndpip_sock_alloc(sock, &pb, 1, false) < 0) {
		errno = EFAULT;
		return -1;
	}

	if (ndpip_tcp_build_syn(sock, false, pb) < 0) {
		sock->state = CLOSED;
		errno = EFAULT;
		return -1;
	}

	sock->tcp_last_ack = sock->tcp_seq;
	sock->tcp_seq++;

	struct sockaddr_in key[2] = { sock->local, sock->remote };
	ndpip_hashtable_put(ndpip_established_sockets, key, sizeof(key), sock);
	ndpip_tcp_send(sock, &pb, 1);

	while (sock->state == CONNECTING)
		ndpip_usleep(1);

	if (sock->state != CONNECTED) {
		errno = ECONNREFUSED;
		return -1;
	}

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

	// ndpip_socket_grants_get(asock);

	while (asock->state != CONNECTED)
		ndpip_usleep(1);

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

	if (sock->state != CONNECTED) {
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

int ndpip_close(int sockfd)
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

	struct ndpip_pbuf *pb;

	if (ndpip_sock_alloc(sock, &pb, 1, false) < 0) {
		errno = EFAULT;
		return -1;
	}

	if (ndpip_tcp_build_meta(sock, TH_FIN, pb) < 0) {
		errno = EFAULT;
		return -1;
	}

	sock->state = CLOSING;
	ndpip_tcp_send(sock, &pb, 1);

	while (sock->state == CLOSING)
		ndpip_usleep(1);

	if (sock->state != CLOSED) {
		errno = ECONNREFUSED;
		return -1;
	}

	return 0;
}
