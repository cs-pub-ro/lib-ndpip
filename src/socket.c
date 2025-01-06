#include <string.h>
#include <time.h>

#include <fcntl.h>

#include "ndpip/socket.h"
#include "ndpip/udp.h"
#include "ndpip/tcp.h"
#include "ndpip/util.h"
#include "ndpip/workhorse.h"


#define NDPIP_TCP_DEFAULT_MSS 1460
#define NDPIP_UDP_DEFAULT_MSS 1472
#define NDPIP_MIN_UNPRIV_PORT 1024
#define NDPIP_MAX_LOCAL_PORT_RETRIES 1024

#define NDPIP_TODO_READ_MAX_PBS (1 << 17)

#define NDPIP_TODO_ESTABLISHED_SOCKETS_BUCKETS 65536
#define NDPIP_TODO_LISTENING_SOCKETS_BUCKETS 1024

#define NDPIP_EQDS_GRANTS_OVERHEAD 60


static int ndpip_sock_bind(struct ndpip_socket *sock, const struct sockaddr *addr);
static int ndpip_sock_listen(struct ndpip_socket *sock);
static int ndpip_sock_connect(struct ndpip_socket *sock, const struct sockaddr *addr);
static int ndpip_sock_accept(struct ndpip_socket *sock, struct sockaddr *addr, socklen_t *addrlen);
static int ndpip_sock_send(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t count);
static int ndpip_sock_recv(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t count);
static int ndpip_sock_write(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t count);
static ssize_t ndpip_sock_read(struct ndpip_socket *sock, void *buf, size_t count);
static int ndpip_sock_prepare(struct ndpip_socket *sock, struct ndpip_pbuf *pb);
static int ndpip_sock_setsockopt(struct ndpip_socket *sock, int optname, const void *optval, socklen_t optlen);
static int ndpip_sock_getsockopt(struct ndpip_socket *sock, int optname, const void *optval, socklen_t optlen);
static int ndpip_sock_close(struct ndpip_socket *sock);
static int ndpip_sock_buf2pbuf(struct ndpip_socket *sock, void *buf, size_t len, struct ndpip_pbuf ***pb);
static ssize_t ndpip_sock_can_send(struct ndpip_socket *sock);

struct ndpip_hashtable *ndpip_tcp_established_sockets = NULL;
struct ndpip_hashtable *ndpip_tcp_listening_sockets = NULL;

struct ndpip_hashtable *ndpip_udp_established_sockets = NULL;
struct ndpip_hashtable *ndpip_udp_listening_sockets = NULL;

struct ndpip_socket **socket_table = NULL;

#ifdef NDPIP_GRANTS_ENABLE
int ndpip_socket_grants_get(struct ndpip_socket *sock, uint32_t grants)
{
	struct ndpip_pbuf *pb;
	
	if (ndpip_sock_alloc(sock, &pb, 1, false) < 0)
		return -1;

	assert(ndpip_pbuf_offset(pb, sizeof(struct ethhdr) + sizeof(struct eqds_cn)) >= 0);

	struct ethhdr *eth = ndpip_pbuf_data(pb);

	struct ether_addr *eth_src = ndpip_iface_get_ethaddr(sock->iface);
	if (eth_src == NULL)
		return -1;

	uint8_t eth_dst[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

	memcpy(eth->h_dest, eth_dst, ETH_ALEN);
	memcpy(eth->h_source, eth_src, ETH_ALEN);

	eth->h_proto = htons(ETH_P_EQDSCN);

	struct eqds_cn *cn = ((void *) eth) + sizeof(struct ether_header);
	cn->destination = sock->remote.sin_addr.s_addr;
	cn->operation = CN_GRANTS_GET;
	cn->value1 = htonl(grants);

	ndpip_iface_xmit(sock->iface, &pb, 1, true);

	return 0;
}
#endif

static struct ndpip_socket *ndpip_socket_get(int sockfd)
{
	if ((sockfd >= 0) && (sockfd < NDPIP_TODO_MAX_FDS))
		return socket_table[sockfd];

	return NULL;
}

struct ndpip_socket *ndpip_socket_new(int domain, int type, int protocol)
{
	if (!((domain == AF_INET) &&
		(type & SOCK_NDPIP) &&
		((protocol == IPPROTO_TCP) || (protocol == IPPROTO_UDP))))

		return NULL;

	int socket_id = 0;
	for (socket_id = 0; socket_id < NDPIP_TODO_MAX_FDS; socket_id++)
		if (socket_table[socket_id] == NULL)
			break;

	if (socket_id == NDPIP_TODO_MAX_FDS)
		return NULL;

	struct ndpip_socket *sock;
	if (protocol == IPPROTO_TCP)
		sock = malloc(sizeof(struct ndpip_tcp_socket));

	else if (protocol == IPPROTO_UDP)
		sock = malloc(sizeof(struct ndpip_udp_socket));

	else
		return NULL;

	sock->socket_id = socket_id;
	sock->protocol = protocol;
	sock->iface = NULL;
#ifdef NDPIP_GRANTS_ENABLE
	sock->grants = 0;
	sock->grants_overhead = NDPIP_EQDS_GRANTS_OVERHEAD;
	sock->grants_overcommit = 0;
#endif

	sock->local = (struct sockaddr_in) { .sin_family = AF_INET, .sin_addr.s_addr = 0, .sin_port = 0 };
	sock->remote = (struct sockaddr_in) { .sin_family = AF_INET, .sin_addr.s_addr = 0, .sin_port = 0 };

	sock->xmit_ring = ndpip_ring_alloc(NDPIP_SOCKET_XMIT_RING_LENGTH);
	sock->recv_ring = ndpip_ring_alloc(NDPIP_SOCKET_RECV_RING_LENGTH);

	sock->rx_loop_seen = false;
	sock->flags = 0;

	if (type & SOCK_NONBLOCK)
		sock->flags |= O_NONBLOCK;

	ndpip_mutex_init(&sock->lock);

	if (protocol == IPPROTO_TCP) {
		sock->tx_mss = NDPIP_TCP_DEFAULT_MSS;

		struct ndpip_tcp_socket *tcp_sock = (struct ndpip_tcp_socket *) sock;
		tcp_sock->state = NEW;

		tcp_sock->timer_rto = ndpip_timer_alloc(ndpip_tcp_rto_handler, (void *) sock);
		ndpip_timer_disarm(tcp_sock->timer_rto);
		ndpip_timers_add(tcp_sock->timer_rto);

		tcp_sock->tcp_seq = 0;
		tcp_sock->tcp_ack = 0;
		tcp_sock->tcp_ack_inc = 0;
		tcp_sock->tcp_recv_win = 0;
		tcp_sock->tcp_max_seq = 0;
		tcp_sock->tcp_last_ack = 0;
		tcp_sock->tcp_recv_win_scale = 0;
		tcp_sock->tcp_send_win_scale = 0;
		tcp_sock->tcp_rto = false;
		tcp_sock->tcp_rsp_ack = false;
		tcp_sock->tcp_req_ack = false;

		tcp_sock->rx_mss = NDPIP_TCP_DEFAULT_MSS;

		ndpip_list_init(&tcp_sock->accept_queue);
		tcp_sock->parent_socket = NULL;
	}

	if (protocol == IPPROTO_UDP) {
		sock->tx_mss = NDPIP_UDP_DEFAULT_MSS;
	}

	socket_table[socket_id] = sock;
	return sock;
}

void ndpip_socket_init(void)
{
	socket_table = calloc(NDPIP_TODO_MAX_FDS, sizeof(struct ndpip_socket *));
	ndpip_tcp_established_sockets = ndpip_hashtable_alloc(NDPIP_TODO_ESTABLISHED_SOCKETS_BUCKETS);
	ndpip_tcp_listening_sockets = ndpip_hashtable_alloc(NDPIP_TODO_LISTENING_SOCKETS_BUCKETS);
	ndpip_udp_established_sockets = ndpip_hashtable_alloc(NDPIP_TODO_ESTABLISHED_SOCKETS_BUCKETS);
	ndpip_udp_listening_sockets = ndpip_hashtable_alloc(NDPIP_TODO_LISTENING_SOCKETS_BUCKETS);
}

int ndpip_socket(int domain, int type, int protocol)
{
	struct ndpip_socket *sock = ndpip_socket_new(domain, type, protocol);
	if (sock == NULL)
		return -1;

	return sock->socket_id;
}

#ifdef NDPIP_GRANTS_ENABLE
int ndpip_grants_get(int sockfd, uint32_t grants)
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
	
	return ndpip_socket_grants_get(sock, grants);
}
#endif

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

	if (addr->sa_family != AF_INET) {
		errno = EINVAL;
		return -1;
	}

	if (addrlen != sizeof(struct sockaddr_in)) {
		errno = EINVAL;
		return -1;
	}

	ndpip_mutex_lock(&sock->lock);
	int ret = ndpip_sock_bind(sock, addr);
	ndpip_mutex_unlock(&sock->lock);

	return ret;
}

static int ndpip_sock_bind(struct ndpip_socket *sock, const struct sockaddr *addr)
{
	sock->local = *((struct sockaddr_in *) addr);
	sock->iface = ndpip_iface_get_by_inaddr(sock->local.sin_addr);

	sock->recv_tmp = malloc(sizeof(struct ndpip_pbuf *) * ndpip_iface_get_burst_size(sock->iface));
	sock->feed_tmp = malloc(sizeof(struct ndpip_pbuf *) * ndpip_iface_get_burst_size(sock->iface));

	sock->feed_tmp_len = 0;
	sock->recv_tmp_len = 0;

	if (sock->protocol == IPPROTO_TCP) {
		struct ndpip_tcp_socket *tcp_sock = (struct ndpip_tcp_socket *) sock;

		if (tcp_sock->state != NEW) {
			errno = EINVAL;
			return -1;
		}
		
		tcp_sock->state = BOUND;
	}

	if (sock->protocol == IPPROTO_UDP) {
		uint32_t hash = ndpip_socket_listening_hash(&sock->local);
		ndpip_hashtable_put(ndpip_udp_listening_sockets, hash, sock);
	}

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

	ndpip_mutex_lock(&sock->lock);
	int ret = ndpip_sock_listen(sock);
	ndpip_mutex_unlock(&sock->lock);

	return ret;
}

static int ndpip_sock_listen(struct ndpip_socket *sock)
{
	if (sock->protocol != IPPROTO_TCP) {
		errno = EOPNOTSUPP;
		return -1;
	}

	struct ndpip_tcp_socket *tcp_sock = (struct ndpip_tcp_socket *) sock;

	if (tcp_sock->state != BOUND) {
		errno = EADDRINUSE;
		return -1;
	}

	uint32_t hash = ndpip_socket_listening_hash(&sock->local);
	struct ndpip_socket *csock = ndpip_hashtable_get(ndpip_tcp_listening_sockets, hash);
	if ((csock != NULL) && (csock != sock)) {
		errno = EADDRINUSE;
		return -1;
	}

	tcp_sock->state = LISTENING;

	ndpip_hashtable_put(ndpip_tcp_listening_sockets, hash, sock);

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

	if (addrlen != sizeof(struct sockaddr_in)) {
		errno = EINVAL;
		return -1;
	}

	ndpip_mutex_lock(&sock->lock);
	int ret = ndpip_sock_connect(sock, addr);
	ndpip_mutex_unlock(&sock->lock);

	return ret;
}

static int ndpip_sock_connect(struct ndpip_socket *sock, const struct sockaddr *addr)
{
	sock->remote = *((struct sockaddr_in *) addr);

	struct ndpip_hashtable *htable;

	if (sock->protocol == IPPROTO_UDP)
		htable = ndpip_udp_established_sockets;

	else if (sock->protocol == IPPROTO_TCP)
		htable = ndpip_tcp_established_sockets;

	else
		return -1;

	if (sock->local.sin_port == 0) {
		int idx = 0;
		for (; idx < NDPIP_MAX_LOCAL_PORT_RETRIES; idx++) {
			sock->local.sin_port = htons(NDPIP_MIN_UNPRIV_PORT + (random() % (UINT16_MAX - NDPIP_MIN_UNPRIV_PORT + 1)));
			uint32_t hash = ndpip_socket_established_hash(&sock->local, &sock->remote);

			if (ndpip_hashtable_get(htable, hash) == NULL)
				break;
		}

		if (idx == NDPIP_MAX_LOCAL_PORT_RETRIES) {
			errno = EADDRINUSE;
			return -1;
		}
	} else {
		uint32_t hash = ndpip_socket_established_hash(&sock->local, &sock->remote);

		if (ndpip_hashtable_get(htable, hash) != NULL) {
			errno = EADDRINUSE;
			return -1;
		}
	}

	if (sock->protocol == IPPROTO_TCP)
		return ndpip_tcp_connect((struct ndpip_tcp_socket *) sock);

	if (sock->protocol == IPPROTO_UDP)
		return ndpip_udp_connect((struct ndpip_udp_socket *) sock);

	errno = EOPNOTSUPP;
	return -1;
}

int ndpip_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
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

	ndpip_mutex_lock(&sock->lock);
	int ret = ndpip_sock_accept(sock, addr, addrlen);
	ndpip_mutex_unlock(&sock->lock);

	return ret;
}

static int ndpip_sock_accept(struct ndpip_socket *sock, struct sockaddr *addr, socklen_t *addrlen)
{
	if (sock->protocol != IPPROTO_TCP) {
		errno = EOPNOTSUPP;
		return -1;
	}

	struct ndpip_socket *asock = (struct ndpip_socket *) ndpip_tcp_accept((struct ndpip_tcp_socket *) sock);
	if (asock == NULL)
		return -1;

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

	if (count == 0) {
		errno = EINVAL;
		return -1;
	}

	int ret = ndpip_sock_recv(sock, pb, count);

	return ret;
}

static int ndpip_sock_recv(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t count)
{
	size_t rcount = count;
	if (ndpip_ring_pop(sock->recv_ring, &rcount, pb) < 0) {
		errno = EAGAIN;

		if (sock->protocol == IPPROTO_TCP) {
			struct ndpip_tcp_socket *tcp_sock = (struct ndpip_tcp_socket *) sock;

			if (tcp_sock->state != CONNECTED)
				errno = EINVAL;
		}

		return -1;
	}
	
	return rcount;
}

static ssize_t ndpip_sock_can_send(struct ndpip_socket *sock)
{
	if (sock->protocol == IPPROTO_TCP)
		return ndpip_tcp_can_send((struct ndpip_tcp_socket *) sock);

	if (sock->protocol == IPPROTO_UDP)
		return ndpip_udp_can_send((struct ndpip_udp_socket *) sock);

	errno = EOPNOTSUPP;
	return -1;
}

ssize_t ndpip_write(int sockfd, void *buf, size_t len)
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

	if (len == 0) {
		errno = EINVAL;
		return -1;
	}

	if (buf == NULL) {
		printf("%d: EFAULT\n", __LINE__);
		errno = EFAULT;
		return -1;
	}

	ssize_t can_send = ndpip_sock_can_send(sock);
	if (can_send < 0)
		return -1;

	len = len < can_send ? len : can_send;
	if (len == 0)
		return 0;

	struct ndpip_pbuf **pbs;
	int count = ndpip_sock_buf2pbuf(sock, buf, len, &pbs);
	if (count < 0)
		return -1;

	ssize_t ret = ndpip_sock_write(sock, pbs, count);
	if (ret < 0)
		goto ret;

	ret = len;

ret:
	free(pbs);
	return ret;
}

static int ndpip_sock_write(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t count)
{
	if (sock->protocol == IPPROTO_TCP)
		return ndpip_tcp_write((struct ndpip_tcp_socket *) sock, pb, count);

	if (sock->protocol == IPPROTO_UDP)
		return ndpip_udp_write((struct ndpip_udp_socket *) sock, pb, count);

	errno = EOPNOTSUPP;
	return -1;
}

static int ndpip_sock_buf2pbuf(struct ndpip_socket *sock, void *buf, size_t len, struct ndpip_pbuf ***pbs_ret)
{
	uint16_t tx_mss = sock->tx_mss;
	size_t count = len / tx_mss;
	size_t len2 = count * tx_mss;
	uint16_t remainder = 0;
	if (len2 < len) {
		count++;
		remainder = len - len2;
	}

	if (count == 0) {
		errno = EINVAL;
		return -1;
	}

	struct ndpip_pbuf **pbs = malloc(count * sizeof(struct ndpip_pbuf *));
	if (pbs == NULL)
		return -1;

	int r = ndpip_sock_alloc(sock, pbs, count, false);
	if (r < 0) {
		free(pbs);
		return -1;
	}

	for (size_t idx = 0; idx < count - 1; idx++) {
		ndpip_pbuf_resize(pbs[idx], tx_mss);
		memcpy(ndpip_pbuf_data(pbs[idx]), buf, tx_mss);
		ndpip_sock_prepare(sock, pbs[idx]);
		buf += tx_mss;
	}

	if (remainder == 0) {
		ndpip_pbuf_resize(pbs[count - 1], tx_mss);
		memcpy(ndpip_pbuf_data(pbs[count - 1]), buf, tx_mss);
		ndpip_sock_prepare(sock, pbs[count - 1]);
	} else {
		ndpip_pbuf_resize(pbs[count -1], tx_mss);
		memcpy(ndpip_pbuf_data(pbs[count - 1]), buf, remainder);
		ndpip_sock_prepare(sock, pbs[count - 1]);
	}

	*pbs_ret = pbs;
	return count;
}

ssize_t ndpip_read(int sockfd, void *buf, size_t len)
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

	if (len == 0) {
		errno = EINVAL;
		return -1;
	}

	if (buf == NULL) {
		errno = EFAULT;
		return -1;
	}

	return ndpip_sock_read(sock, buf, len);
}

ssize_t ndpip_sock_read(struct ndpip_socket *sock, void *buf, size_t len)
{
	size_t count = ndpip_ring_size(sock->recv_ring);
                
	if ((count == 0) && (sock->protocol == IPPROTO_TCP)) {
		struct ndpip_tcp_socket *tcp_sock = (struct ndpip_tcp_socket *) sock;
                        
		if (tcp_sock->state != CONNECTED) {
			errno = EINVAL;
			return -1;
		}
	}

	struct ndpip_pbuf **pbs = malloc(count * sizeof(struct ndpip_pbuf *));
	ndpip_ring_peek(sock->recv_ring, &count, pbs);

	ssize_t ret = 0;
	size_t idx = 0;
	for (; idx < count; idx++) {
		struct ndpip_pbuf *pb = pbs[idx];
		uint16_t data_len = ndpip_pbuf_length(pb);

		if ((ret + data_len) > len) {
			uint16_t remainder = len - ret;
			memcpy(buf + ret, ndpip_pbuf_data(pb), remainder);
			assert(ndpip_pbuf_offset(pb, -remainder) >= 0);
			ret += remainder;
		} else {
			memcpy(buf + ret, ndpip_pbuf_data(pb), data_len);
			ret += data_len;
		}

		if (ret == len)
			break;

		assert(ret < len);
	}

	ndpip_ring_flush(sock->recv_ring, idx);
	ndpip_sock_free(sock, pbs, idx);
	free(pbs);

	return ret;
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

	if (count == 0) {
		errno = EINVAL;
		return -1;
	}

	int ret = ndpip_sock_send(sock, pb, count);

	return ret;
}

static int ndpip_sock_send(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t count)
{
	if (sock->protocol == IPPROTO_TCP)
		return ndpip_tcp_send((struct ndpip_tcp_socket *) sock, pb, count);

	if (sock->protocol == IPPROTO_UDP)
		return ndpip_udp_send((struct ndpip_udp_socket *) sock, pb, count);

	errno = EOPNOTSUPP;
	return -1;
}

int ndpip_free(int sockfd, struct ndpip_pbuf **pb, size_t len)
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

	return ndpip_sock_free(sock, pb, len);
}

size_t ndpip_alloc(int sockfd, struct ndpip_pbuf **pb, size_t len)
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

	if (len == 0)
		return 0;

	int ret = ndpip_sock_alloc(sock, pb, len, false);

	return ret;
}

#ifdef NDPIP_GRANTS_ENABLE
static int ndpip_sock_cost(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t len, uint16_t *pb_cost);

uint16_t ndpip_socket_pbuf_cost(struct ndpip_socket *sock, struct ndpip_pbuf *pb)
{
	uint16_t transport_overhead = 0;
	if (sock->protocol == IPPROTO_TCP)
		transport_overhead = sizeof(struct tcphdr);

	if (sock->protocol == IPPROTO_UDP)
		transport_overhead = sizeof(struct udphdr);

	if (pb == NULL)
		return sock->grants_overhead + sizeof(struct ethhdr) + sizeof(struct iphdr) + transport_overhead;

	return sock->grants_overhead + sizeof(struct ethhdr) + sizeof(struct iphdr) + transport_overhead + ndpip_pbuf_length(pb);
}

int ndpip_cost(int sockfd, struct ndpip_pbuf **pb, uint16_t len, uint16_t *pb_cost)
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

	int ret = ndpip_sock_cost(sock, pb, len);

	return ret;
}

static int ndpip_sock_cost(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t len, uint16_t *pb_cost)
{
	if (sock->grants_overhead < 0) {
		errno = EINVAL;
		return -1;
	}

	for (uint16_t idx = 0; idx < len; idx++) {
		pb_cost[idx] = ndpip_socket_pbuf_cost(sock, pb[idx]);
	}

	return 0;
}
#endif

int ndpip_sock_free(struct ndpip_socket *sock, struct ndpip_pbuf **pb, size_t len)
{
	if (len == 0)
		return 0;

	if (ndpip_pbuf_release(pb, len) < 0) {
		printf("%d: EFAULT\n", __LINE__);
		errno = EFAULT;
		return -1;
	}

	return 0;
}

ssize_t ndpip_sock_alloc(struct ndpip_socket *sock, struct ndpip_pbuf **pb, size_t len, bool rx)
{
	struct ndpip_pbuf_pool *pool = NULL;
	
	if (rx)
		pool = ndpip_iface_get_pbuf_pool_rx(sock->iface);
	else
		pool = ndpip_iface_get_pbuf_pool_tx(sock->iface);

	if (pool == NULL) {
		errno = EFAULT;
		return -1;
	}

	if (ndpip_pbuf_pool_request(pool, pb, len) < 0) {
		errno = ENOMEM;
		return -1;
	}

	return len;
}

int ndpip_prepare(int sockfd, struct ndpip_pbuf *pb)
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

	return ndpip_sock_prepare(sock, pb);
}

static int ndpip_sock_prepare(struct ndpip_socket *sock, struct ndpip_pbuf *pb)
{
	if (sock->protocol == IPPROTO_TCP)
		ndpip_tcp_prepare_send((struct ndpip_tcp_socket *) sock, pb);

	if (sock->protocol == IPPROTO_UDP)
		ndpip_udp_prepare_send((struct ndpip_udp_socket *) sock, pb);

	return 0;
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

	ndpip_mutex_lock(&sock->lock);
	int ret = ndpip_sock_setsockopt(sock, optname, optval, optlen);
	ndpip_mutex_unlock(&sock->lock);

	return ret;
}

static int ndpip_sock_setsockopt(struct ndpip_socket *sock, int optname, const void *optval, socklen_t optlen)
{
	struct ndpip_tcp_socket *tcp_sock = (struct ndpip_tcp_socket *) sock;
	int mss;

	switch (optname) {
		case SO_NDPIP_TCP_WIN_SCALE:
			if (sock->protocol != IPPROTO_TCP) {
				errno = EINVAL;
				return -1;
			}

			if (optlen != 1) {
				errno = EINVAL;
				return -1;
			}

			if (tcp_sock->state != NEW) {
				errno = EINVAL;
				return -1;
			}

			tcp_sock->tcp_recv_win_scale = *((uint8_t *) optval);

			return 0;

		case SO_NDPIP_MAX_TX_SEG:
			if (optlen != sizeof(int)) {
				errno = EINVAL;
				return -1;
			}

			mss = *(int *) optval;

			if ((mss <= 0) ||
				((mss > NDPIP_TCP_DEFAULT_MSS) && sock->protocol == IPPROTO_TCP) ||
				((mss > NDPIP_UDP_DEFAULT_MSS) && sock->protocol == IPPROTO_UDP)) {

				errno = EINVAL;
				return -1;
			}

			sock->tx_mss = mss;

			return 0;

		case SO_NDPIP_TCP_MAX_RX_SEG:
			if (optlen != sizeof(int)) {
				errno = EINVAL;
				return -1;
			}

			if (sock->protocol != IPPROTO_TCP) {
				errno = EINVAL;
				return -1;
			}

			mss = *(int *) optval;

			if ((mss <= 0) || (mss > NDPIP_TCP_DEFAULT_MSS)) {
				errno = EINVAL;
				return -1;
			}

			tcp_sock->rx_mss = mss;

			return 0;

		default:
			errno = EINVAL;
			return -1;
	}
}

int ndpip_getsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
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

	ndpip_mutex_lock(&sock->lock);
	int ret = ndpip_sock_getsockopt(sock, optname, optval, optlen);
	ndpip_mutex_unlock(&sock->lock);

	return ret;
}

static int ndpip_sock_getsockopt(struct ndpip_socket *sock, int optname, const void *optval, socklen_t optlen)
{
	switch (optname) {
#ifdef NDPIP_GRANTS_ENABLE
		case SO_NDPIP_GRANTS:
			if (sock->protocol != IPPROTO_TCP) {
				errno = EINVAL;
				return -1;
			}

			if (optlen != sizeof(size_t)) {
				errno = EINVAL;
				return -1;
			}

			struct ndpip_tcp_socket *tcp_sock = (struct ndpip_tcp_socket *) sock;

			if (tcp_sock->state != CONNECTED) {
				errno = EINVAL;
				return -1;
			}

			size_t grants = ndpip_iface_get_burst_size(sock->iface) *
					ndpip_iface_get_mtu(sock->iface);

			grants = grants < sock->grants ? grants : sock->grants;

			size_t win_size = tcp_sock->tcp_max_seq - tcp_sock->tcp_seq;
			grants = grants < win_size ? grants : win_size;

			*((size_t *) optval) = grants;

			return 0;
#endif

		case SO_NDPIP_BURST:
			if (optlen != sizeof(uint16_t)) {
				errno = EINVAL;
				return -1;
			}

			*((uint16_t *) optval) = ndpip_iface_get_burst_size(sock->iface);

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

	socket_table[sockfd] = NULL;

	ndpip_mutex_lock(&sock->lock);
	int ret = ndpip_sock_close(sock);
	ndpip_mutex_unlock(&sock->lock);

	return ret;
}

static int ndpip_sock_close(struct ndpip_socket *sock)
{
	if (sock->protocol == IPPROTO_TCP)
		return ndpip_tcp_close((struct ndpip_tcp_socket *) sock);

	if (sock->protocol == IPPROTO_UDP)
		return ndpip_udp_close((struct ndpip_udp_socket *) sock);

	errno = ENOTSOCK;
	return -1;
}

#define NDPIP_XXH32_PRIME2 2246822519U
#define NDPIP_XXH32_PRIME3 3266489917U
#define NDPIP_XXH32_PRIME4  668265263U
#define NDPIP_XXH32_PRIME5  374761393U

#define NDPIP_XXH32_ROTL(x, bits) (((x) << (bits)) | ((x) >> (32 - (bits))))
#define NDPIP_XXH32_FINISH(x) do \
{ \
	x ^= x >> 15; \
	x *= NDPIP_XXH32_PRIME2; \
	\
	x ^= x >> 13; \
	x *= NDPIP_XXH32_PRIME3; \
	\
	x ^= x >> 16; \
} while (0)

uint32_t ndpip_socket_established_hash(struct sockaddr_in *local, struct sockaddr_in *remote)
{
	uint32_t ret = NDPIP_XXH32_PRIME5;

	uint32_t saddr = local->sin_addr.s_addr;
	uint32_t daddr = remote->sin_addr.s_addr;
	uint32_t ports = local->sin_port << 16 | remote->sin_port;

	ret = NDPIP_XXH32_ROTL(ret + saddr * NDPIP_XXH32_PRIME3, 17) * NDPIP_XXH32_PRIME4;
	ret = NDPIP_XXH32_ROTL(ret + daddr * NDPIP_XXH32_PRIME3, 17) * NDPIP_XXH32_PRIME4;
	ret = NDPIP_XXH32_ROTL(ret + ports * NDPIP_XXH32_PRIME3, 17) * NDPIP_XXH32_PRIME4;
	
	NDPIP_XXH32_FINISH(ret);

	return ret;
}

uint32_t ndpip_socket_listening_hash(struct sockaddr_in *local)
{
	uint32_t ret = NDPIP_XXH32_PRIME5;

	uint32_t saddr = local->sin_addr.s_addr;
	uint32_t ports = local->sin_port;

	ret = NDPIP_XXH32_ROTL(ret + saddr * NDPIP_XXH32_PRIME3, 17) * NDPIP_XXH32_PRIME4;
	ret = NDPIP_XXH32_ROTL(ret + ports * NDPIP_XXH32_PRIME3, 17) * NDPIP_XXH32_PRIME4;
	
	NDPIP_XXH32_FINISH(ret);

	return ret;
}

struct ndpip_socket *ndpip_socket_get_by_peer(struct sockaddr_in *local, struct sockaddr_in *remote, int protocol)
{
	uint32_t hash1 = ndpip_socket_established_hash(local, remote);

	if (protocol == IPPROTO_TCP) {
		struct ndpip_socket *ret = ndpip_hashtable_get(ndpip_tcp_established_sockets, hash1);
		if (ret != NULL)
			return ret;

		uint32_t hash2 = ndpip_socket_listening_hash(local);
		return ndpip_hashtable_get(ndpip_tcp_listening_sockets, hash2);
	}

	if (protocol == IPPROTO_UDP) {
		struct ndpip_socket *ret = ndpip_hashtable_get(ndpip_udp_established_sockets, hash1);
		if (ret != NULL)
			return ret;

		uint32_t hash2 = ndpip_socket_listening_hash(local);
		return ndpip_hashtable_get(ndpip_udp_listening_sockets, hash2);
	}

	return NULL;
}

uint32_t ndpip_socket_poll(struct ndpip_socket *sock)
{
	uint32_t ret = 0;

	if (sock->protocol == IPPROTO_TCP) {
		struct ndpip_tcp_socket *tcp_sock = (void *) sock;
		ret = ndpip_tcp_poll(tcp_sock);
	}

	if (sock->protocol == IPPROTO_UDP) {
		struct ndpip_udp_socket *udp_sock = (void *) sock;
		ret = ndpip_udp_poll(udp_sock);
	}

	return ret;
}

/*
void ndpip_sock_grants_dec(struct ndpip_socket *sock, uint32_t gen, uint32_t val)
{
	struct _Atomic ndpip_socket_grants tmp_grants = sock->grants;

	if (tmp_grants.generation != gen)
		return;

	sock->grants -= val;
}
*/
