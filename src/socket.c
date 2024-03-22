#include <string.h>
#include <time.h>

#include <fcntl.h>

#include "ndpip/socket.h"
#include "ndpip/udp.h"
#include "ndpip/tcp.h"
#include "ndpip/util.h"
#include "ndpip/workhorse.h"


#define NDPIP_TCP_DEFAULT_MSS (ETH_DATA_LEN - (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
#define NDPIP_UDP_DEFAULT_MSS (ETH_DATA_LEN - (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr)))

#define NDPIP_TODO_ESTABLISHED_SOCKETS_BUCKETS 1024
#define NDPIP_TODO_LISTENING_SOCKETS_BUCKETS 32

#define NDPIP_EQDS_GRANTS_OVERHEAD 60


struct ndpip_hashtable *ndpip_tcp_established_sockets = NULL;
struct ndpip_hashtable *ndpip_tcp_listening_sockets = NULL;

struct ndpip_hashtable *ndpip_udp_established_sockets = NULL;
struct ndpip_hashtable *ndpip_udp_listening_sockets = NULL;

struct ndpip_socket **socket_table = NULL;

#ifdef NDPIP_GRANTS_ENABLE
int ndpip_socket_grants_get(struct ndpip_socket *sock, uint32_t grants) {
	struct ndpip_pbuf *pb;
	
	if (ndpip_sock_alloc(sock, &pb, 1, false) == 0)
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
	if (sockfd < NDPIP_TODO_MAX_FDS)
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

	if (protocol == IPPROTO_TCP) {
		sock->tx_mss = NDPIP_TCP_DEFAULT_MSS;

		struct ndpip_tcp_socket *tcp_sock = (struct ndpip_tcp_socket *) sock;
		tcp_sock->state = NEW;

		tcp_sock->timer_rto = ndpip_timer_alloc(ndpip_tcp_rto_handler, (void *) sock);
		ndpip_timer_disarm(tcp_sock->timer_rto);
		ndpip_timers_add(tcp_sock->timer_rto);

		tcp_sock->tcp_seq = 0;
		tcp_sock->tcp_ack = 0;
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
		ndpip_mutex_init(&tcp_sock->accept_queue_lock);
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

	sock->local = *((struct sockaddr_in *) addr);
	sock->iface = ndpip_iface_get_by_inaddr(sock->local.sin_addr);
	sock->recv_tmp = malloc(sizeof(struct ndpip_pbuf *) * ndpip_iface_get_burst_size(sock->iface));
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

	if (sock->protocol != IPPROTO_TCP) {
		errno = EOPNOTSUPP;
		return -1;
	}

	struct ndpip_tcp_socket *tcp_sock = (struct ndpip_tcp_socket *) sock;

	if (tcp_sock->state != BOUND) {
		errno = EADDRINUSE;
		return -1;
	}

	for (size_t idx = 0; idx < NDPIP_TODO_MAX_FDS; idx++) {
		if (socket_table[idx] == NULL)
			continue;

		struct ndpip_socket *csock = socket_table[idx];

		if (csock == sock)
			continue;

		if ((memcmp(&csock->local, &sock->local, sizeof(struct sockaddr_in)) == 0) &&
			(csock->protocol == sock->protocol)) {

			errno = EADDRINUSE;
			return -1;
		}
	}

	tcp_sock->state = LISTENING;

	uint32_t hash = ndpip_socket_listening_hash(&sock->local);
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

	sock->remote = *((struct sockaddr_in *) addr);

	bool find_local_port = false;
	if (sock->local.sin_port == 0) {
		find_local_port = true;
		sock->local.sin_port = 1025;
	}

	for (size_t idx = 0; idx < NDPIP_TODO_MAX_FDS; idx++) {
		if (socket_table[idx] == NULL)
			continue;

		struct ndpip_socket *csock = socket_table[idx];

		if (csock == sock)
			continue;

		if ((memcmp(&csock->local, &sock->local, sizeof(struct sockaddr_in)) == 0) &&
				(memcmp(&csock->remote, &sock->remote, sizeof(struct sockaddr_in)) == 0) &&
				(csock->protocol == sock->protocol)) {

			if (find_local_port) {
				sock->local.sin_port++;
				idx = 0;
			} else {
				errno = EADDRINUSE;
				return -1;
			}
		}
	}

	if (sock->protocol == IPPROTO_TCP)
		return ndpip_tcp_connect((struct ndpip_tcp_socket *) sock);

	if (sock->protocol == IPPROTO_UDP)
		return ndpip_udp_connect((struct ndpip_udp_socket *) sock);

	errno = EOPNOTSUPP;
	return -1;
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

	if (sock->protocol == IPPROTO_TCP)
		return ndpip_tcp_send((struct ndpip_tcp_socket *) sock, pb, count);

	if (sock->protocol == IPPROTO_UDP)
		return ndpip_udp_send((struct ndpip_udp_socket *) sock, pb, count);

	errno = EOPNOTSUPP;
	return -1;
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

	return ndpip_sock_free(sock, pb, len, true);
}

size_t ndpip_alloc(int sockfd, struct ndpip_pbuf **pb, size_t len) {
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

#ifdef NDPIP_GRANTS_ENABLE
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

int ndpip_cost(int sockfd, struct ndpip_pbuf **pb, uint16_t len, uint16_t *pb_cost) {
	if (sockfd < 0) {
		errno = EBADF;
		return -1;
	}

	struct ndpip_socket *sock = ndpip_socket_get(sockfd);
	if (sock == NULL) {
		errno = ENOTSOCK;
		return -1;
	}

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

int ndpip_sock_free(struct ndpip_socket *sock, struct ndpip_pbuf **pb, size_t len, bool rx)
{
	struct ndpip_pbuf_pool *pool = NULL;
	
	if (len == 0)
		return 0;

	if (rx)
		pool = ndpip_iface_get_pbuf_pool_rx(sock->iface);
	else
		pool = ndpip_iface_get_pbuf_pool_tx(sock->iface);

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

size_t ndpip_sock_alloc(struct ndpip_socket *sock, struct ndpip_pbuf **pb, size_t len, bool rx)
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

	if (ndpip_pbuf_pool_request(pool, pb, &len) < 0) {
		errno = EFAULT;
		return 0;
	}

	return len;
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
				((mss >= NDPIP_TCP_DEFAULT_MSS) && sock->protocol == IPPROTO_TCP) ||
				((mss >= NDPIP_UDP_DEFAULT_MSS) && sock->protocol == IPPROTO_UDP)) {

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

			if ((mss <= 0) || (mss >= NDPIP_TCP_DEFAULT_MSS)) {
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
	if (sock->protocol == IPPROTO_TCP) {
		struct ndpip_tcp_socket *tcp_sock = (void *) sock;
		return ndpip_tcp_poll(tcp_sock);
	}

	if (sock->protocol == IPPROTO_UDP) {
		struct ndpip_udp_socket *udp_sock = (void *) sock;
		return ndpip_udp_poll(udp_sock);
	}

	return 0;
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
