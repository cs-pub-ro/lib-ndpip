#include <string.h>
#include <time.h>

#include "ndpip/socket.h"
#include "ndpip/udp.h"
#include "ndpip/tcp.h"
#include "ndpip/util.h"
#include "ndpip/workhorse.h"


#define NDPIP_TODO_ESTABLISHED_SOCKETS_BUCKETS 1024
#define NDPIP_TODO_LISTENING_SOCKETS_BUCKETS 32
#define NDPIP_TODO_SOCKET_XMIT_RING_LENGTH (1 << 20)
#define NDPIP_TODO_SOCKET_RECV_RING_LENGTH (1 << 20)

#define NDPIP_EQDS_GRANTS_OVERHEAD 60


struct ndpip_hashtable *ndpip_established_sockets = NULL;
struct ndpip_hashtable *ndpip_listening_sockets = NULL;

struct ndpip_socket **socket_table = NULL;

int ndpip_socket_grants_get(struct ndpip_socket *sock, uint32_t grants) {
	struct ndpip_pbuf *pb;
	
	if (ndpip_sock_alloc(sock, &pb, 1, false) < 0)
		return -1;

	ndpip_pbuf_resize(pb, sizeof(struct ethhdr) + sizeof(struct eqds_cn));

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
	if (!((domain == AF_INET) && (type == SOCK_NDPIP) && ((protocol == IPPROTO_TCP) || (protocol == IPPROTO_UDP))))
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
	sock->grants = 0;
	sock->grants_overhead = NDPIP_EQDS_GRANTS_OVERHEAD;
	sock->grants_overcommit = 0;

	sock->local = (struct sockaddr_in) { .sin_family = AF_INET, .sin_addr.s_addr = 0, .sin_port = 0 };
	sock->remote = (struct sockaddr_in) { .sin_family = AF_INET, .sin_addr.s_addr = 0, .sin_port = 0 };

	sock->xmit_ring = ndpip_ring_alloc(NDPIP_TODO_SOCKET_XMIT_RING_LENGTH, sizeof(struct ndpip_pbuf *));
	sock->recv_ring = ndpip_ring_alloc(NDPIP_TODO_SOCKET_RECV_RING_LENGTH, sizeof(struct ndpip_pbuf *));


	if (protocol == IPPROTO_TCP) {
		struct ndpip_tcp_socket *tcp_sock = (struct ndpip_tcp_socket *) sock;
		tcp_sock->state = NEW;

		tcp_sock->timer_rto = ndpip_timer_alloc(ndpip_tcp_rto_handler, (void *) sock);
		struct timespec expire;
		ndpip_time_now(&expire);
		ndpip_timer_arm(tcp_sock->timer_rto, &expire);
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
		tcp_sock->rx_loop_seen = false;

		tcp_sock->accept_queue = (struct ndpip_list_head) { &tcp_sock->accept_queue, &tcp_sock->accept_queue };
	}

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

	struct sockaddr_in *addr_in = (void *) addr;

	for (size_t idx = 0; idx < NDPIP_TODO_MAX_FDS; idx++) {
		if (socket_table[idx] == NULL)
			continue;

		if ((memcmp(&socket_table[idx]->local, addr_in, sizeof(struct sockaddr_in)) == 0) && (sock->protocol == socket_table[idx]->protocol)) {
			errno = EADDRINUSE;
			return -1;
		}
	}

	sock->local = *addr_in;
	sock->iface = ndpip_iface_get_by_inaddr(sock->local.sin_addr);

	if (sock->protocol == IPPROTO_TCP) {
		struct ndpip_tcp_socket *tcp_sock = (struct ndpip_tcp_socket *) sock;

		if (tcp_sock->state != NEW) {
			errno = EINVAL;
			return -1;
		}
		
		tcp_sock->state = BOUND;
	}

	if (sock->protocol == IPPROTO_UDP) {
		struct ndpip_listening_key key = {
			.daddr = sock->local.sin_addr.s_addr,
			.dport = sock->local.sin_port,
			.proto = IPPROTO_UDP
		};

		ndpip_hashtable_put(ndpip_listening_sockets, &key, sizeof(key), sock);
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

	tcp_sock->state = LISTENING;

	struct ndpip_listening_key key = {
		.daddr = sock->local.sin_addr.s_addr,
		.dport = sock->local.sin_port,
		.proto = IPPROTO_TCP
	};

	ndpip_hashtable_put(ndpip_listening_sockets, &key, sizeof(key), sock);

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

	struct sockaddr_in *addr_in = (void *) addr;

	sock->remote.sin_addr = addr_in->sin_addr;
	sock->remote.sin_port = addr_in->sin_port;

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

	if (sock->protocol == IPPROTO_TCP) {
		struct ndpip_tcp_socket *tcp_sock = (struct ndpip_tcp_socket *) sock;

		if ((tcp_sock->state != CONNECTED) &&
			(tcp_sock->state != CLOSING) &&
			(ndpip_ring_size(sock->recv_ring) == 0)) {

			errno = EINVAL;
			return -1;
		}
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
		uint16_t transport_overhead = 0;
		if (sock->protocol == IPPROTO_TCP)
			transport_overhead = sizeof(struct tcphdr);

		if (sock->protocol == IPPROTO_UDP)
			transport_overhead = sizeof(struct udphdr);

		pb_cost[idx] = sock->grants_overhead + sizeof(struct ethhdr) + sizeof(struct iphdr) + transport_overhead + ndpip_pbuf_length(pb[idx]);
	}

	return 0;
}

int ndpip_sock_free(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t len, bool rx)
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
		pool = ndpip_iface_get_pbuf_pool_rx(sock->iface);
	else
		pool = ndpip_iface_get_pbuf_pool_tx(sock->iface);

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
			if (sock->protocol != IPPROTO_TCP) {
				errno = EINVAL;
				return -1;
			}

			if (optlen != 1) {
				errno = EINVAL;
				return -1;
			}

			struct ndpip_tcp_socket *tcp_sock = (struct ndpip_tcp_socket *) sock;

			if (tcp_sock->state != NEW) {
				errno = EINVAL;
				return -1;
			}

			tcp_sock->tcp_recv_win_scale = *((uint8_t *) optval);

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


struct ndpip_socket *ndpip_socket_get_by_peer(struct sockaddr_in *local, struct sockaddr_in *remote, int protocol)
{
	if (socket_table == NULL)
		return NULL;

	struct ndpip_established_key key = {
		.saddr = remote->sin_addr.s_addr,
		.daddr = local->sin_addr.s_addr,
		.sport = remote->sin_port,
		.dport = local->sin_port,
		.proto = protocol
	};

	struct ndpip_listening_key key2 = {
		.daddr = local->sin_addr.s_addr,
		.dport = local->sin_port,
		.proto = protocol
	};

	/*
	printf("GET_ESTABLISHED: ");
	for (int i = 0; i < sizeof(key); i++)
		printf("%hhx", ((uint8_t *)&key)[i]);
	printf("\n");
	*/
	struct ndpip_socket *ret = ndpip_hashtable_get(ndpip_established_sockets, &key, sizeof(key));
	if (ret != NULL)
		return ret;

	return ndpip_hashtable_get(ndpip_listening_sockets, &key2, sizeof(key2));
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
