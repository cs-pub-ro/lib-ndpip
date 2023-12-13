#ifndef _SRC_INCLUDE_NDPIP_SOCKET_H_
#define _SRC_INCLUDE_NDPIP_SOCKET_H_

#include <netinet/ether.h>
#include <netinet/ip.h>

#include <sys/socket.h>

#include "../../../include/ndpip/socket.h"
#include "ndpip/iface.h"
#include "ndpip/util.h"

#ifdef NDPIP_UK
#include "ndpip/uk.h"
#endif

#ifdef NDPIP_LINUX_DPDK
#include "ndpip/linux_dpdk.h"
#endif

#define NDPIP_TODO_MAX_FDS 1024
#define NDPIP_SOCKET_XMIT_RING_LENGTH (1 << 20)
#define NDPIP_SOCKET_RECV_RING_LENGTH (1 << 15)

#define ndpip_socket_foreach(sock) \
	for (struct ndpip_socket **(sock) = socket_table; (socket_table != NULL) && ((sock) < (socket_table + NDPIP_TODO_MAX_FDS)); sock++)


extern struct ndpip_hashtable *ndpip_tcp_established_sockets;
extern struct ndpip_hashtable *ndpip_tcp_listening_sockets;

extern struct ndpip_hashtable *ndpip_udp_established_sockets;
extern struct ndpip_hashtable *ndpip_udp_listening_sockets;


struct ndpip_socket {
	struct ndpip_list_head list;

	int socket_id;
	int protocol;
	struct ndpip_iface *iface;

	struct sockaddr_in local;
	struct sockaddr_in remote;

	struct ndpip_ring *xmit_ring;
	struct ndpip_ring *recv_ring;

	uint16_t tx_mss;

#ifdef NDPIP_GRANTS_ENABLE
	int64_t grants_overhead;
	_Atomic int64_t grants;
	_Atomic int64_t grants_overcommit;
#endif
};

void ndpip_socket_init(void);
struct ndpip_socket *ndpip_socket_new(int domain, int type, int protocol);
struct ndpip_socket *ndpip_socket_accept(struct ndpip_socket *sock);
int ndpip_sock_free(struct ndpip_socket *sock, struct ndpip_pbuf **pb, size_t len, bool rx);
size_t ndpip_sock_alloc(struct ndpip_socket *sock, struct ndpip_pbuf **pb, size_t len, bool rx);
struct ndpip_socket *ndpip_socket_get_by_peer(struct sockaddr_in *local, struct sockaddr_in *remote, int protocol);
uint64_t ndpip_socket_listening_hash(struct sockaddr_in *local);
uint64_t ndpip_socket_established_hash(struct sockaddr_in *local, struct sockaddr_in *remote);
#ifdef NDPIP_GRANTS_ENABLE
int ndpip_socket_grants_get(struct ndpip_socket *sock, uint32_t grants);
uint16_t ndpip_socket_pbuf_cost(struct ndpip_socket *sock, struct ndpip_pbuf *pb);
#endif

extern struct ndpip_socket **socket_table;

#endif
