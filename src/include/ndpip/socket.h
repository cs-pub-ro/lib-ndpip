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
#define ndpip_socket_foreach(sock) \
	for (struct ndpip_socket **(sock) = socket_table; (socket_table != NULL) && ((sock) < (socket_table + NDPIP_TODO_MAX_FDS)); sock++)


extern struct ndpip_hashtable *ndpip_established_sockets;
extern struct ndpip_hashtable *ndpip_listening_sockets;

struct ndpip_established_key {
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	int proto;
} __attribute__((packed));

struct ndpip_listening_key {
	uint32_t daddr;
	uint16_t dport;
	int proto;
} __attribute__((packed));

struct ndpip_socket {
	struct ndpip_list_head list;

	int socket_id;
	int protocol;
	struct ndpip_iface *iface;

	struct sockaddr_in local;
	struct sockaddr_in remote;

	struct ndpip_ring *xmit_ring;
	struct ndpip_ring *recv_ring;

	int64_t grants_overhead;
	_Atomic int64_t grants;
	_Atomic int64_t grants_overcommit;
};

struct ndpip_socket *ndpip_socket_new(int domain, int type, int protocol);
struct ndpip_socket *ndpip_socket_accept(struct ndpip_socket *sock);
int ndpip_sock_free(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t len, bool rx);
int ndpip_sock_alloc(struct ndpip_socket *sock, struct ndpip_pbuf **pb, uint16_t len, bool rx);
struct ndpip_socket *ndpip_socket_get_by_peer(struct sockaddr_in *local, struct sockaddr_in *remote, int protocol);
int ndpip_socket_grants_get(struct ndpip_socket *sock, uint32_t grants);

extern struct ndpip_socket **socket_table;

#endif
