#ifndef _H_SRC_INCLUDE_NDPIP_PBUF_H_
#define _H_SRC_INCLUDE_NDPIP_PBUF_H_

#include "../../include/ndpip/pbuf.h"

#include <stdint.h>
#include <time.h>

#include <netinet/in.h>

struct ndpip_pbuf_meta {
	uint32_t tcp_ack;
	uint16_t data_len;
	struct sockaddr_in remote;

	struct tcphdr *th;
	uint16_t th_hlen;
};

enum ndpip_pbuf_flag {
	NDPIP_PBUF_F_RX_L4_CSUM_GOOD,
	NDPIP_PBUF_F_RX_L4_CSUM_BAD,
	NDPIP_PBUF_F_RX_L4_CSUM_NONE,
	NDPIP_PBUF_F_RX_IP_CSUM_GOOD,
	NDPIP_PBUF_F_RX_IP_CSUM_BAD,
	NDPIP_PBUF_F_RX_IP_CSUM_NONE,
	NDPIP_PBUF_F_TX_IP_CKSUM,
	NDPIP_PBUF_F_TX_TCP_CKSUM,
	NDPIP_PBUF_F_TX_UDP_CKSUM,
	NDPIP_PBUF_F_TX_IPV4
};

#endif
