#ifndef _H_SRC_INCLUDE_NDPIP_PBUF_H_
#define _H_SRC_INCLUDE_NDPIP_PBUF_H_

#include "../../include/ndpip/pbuf.h"

struct ndpip_pbuf_meta {
	struct timespec xmit_time;
	uint32_t data_len;
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
