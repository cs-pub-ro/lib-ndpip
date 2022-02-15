#ifndef _H_SRC_INCLUDE_NDPIP_PBUF_H_
#define _H_SRC_INCLUDE_NDPIP_PBUF_H_

#include "../../include/ndpip/pbuf.h"

struct ndpip_pbuf_meta {
	uint64_t xmit_tsc;
};

enum ndpip_pbuf_flag {
	NDPIP_PBUF_F_RX_L4_CSUM_GOOD,
	NDPIP_PBUF_F_RX_L4_CSUM_BAD,
	NDPIP_PBUF_F_RX_L4_CSUM_NONE,
	NDPIP_PBUF_F_TX_IP_CKSUM,
	NDPIP_PBUF_F_TX_TCP_CKSUM,
	NDPIP_PBUF_F_TX_IPV4
};

#endif
