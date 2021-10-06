#ifndef _H_SRC_INCLUDE_NDPIP_PBUF_H_
#define _H_SRC_INCLUDE_NDPIP_PBUF_H_

#include "../../include/ndpip/pbuf.h"

struct ndpip_pbuf_train {
	struct ndpip_pbuf **train_pbufs;
	size_t train_pbuf_count;
};

#endif
