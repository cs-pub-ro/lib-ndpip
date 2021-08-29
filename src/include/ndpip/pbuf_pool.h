#ifndef _H_SRC_INCLUDE_PBUF_POOL_H_
#define _H_SRC_INCLUDE_PBUF_POOL_H_

#include "../../include/ndpip/pbuf.h"

struct ndpip_pbuf_pool;

#ifdef NDPIP_UK

#define ndpip_pbuf_pool_alloc ndpip_uk_pbuf_pool_alloc
#define ndpip_pbuf_pool_request ndpip_uk_pbuf_pool_request
#define ndpip_pbuf_pool_release ndpip_uk_pbuf_pool_release

#endif

#endif
