#ifndef _H_INCLUDE_NDPIP_PBUF_H_
#define _H_INCLUDE_NDPIP_PBUF_H_

struct ndpip_pbuf;

#ifdef NDPIP_UK
#include "uk.h"

#define ndpip_pbuf_data ndpip_uk_pbuf_data
#define ndpip_pbuf_length ndpip_uk_pbuf_length
#define ndpip_pbuf_offset ndpip_uk_pbuf_offset
#define ndpip_pbuf_resize ndpip_uk_pbuf_resize
#define ndpip_pbuf_refcount_get ndpip_uk_pbuf_refcount_get
#define ndpip_pbuf_refcount_add ndpip_uk_pbuf_refcount_add
#define ndpip_pbuf_refcount_set ndpip_uk_pbuf_refcount_set

#endif

#endif
