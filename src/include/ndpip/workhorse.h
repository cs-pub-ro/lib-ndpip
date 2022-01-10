#ifndef _SRC_INCLUDE_NDPIP_WORKHORSE_H_
#define _SRC_INCLUDE_NDPIP_WORKHORSE_H_

#include "ndpip/util.h"
#include "ndpip/iface.h"

int ndpip_rx_thread(void *argp);
void ndpip_timers_thread(struct ndpip_iface *iface);
void ndpip_timers_add(struct ndpip_timer *timer);

#endif
