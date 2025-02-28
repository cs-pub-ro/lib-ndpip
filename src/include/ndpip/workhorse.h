#ifndef _SRC_INCLUDE_NDPIP_WORKHORSE_H_
#define _SRC_INCLUDE_NDPIP_WORKHORSE_H_

#include "ndpip/util.h"
#include "ndpip/iface.h"

void ndpip_workhorse_init();
int ndpip_rx_thread(void *argp);
void ndpip_timers_thread(struct ndpip_iface *iface);
void ndpip_timers_del(struct ndpip_timer *timer);
void ndpip_timers_add(struct ndpip_timer *timer);

#endif
