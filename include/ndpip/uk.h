#ifndef _INCLUDE_NDPIP_UK_H_
#define _INCLUDE_NDPIP_UK_H_

#include <netinet/in.h>
#include <netinet/ether.h>

#include <uk/netdev.h>

#include "pbuf.h"

struct ndpip_arp_peer {
	struct in_addr inaddr;
	struct ether_addr ethaddr;
};

int ndpip_uk_register_iface(int netdev_id, bool intr);
int ndpip_uk_start_iface(int netdev_id);

int ndpip_uk_set_ethaddr(int netdev_id, struct ether_addr iface_ethaddr);
int ndpip_uk_set_inaddr(int netdev_id, struct in_addr iface_inaddr);
int ndpip_uk_set_arp_table(int netdev_id, struct ndpip_arp_peer *iface_arp_table, size_t iface_arp_table_len);

void *ndpip_uk_pbuf_data(struct ndpip_pbuf *pbuf);
int ndpip_uk_pbuf_resize(struct ndpip_pbuf *pbuf, uint16_t len);

#endif
