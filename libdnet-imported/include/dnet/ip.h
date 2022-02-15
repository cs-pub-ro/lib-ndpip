/*
 * ip.h
 *
 * Internet Protocol (RFC 791).
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#ifndef DNET_IP_H
#define DNET_IP_H

#include <stdint.h>

#include <netinet/ip.h>

uint16_t ipv4_checksum(struct iphdr *iph);
uint16_t ipv4_checksum_pheader(struct iphdr *iph, uint16_t len);
uint16_t tcpv4_checksum(struct iphdr *iph);

int32_t ip_cksum_add(const void *buf, uint16_t len, int32_t cksum);
#define ip_cksum_carry(x) \
	(x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

#endif /* DNET_IP_H */
