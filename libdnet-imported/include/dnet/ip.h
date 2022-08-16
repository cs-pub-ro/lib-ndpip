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

uint16_t iphv4_checksum(struct iphdr *iph);
uint16_t ipv4_checksum(struct iphdr *iph);
uint16_t ipv4_checksum_pheader(struct iphdr *iph, uint16_t len);

#endif /* DNET_IP_H */
