/*
 * ip-util.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include <dnet/ip.h>


#define ip_cksum_carry(x) \
	(x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))


int32_t ip_cksum_add(const void *buf, uint16_t len, int32_t cksum);

uint16_t iphv4_checksum(struct iphdr *iph)
{
	int32_t sum;

	uint16_t hl = iph->ihl << 2;

	sum = ip_cksum_add(iph, hl, 0);

	return ip_cksum_carry(sum);
}

uint16_t ipv4_checksum_pheader(struct iphdr *iph, uint16_t len)
{
	int32_t sum = 0;

	sum += iph->saddr >> 16;
	sum += iph->saddr & 0xffff;
	sum += iph->daddr >> 16;
	sum += iph->daddr & 0xffff;
	sum += htons(iph->protocol + len);

	sum = ip_cksum_carry(sum);

	return htons(sum);
}

uint16_t inet_checksum_partial(void *payload, uint16_t len, int32_t sum)
{
	sum = ip_cksum_add(payload, len, sum);
 	return ip_cksum_carry(sum);
}

uint16_t ipv4_checksum(struct iphdr *iph)
{
	uint16_t hl = iph->ihl << 2;
	uint16_t len = ntohs(iph->tot_len) - hl;
	void *payload = ((void *) iph) + hl;

	int32_t sum = 0;

	sum += iph->saddr >> 16;
	sum += iph->saddr & 0xffff;
	sum += iph->daddr >> 16;
	sum += iph->daddr & 0xffff;
	sum += htons(iph->protocol + len);
		
	return inet_checksum_partial(payload, len, sum);
}

int32_t ip_cksum_add(const void *buf, uint16_t len, int32_t cksum)
{
	uint16_t *sp = (uint16_t *) buf;
	int n, sn;
	
	sn = len / 2;
	n = (sn + 15) / 16;

	/* XXX - unroll loop using Duff's device. */
	switch (sn % 16) {
	case 0:	do {
		cksum += *sp++;
	case 15:
		cksum += *sp++;
	case 14:
		cksum += *sp++;
	case 13:
		cksum += *sp++;
	case 12:
		cksum += *sp++;
	case 11:
		cksum += *sp++;
	case 10:
		cksum += *sp++;
	case 9:
		cksum += *sp++;
	case 8:
		cksum += *sp++;
	case 7:
		cksum += *sp++;
	case 6:
		cksum += *sp++;
	case 5:
		cksum += *sp++;
	case 4:
		cksum += *sp++;
	case 3:
		cksum += *sp++;
	case 2:
		cksum += *sp++;
	case 1:
		cksum += *sp++;
		} while (--n > 0);
	}

	if (len & 1)
		cksum += htons(*((uint8_t *) sp) << 8);

	return cksum;
}
