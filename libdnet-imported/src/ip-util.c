/*
 * ip-util.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include <dnet/ip.h>

#include <netinet/tcp.h>

void tcpip_checksum(struct iphdr *iph)
{
	int32_t sum;

	uint16_t hl = iph->ihl << 2;

	iph->check = 0;
	sum = ip_cksum_add(iph, hl, 0);
	iph->check = ip_cksum_carry(sum);

	uint16_t len = ntohs(iph->tot_len) - hl;
	
	struct tcphdr *th = ((void *) iph) + hl;
		
	th->th_sum = 0;

	sum = iph->saddr >> 16;
	sum += iph->saddr & 0xffff;

	sum += iph->daddr >> 16;
	sum += iph->daddr & 0xffff;

	sum += iph->protocol << 8;
	sum += htons(len);

	sum = ip_cksum_add(th, len, sum);

	th->th_sum = ip_cksum_carry(sum);
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
		cksum += *((uint8_t *) sp);

	return cksum;
}
