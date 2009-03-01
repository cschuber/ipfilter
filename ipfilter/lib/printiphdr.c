/*
 * Copyright (C)  by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include "ipf.h"


void
printiphdr(ip)
	ip_t *ip;
{
	PRINTF("ip(v=%d,hl=%d,len=%d,tos=%#x,off=%#x,sum=%#x,src=%#x,dst=%#x",
	       ip->ip_v, ip->ip_hl, ntohs(ip->ip_len), ip->ip_tos,
	       ntohs(ip->ip_off), ntohs(ip->ip_sum), ntohl(ip->ip_src.s_addr),
	       ntohl(ip->ip_dst.s_addr));
}
