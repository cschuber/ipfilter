/*
 * Copyright (C) 2004-2005 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */
#include "ipf.h"
#include "kmem.h"

void printfraginfo(prefix, ifr)
char *prefix;
struct ipfr *ifr;
{
	frentry_t fr;

	fr.fr_flags = 0xffffffff;

	printf("%s%s -> ", prefix, hostname(4, &ifr->ipfr_src));
/*
	if (kmemcpy((char *)&fr, (u_long)ifr->ipfr_rule,
		    sizeof(fr)) == -1)
		return;
*/
	printf("%s id %d ttl %d pr %d seen0 %d ref %d tos %#02x = %#x\n",
		hostname(4, &ifr->ipfr_dst), ifr->ipfr_id, ifr->ipfr_seen0,
		ifr->ipfr_ttl, ifr->ipfr_p, ifr->ipfr_ref, ifr->ipfr_tos,
		0);
}
