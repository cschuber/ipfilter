/*
 * Copyright (C) 2002-2008 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include "ipf.h"

void printhostmap(hmp, hv)
	hostmap_t *hmp;
	u_int hv;
{

	printactiveaddress(hmp->hm_v, "%s", &hmp->hm_osrcip6, NULL);
	putchar(',');
	printactiveaddress(hmp->hm_v, "%s", &hmp->hm_odstip6, NULL);
	printf(" -> ");
	printactiveaddress(hmp->hm_v, "%s", &hmp->hm_nsrcip6, NULL);
	putchar(',');
	printactiveaddress(hmp->hm_v, "%s", &hmp->hm_ndstip6, NULL);
	putchar(' ');
	printf("(use = %d", hmp->hm_ref);
	if (opts & OPT_VERBOSE)
		printf(" hv = %u", hv);
	printf(")\n");
}
