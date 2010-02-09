/*
 * Copyright (C) 2002-2007 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 */

#include "ipf.h"


ip_pool_node_t *
printpoolnode(np, opts, fields)
	ip_pool_node_t *np;
	int opts;
	wordtab_t *fields;
{
	int i;

	if (fields != NULL) {
		for (i = 0; fields[i].w_value != 0; i++) {
			printpoolfield(np, IPLT_POOL, i);
			if (fields[i + 1].w_value != 0)
				printf("\t");
		}
		printf("\n");
	} else if ((opts & OPT_DEBUG) == 0) {
		putchar(' ');
		if (np->ipn_info == 1)
			PRINTF("! ");
		if (np->ipn_addr.adf_family == AF_INET) {
			printip(np->ipn_addr.adf_family,
				(u_32_t *)&np->ipn_addr.adf_addr.in4);
		} else {
#ifdef USE_INET6
			char buf[INET6_ADDRSTRLEN+1];
			const char *str;

			str = inet_ntop(AF_INET6, &np->ipn_addr.adf_addr,
					buf, sizeof(buf) - 1);
			if (str != NULL)
				PRINTF("%s", str);
#endif
		}
		printmask(np->ipn_addr.adf_family,
			  (u_32_t *)&np->ipn_mask.adf_addr);
	} else {
		PRINTF("\tAddress: %s%s", np->ipn_info ? "! " : "",
			inet_ntoa(np->ipn_addr.adf_addr.in4));
		printmask(np->ipn_addr.adf_family,
			  (u_32_t *)&np->ipn_mask.adf_addr);
#ifdef USE_QUAD_T
		PRINTF("\n\t\tHits %qu\tBytes %qu\tName %s\tRef %d\n",
			np->ipn_hits, np->ipn_bytes,
			np->ipn_name, np->ipn_ref);
#else
		PRINTF("\n\t\tHits %lu\tBytes %lu\tName %s\tRef %d\n",
			np->ipn_hits, np->ipn_bytes,
			np->ipn_name, np->ipn_ref);
#endif
	}
	return np->ipn_next;
}
