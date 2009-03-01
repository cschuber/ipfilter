/*
 * Copyright (C) 2002-2007 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 */

#include "ipf.h"


iphtent_t *
printhashnode(iph, ipep, copyfunc, opts)
	iphtable_t *iph;
	iphtent_t *ipep;
	copyfunc_t copyfunc;
	int opts;
{
	iphtent_t ipe;
	u_int hv;

	if ((*copyfunc)(ipep, &ipe, sizeof(ipe)))
		return NULL;

	hv = IPE_V4_HASH_FN(ipe.ipe_addr.i6[0], ipe.ipe_mask.i6[0],
			    iph->iph_size);
	ipe.ipe_addr.i6[0] = htonl(ipe.ipe_addr.i6[0]);
	ipe.ipe_addr.i6[1] = htonl(ipe.ipe_addr.i6[1]);
	ipe.ipe_addr.i6[2] = htonl(ipe.ipe_addr.i6[2]);
	ipe.ipe_addr.i6[3] = htonl(ipe.ipe_addr.i6[3]);
	ipe.ipe_mask.i6[0] = htonl(ipe.ipe_mask.i6[0]);
	ipe.ipe_mask.i6[1] = htonl(ipe.ipe_mask.i6[1]);
	ipe.ipe_mask.i6[2] = htonl(ipe.ipe_mask.i6[2]);
	ipe.ipe_mask.i6[3] = htonl(ipe.ipe_mask.i6[3]);

	if ((opts & OPT_DEBUG) != 0) {
		PRINTF("\t%d\tAddress: %s", hv,
			inet_ntoa(ipe.ipe_addr.in4));
		printmask(ipe.ipe_family, (u_32_t *)&ipe.ipe_mask.in4_addr);
		PRINTF("\tRef. Count: %d\tGroup: %s\n", ipe.ipe_ref,
			ipe.ipe_group);
	} else {
		putchar(' ');
		printip(ipe.ipe_family, (u_32_t *)&ipe.ipe_addr.in4_addr);
		printmask(ipe.ipe_family, (u_32_t *)&ipe.ipe_mask.in4_addr);
		if (ipe.ipe_value != 0) {
			switch (iph->iph_type & ~IPHASH_ANON)
			{
			case IPHASH_GROUPMAP :
				if (strncmp(ipe.ipe_group, iph->iph_name,
					    FR_GROUPLEN))
					PRINTF(", group=%s", ipe.ipe_group);
				break;
			}
		}
		putchar(';');
	}

	ipep = ipe.ipe_next;
	return ipep;
}
