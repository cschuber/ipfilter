/*
 * Copyright (C) 2002-2005 by Darren Reed.
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

	printf("%s,", inet_ntoa(hmp->hm_osrcip));
	printf("%s ", inet_ntoa(hmp->hm_odstip));
	printf("-> %s,", inet_ntoa(hmp->hm_nsrcip));
	printf("%s ", inet_ntoa(hmp->hm_ndstip));
	printf("(use = %d hv = %u)\n", hmp->hm_ref, hv);
}
