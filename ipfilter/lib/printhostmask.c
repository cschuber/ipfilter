/*
 * Copyright (C) 2000-2005 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include "ipf.h"


void	printhostmask(family, addr, mask)
	int	family;
	u_32_t	*addr, *mask;
{
#ifdef  USE_INET6
	char ipbuf[64];
#else
	struct in_addr ipa;
#endif

	if ((family == -1) || ((!addr || !*addr) && (!mask || !*mask)))
		printf("any");
	else {
		void *ptr = addr;

#ifdef  USE_INET6
		printf("%s", inet_ntop(family, ptr, ipbuf, sizeof(ipbuf)));
#else
		ipa.s_addr = *addr;
		printf("%s", inet_ntoa(ipa));
#endif
		if (mask != NULL)
			printmask(family, mask);
	}
}
