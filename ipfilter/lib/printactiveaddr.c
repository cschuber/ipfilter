/*
 * Copyright (C) 2009 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Added redirect stuff and a variety of bug fixes. (mcn@EnGarde.com)
 */

#include "ipf.h"


#if !defined(lint)
static const char rcsid[] = "@(#)$Id$";
#endif


void
printactiveaddress(v, fmt, addr, ifname)
	int v;
	char *fmt, *ifname;
	i6addr_t *addr;
{
	switch (v)
	{
	case 4 :
		PRINTF(fmt, inet_ntoa(addr->in4));
		break;
#ifdef USE_INET6
	case 6 :
		printaddr(AF_INET6, FRI_NORMAL, ifname, 0,
			  (u_32_t *)&addr->in6, NULL);
		break;
#endif
	default :
		break;
	}
}
