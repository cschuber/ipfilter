/*
 * Copyright (C) 2008 by Darren Reed.
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
	char *fmt;
	i6addr_t *addr;
	char *ifname;
{
	switch (v)
	{
	case 4 :
		printf(fmt, inet_ntoa(addr->in4));
		break;
#ifdef USE_INET6
	case 6 :
		printaddr(AF_INET6, FRI_NORMAL, ifname,
			  (u_32_t *)&addr->in6, NULL);
		break;
#endif
	default :
		break;
	}
}
