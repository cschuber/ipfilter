/*
 * Copyright (C) 2002-2007 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include "ipf.h"


void	printip(family, addr)
	int family;
	u_32_t *addr;
{
	struct in_addr ipa;

	if (family == AF_INET) {
		ipa.s_addr = *addr;
		if (ntohl(ipa.s_addr) < 256)
			printf("%lu", (u_long)ntohl(ipa.s_addr));
		else
			printf("%s", inet_ntoa(ipa));
	}
#ifdef AF_INET6
	else if (family == AF_INET6) {
		char buf[INET6_ADDRSTRLEN + 1];
		const char *str;

		buf[0] = '\0';
		str = inet_ntop(AF_INET6, addr, buf, sizeof(buf) - 1);
		if (str != NULL)
			printf("%s", str);
		else
			printf("???");
	}
#endif
	else
		printf("?(%d)?", family);
}
