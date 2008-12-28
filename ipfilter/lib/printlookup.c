/*
 * Copyright (C) 2005 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include "ipf.h"


void printlookup(addr, mask)
	i6addr_t *addr, *mask;
{
	char name[32];

	switch (addr->iplookuptype)
	{
	case IPLT_POOL :
		printf("pool/");
		break;
	case IPLT_HASH :
		printf("hash/");
		break;
	default :
		printf("lookup(%x)=", addr->iplookuptype);
		break;
	}

	if (addr->iplookupsubtype == 0)
		printf("%u", addr->iplookupnum);
	else if (addr->iplookupsubtype == 1) {
		strncpy(name, addr->iplookupname, sizeof(addr->iplookupname));
		name[sizeof(addr->iplookupname)] = '\0';
		printf("%s", name);
	}

	if (mask->iplookupptr == NULL)
		printf("(!)");
}
