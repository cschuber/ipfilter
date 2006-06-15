/*
 * Copyright (C) 2005 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */
#include "ipf.h"

char *icmptypename(v, type)
int v, type;
{
	icmptype_t *i;

	if ((type < 0) || (type > 255))
		return NULL;

	for (i = icmptypelist; i->it_name != NULL; i++) {
		if ((v == 4) && (i->it_v4 == type))
			return i->it_name;
		if ((v == 6) && (i->it_v6 == type))
			return i->it_name;
	}

	return NULL;
}
