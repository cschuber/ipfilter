/*
 * Copyright (C) 2005 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */
#include "ipf.h"

int geticmptype(v, name)
int v;
char *name;
{
	icmptype_t *i;

	for (i = icmptypelist; i->it_name != NULL; i++) {
		if (!strcmp(name, i->it_name)) {
			if (v == 4)
				return i->it_v4;
			if (v == 6)
				return i->it_v6;
			return -1;
		}
	}

	return -1;
}
