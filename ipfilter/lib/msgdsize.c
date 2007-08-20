/*
 * Copyright (C) 2007 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include "ipf.h"

size_t msgdsize(orig)
mb_t *orig;
{
	size_t sz;
	mb_t *m;

	for (sz = 0, m = orig; m != NULL; sz += m->mb_len, m = m->mb_next)
		;
	return sz;
}
