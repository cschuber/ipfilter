/*
 * Copyright (C) 2006-2009 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include "ipf.h"

void freembt(m)
	mb_t *m;
{

	free(m);
}
