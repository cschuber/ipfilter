/*
 * Copyright (C) 2006 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include "ipf.h"

int prependmbt(fin, m)
	fr_info_t *fin;
	mb_t *m;
{
	m->mb_next = *fin->fin_mp;
	*fin->fin_mp = m;
}
