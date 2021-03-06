/*
 * Copyright (C) 2009 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include "ipf.h"

mb_t *allocmbt(size_t len)
{
	mb_t *m;

	m = (mb_t *)malloc(sizeof(mb_t));
	if (m == NULL)
		return NULL;
	m->mb_len = len;
	m->mb_next = NULL;
	m->mb_data = (char *)m->mb_buf;
	return m;
}
