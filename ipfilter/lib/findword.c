/*
 * Copyright (C) 2012 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include "ipf.h"


wordtab_t *findword(words, name)
	wordtab_t *words;
	char *name;
{
	wordtab_t *w;

	for (w = words; w->w_word != NULL; w++)
		if (!strcmp(name, w->w_word))
			break;
	if (w->w_word == NULL)
		return NULL;

	return w;
}
