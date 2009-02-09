/*
 * Copyright (C) 2006-2007 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include "ipf.h"

void assigndefined(env)
	char *env;
{
	char *s, *t;

	if (env == NULL)
		return;

	for (s = strtok(env, ";"); s != NULL; s = strtok(NULL, ";")) {
		t = strchr(s, '=');
		if (t == NULL)
			continue;
		*t++ = '\0';
		set_variable(s, t);
		*--t = '=';
	}
}
