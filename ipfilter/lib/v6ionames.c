/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */
#include "ipf.h"


#ifdef	USE_INET6

struct	ipopt_names	v6ionames[] ={
	{ IPPROTO_HOPOPTS,	0x000001,	0,	"hopopts" },
	{ IPPROTO_DSTOPTS,	0x000002,	0,	"dstopts" },
	{ IPPROTO_ESP,		0x000004,	0,	"esp" },
	{ IPPROTO_AH,		0x000008,	0,	"ah" },
	{ IPPROTO_ROUTING,	0x000010,	0,	"routing" },
	{ IPPROTO_IPV6,		0x000020,	0,	"ipv6" },
	{ IPPROTO_FRAGMENT,	0x000040,	0,	"frag" },	
	{ IPPROTO_NONE,		0x000080,	0,	"none" },	
	{ 0, 			0,		0,	(char *)NULL }
};

#endif
