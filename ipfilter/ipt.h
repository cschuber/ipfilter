/*
 * Copyright (C) 1993-2009 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#ifndef	__IPT_H__
#define	__IPT_H__

#include <fcntl.h>


struct	ipread	{
	int	(*r_open)(char *);
	int	(*r_close)(void);
	int	(*r_readip)(mb_t *, char **, int *);
	int	r_flags;
};

#define	R_DO_CKSUM	0x01

#endif /* __IPT_H__ */
