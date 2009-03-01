/*
 * Copyright (C) 2002-2008 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include <fcntl.h>
#include <sys/ioctl.h>
#include "ipf.h"
#include "netinet/ip_lookup.h"
#include "netinet/ip_pool.h"

static int poolfd = -1;


int
pool_open()
{

	if ((opts & OPT_DONTOPEN) != 0)
		return 0;

	if (poolfd == -1)
		poolfd = open(IPLOOKUP_NAME, O_RDWR);
	return poolfd;
}

int
pool_ioctl(iocfunc, cmd, ptr)
	ioctlfunc_t iocfunc;
	ioctlcmd_t cmd;
	void *ptr;
{
	return (*iocfunc)(poolfd, cmd, ptr);
}


void
pool_close()
{
	if (poolfd != -1) {
		close(poolfd);
		poolfd = -1;
	}
}
