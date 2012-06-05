/*
 * Copyright (C) 2003-2008 by Darren Reed.
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


int
load_dstlistnode(role, name, node, iocfunc)
	int role;
	char *name;
	ipf_dstnode_t *node;
	ioctlfunc_t iocfunc;
{
	iplookupop_t op;
	frdest_t *dst;
	char *what;
	int err;

	if (pool_open() == -1)
		return -1;

	dst = calloc(1, sizeof(*dst) + node->ipfd_dest.fd_name);
	if (dst == NULL)
		return -1;

	op.iplo_unit = role;
	op.iplo_type = IPLT_DSTLIST;
	op.iplo_arg = 0;
	op.iplo_struct = dst;
	op.iplo_size = sizeof(*dst) + node->ipfd_dest.fd_name;
	strncpy(op.iplo_name, name, sizeof(op.iplo_name));

	dst->fd_addr = node->ipfd_dest.fd_addr;
	dst->fd_type = node->ipfd_dest.fd_type;
	dst->fd_name = node->ipfd_dest.fd_name;
	bcopy(node->ipfd_names, (char *)dst + sizeof(*dst),
	      node->ipfd_dest.fd_name);

	if ((opts & OPT_REMOVE) == 0) {
		what = "add";
		err = pool_ioctl(iocfunc, SIOCLOOKUPADDNODE, &op);
	} else {
		what = "delete";
		err = pool_ioctl(iocfunc, SIOCLOOKUPDELNODE, &op);
	}
	free(dst);

	if (err != 0) {
		if ((opts & OPT_DONOTHING) == 0) {
			char msg[80];

			sprintf(msg, "%s lookup node", what);
			return ipf_perror_fd(pool_fd(), iocfunc, msg);
		}
	}

	return 0;
}
