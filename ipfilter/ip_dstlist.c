/*
 * Copyright (C) 2008 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 */
#if defined(KERNEL) || defined(_KERNEL)
# undef KERNEL
# undef _KERNEL
# define        KERNEL	1
# define        _KERNEL	1
#endif
#if defined(__osf__)
# define _PROTO_NET_H_
#endif
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/file.h>
#if !defined(_KERNEL) && !defined(__KERNEL__)
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# define _KERNEL
# ifdef __OpenBSD__
struct file;
# endif
# include <sys/uio.h>
# undef _KERNEL
#else
# include <sys/systm.h>
# if defined(NetBSD) && (__NetBSD_Version__ >= 104000000)
#  include <sys/proc.h>
# endif
#endif
#include <sys/time.h>
#if !defined(linux)
# include <sys/protosw.h>
#endif
#include <sys/socket.h>
#if defined(_KERNEL) && (!defined(__SVR4) && !defined(__svr4__))
# include <sys/mbuf.h>
#endif
#if defined(__SVR4) || defined(__svr4__)
# include <sys/filio.h>
# include <sys/byteorder.h>
# ifdef _KERNEL
#  include <sys/dditypes.h>
# endif
# include <sys/stream.h>
# include <sys/kmem.h>
#endif
#if defined(__FreeBSD_version) && (__FreeBSD_version >= 300000)
# include <sys/malloc.h>
#endif

#if defined(_KERNEL) && (defined(__osf__) || defined(AIX) || \
     defined(__hpux) || defined(__sgi))
# include "radix_ipf_local.h"
# define _RADIX_H_
#endif
#include <net/if.h>
#include <netinet/in.h>

#include "netinet/ip_compat.h"
#include "netinet/ip_fil.h"
#include "netinet/ip_lookup.h"
#include "netinet/ip_dstlist.h"

/* END OF INCLUDES */

#if !defined(lint)
static const char rcsid[] = "@(#)$Id$";
#endif


static int ipf_dstlist_init __P((void));
static void ipf_dstlist_fini __P((void));
static int ipf_dstlist_addr_find __P((void *, int, void *));
static size_t ipf_dstlist_flush __P((iplookupflush_t *));
static int ipf_dstlist_iter_deref __P((int, int, void *));
static int ipf_dstlist_iter_next __P((ipftoken_t *, ipflookupiter_t *));
static int ipf_dstlist_node_add __P((iplookupop_t *));
static int ipf_dstlist_node_del __P((iplookupop_t *));
static int ipf_dstlist_stats_get __P((iplookupop_t *));
static int ipf_dstlist_table_add __P((iplookupop_t *));
static int ipf_dstlist_table_del __P((iplookupop_t *));
static int ipf_dstlist_table_deref __P((void *));
static void *ipf_dstlist_table_find __P((int, char *));
static void ipf_dstlist_table_flush __P((ippool_dst_t *));
static void ipf_dstlist_table_clearnodes __P((ippool_dst_t *));
static ipf_dstnode_t *ipf_dstlist_select __P((ippool_dst_t *));
void *ipf_dstlist_select_ref __P((int, char *));
void ipf_dstlist_unselect_deref __P((ipf_dstnode_t *));
static void ipf_dstlist_node_free __P((ipf_dstnode_t *));
static void *ipf_dstlist_table_find __P((int, char *));
static int ipf_dstlist_node_deref __P((ipf_dstnode_t *));

ipf_lookup_t ipf_dstlist_backend = {
	IPLT_DSTLIST,
	ipf_dstlist_init,
	ipf_dstlist_fini,
	ipf_dstlist_addr_find,
	ipf_dstlist_flush,
	ipf_dstlist_iter_deref,
	ipf_dstlist_iter_next,
	ipf_dstlist_node_add,
	ipf_dstlist_node_del,
	ipf_dstlist_stats_get,
	ipf_dstlist_table_add,
	ipf_dstlist_table_del,
	ipf_dstlist_table_deref,
	ipf_dstlist_table_find
};


static ippool_dst_t *dstlist[IPL_LOGSIZE];


static int
ipf_dstlist_init()
{
	int i;

	for (i = 0; i < IPL_LOGSIZE; i++)
		dstlist[i] = NULL;

	return 0;
}


static void
ipf_dstlist_fini()
{
	int i;

	for (i = 0; i < IPL_LOGSIZE; i++)
		while (dstlist[i] != NULL)
			ipf_dstlist_table_flush(dstlist[i]);
}


/*ARGSUSED*/
static int
ipf_dstlist_addr_find(arg1, arg2, arg3)
	void *arg1, *arg3;
	int arg2;
{
	/*
	 * No such thing as searching a destination list for an address?
	 */
	return -1;
}


static size_t
ipf_dstlist_flush(fop)
	iplookupflush_t *fop;
{
	ippool_dst_t *node, *next;
	int n, i;

	for (n = 0, i = 0; i < IPL_LOGSIZE; i++) {
		if (fop->iplf_unit != IPLT_ALL && fop->iplf_unit != i)
			continue;
		for (node = dstlist[i]; node != NULL; node = next) {
			next = node->ipld_next;

			if ((*fop->iplf_name != '\0') &&
			    strncmp(fop->iplf_name, node->ipld_name,
				    FR_GROUPLEN))
				continue;

			ipf_dstlist_table_flush(node);
			n++;
		}
	}
	return n;
}


static int
ipf_dstlist_iter_deref(otype, unit, data)
	int otype, unit;
	void *data;
{
	if (data == NULL)
		return EINVAL;

	if (unit < 0 || unit > IPL_LOGMAX)
		return EINVAL;

	switch (otype)
	{
	case IPFLOOKUPITER_LIST :
		ipf_dstlist_table_deref((ippool_dst_t *)data);
		break;

	case IPFLOOKUPITER_NODE :
		ipf_dstlist_node_deref((ipf_dstnode_t *)data);
		break;
	}

	return 0;
}


static int
ipf_dstlist_iter_next(token, iter)
	ipftoken_t *token;
	ipflookupiter_t *iter;
{
	ipf_dstnode_t zn, *nextnode, *node;
	ippool_dst_t zero, *next, *list;
	int err;

	switch (iter->ili_otype)
	{
	case IPFLOOKUPITER_LIST :
		list = token->ipt_data;
		if (list == NULL) {
			next = dstlist[(int)iter->ili_unit];
		} else {
			next = list->ipld_next;
		}

		if (next != NULL) {
			ATOMIC_INC(list->ipld_ref);
			token->ipt_data = next;
		} else {
			bzero((char *)&zero, sizeof(zero));
			next = &zero;
			token->ipt_data = NULL;
		}
		break;

	case IPFLOOKUPITER_NODE :
		node = token->ipt_data;
		if (node == NULL) {
			list = ipf_dstlist_table_find(iter->ili_unit,
						      iter->ili_name);
			if (list == NULL) {
				err = ESRCH;
				nextnode = NULL;
			} else {
				nextnode = list->ipld_dests;
				list = NULL;
			}
		} else {
			nextnode = node->ipfd_next;
		}

		if (nextnode != NULL) {
			ATOMIC_INC(nextnode->ipfd_ref);
			token->ipt_data = nextnode;
		} else {
			bzero((char *)&zn, sizeof(zn));
			nextnode = &zn;
			token->ipt_data = NULL;
		}
		break;
	default :
		err = EINVAL;
		break;
	}

	if (err != 0)
		return err;

	switch (iter->ili_otype)
	{
	case IPFLOOKUPITER_LIST :
		if (node != NULL) {
			ipf_dstlist_table_deref(node);
		}
		token->ipt_data = next;
		err = COPYOUT(next, iter->ili_data, sizeof(*next));
		if (err != 0) {
			err = EFAULT;
		}
		break;

	case IPFLOOKUPITER_NODE :
		if (node != NULL) {
			ipf_dstlist_node_deref(node);
		}
		token->ipt_data = nextnode;
		err = COPYOUT(nextnode, iter->ili_data, sizeof(*nextnode));
		if (err != 0) {
			err = EFAULT;
		}
		break;
	}

	return err;
}


static int
ipf_dstlist_node_add(op)
	iplookupop_t *op;
{
	ipf_dstnode_t *node;
	ippool_dst_t *d;
	int err;

	if (op->iplo_size != sizeof(frdest_t)) {
		return EINVAL;
	}

	KMALLOC(node, ipf_dstnode_t *);
	if (node == NULL) {
		return ENOMEM;
	}

	err = COPYIN(op->iplo_struct, &node->ipfd_dest,
		     sizeof(node->ipfd_dest));
	if (err != 0) {
		return EFAULT;
	}

	d = ipf_dstlist_table_find(op->iplo_unit, op->iplo_name);
	if (d == NULL) {
		KFREE(node);
		return ESRCH;
	}

	MUTEX_INIT(&node->ipfd_lock, "ipf dst node lock");
	node->ipfd_plock = &d->ipld_lock;

	node->ipfd_bytes = 0;
	node->ipfd_states = 0;
	node->ipfd_ref = 1;

	MUTEX_ENTER(&d->ipld_lock);
	node->ipfd_next = d->ipld_dests;
	node->ipfd_pnext = &d->ipld_dests;
	if (d->ipld_dests != NULL)
		d->ipld_dests->ipfd_pnext = &node->ipfd_next;
	d->ipld_dests = node;
	MUTEX_EXIT(&d->ipld_lock);

	return 0;
}


static int
ipf_dstlist_node_deref(node)
	ipf_dstnode_t *node;
{
	return 0;
}


static int
ipf_dstlist_node_del(op)
	iplookupop_t *op;
{
	ipf_dstnode_t *node;
	ippool_dst_t *d;
	frdest_t dest;
	int err;

	err = COPYIN(op->iplo_struct, &dest, sizeof(dest));
	if (err != 0) {
		return EFAULT;
	}

	d = ipf_dstlist_table_find(op->iplo_unit, op->iplo_name);
	if (d == NULL) {
		return ESRCH;
	}

	MUTEX_ENTER(&d->ipld_lock);
	for (node = d->ipld_dests; node != NULL; node = node->ipfd_next) {
		if (!bcmp(&node->ipfd_dest.fd_ip6, &dest.fd_ip6,
			  sizeof(dest) - offsetof(frdest_t, fd_ip6))) {
			MUTEX_ENTER(&node->ipfd_lock);
			ipf_dstlist_node_free(node);
			MUTEX_EXIT(&d->ipld_lock);
			return 0;
		}
	}
	MUTEX_EXIT(&d->ipld_lock);

	return ESRCH;
}


static void
ipf_dstlist_node_free(node)
	ipf_dstnode_t *node;
{
	int ref;

	/*
	 * ipfd_plock points back to the lock in the ippool_dst_t that is
	 * used to synchronise additions/deletions from its node list.
	 */
	MUTEX_ENTER(node->ipfd_plock);

	ref = --node->ipfd_ref;

	if (node->ipfd_next != NULL) {
		node->ipfd_next->ipfd_pnext = node->ipfd_pnext;
		node->ipfd_next = NULL;
	}
	if (node->ipfd_pnext != NULL) {
		*node->ipfd_pnext = node->ipfd_next;
		node->ipfd_pnext = NULL;
	}

	MUTEX_EXIT(node->ipfd_plock);

	if (ref == 0) {
		KFREE(node);
	}
}


static int
ipf_dstlist_stats_get(op)
	iplookupop_t *op;
{

	return 0;
}


static int
ipf_dstlist_table_add(op)
	iplookupop_t *op;
{

	ippool_dst_t *d, *new;
	int unit;

	KMALLOC(new, ippool_dst_t *);

	d = ipf_dstlist_table_find(op->iplo_unit, op->iplo_name);
	if (d != NULL) {
		if (new != NULL) {
			KFREE(new);
		}
		return EEXIST;
	}

	if (new == NULL) {
		return ENOMEM;
	}

	MUTEX_INIT(&new->ipld_lock, "ipf dst table lock");

	strncpy(new->ipld_name, op->iplo_name, FR_GROUPLEN);
	unit = op->iplo_unit;
	new->ipld_unit = unit;
	/*
	 * put the new destination list at the top of the list
	 */
	new->ipld_pnext = &dstlist[unit];
	new->ipld_next = dstlist[unit];
	if (dstlist[unit] != NULL)
		dstlist[unit]->ipld_pnext = &new->ipld_next;
	dstlist[unit] = new;

	return 0;
}


static int
ipf_dstlist_table_del(op)
	iplookupop_t *op;
{
	ippool_dst_t *d;

	d = ipf_dstlist_table_find(op->iplo_unit, op->iplo_name);
	if (d == NULL) {
		return ESRCH;
	}

	if (d->ipld_dests != NULL) {
		return EBUSY;
	}

	ipf_dstlist_table_deref(d);

	return 0;
}


static void
ipf_dstlist_table_flush(dst)
	ippool_dst_t *dst;
{

	ipf_dstlist_table_clearnodes(dst);

	if (dst->ipld_ref != 1)
		return;

	KFREE(dst);
}


static int
ipf_dstlist_table_deref(arg)
	void *arg;
{
	ippool_dst_t *d = arg;

	ipf_dstlist_table_clearnodes(d);

	d->ipld_ref--;
	if (d->ipld_ref != 1) {
		d->ipld_flags |= IPDST_DELETE;
		return d->ipld_ref;
	}

	KFREE(d);

	return 0;
}


static void
ipf_dstlist_table_clearnodes(dst)
	ippool_dst_t *dst;
{
	ipf_dstnode_t *node;

	while ((node = dst->ipld_dests) != NULL) {
		ipf_dstlist_node_free(node);
	}
}


static void *
ipf_dstlist_table_find(unit, name)
	int unit;
	char *name;
{
	ippool_dst_t *d;

	for (d = dstlist[unit]; d != NULL; d = d->ipld_next) {
		if ((d->ipld_unit == unit) &&
		    !strncmp(d->ipld_name, name, FR_GROUPLEN)) {
			return d;
		}
	}

	return NULL;
}


static ipf_dstnode_t *
ipf_dstlist_select(d)
	ippool_dst_t *d;
{
	ipf_dstnode_t *node, *sel;
	U_QUAD_T bytes;
	int connects;

	if (d->ipld_dests == NULL)
		return NULL;

	MUTEX_ENTER(&d->ipld_lock);

	switch (d->ipld_policy)
	{
	case IPLDP_ROUNDROBIN:
		sel = d->ipld_selected;
		if (sel == NULL) {
			sel = d->ipld_dests;
		} else {
			sel = sel->ipfd_next;
			if (sel == NULL)
				sel = d->ipld_dests;
		}
		d->ipld_selected = sel;
		break;

	case IPLDP_BYTES:
		if (d->ipld_selected == NULL) {
			d->ipld_selected = d->ipld_dests;
			sel = d->ipld_selected;
			break;
		}

		sel = d->ipld_selected;
		bytes = sel->ipfd_bytes;
		for (node = sel->ipfd_next; node != d->ipld_selected; ) {
			if (node == NULL)
				node = d->ipld_dests;
			if (node->ipfd_bytes < bytes)
				sel = node;
		}

		d->ipld_selected = sel;
		break;

	case IPLDP_CONNECTION:
		if (d->ipld_selected == NULL) {
			d->ipld_selected = d->ipld_dests;
			sel = d->ipld_selected;
			break;
		}

		sel = d->ipld_selected;
		connects = sel->ipfd_states;
		for (node = sel->ipfd_next; node != d->ipld_selected; ) {
			if (node == NULL)
				node = d->ipld_dests;
			if (node->ipfd_states < connects)
				sel = node;
		}

		d->ipld_selected = sel;
		break;

	default :
		sel = NULL;
		break;
	}

	MUTEX_EXIT(&d->ipld_lock);

	return sel;
}


void *
ipf_dstlist_select_ref(unit, name)
	int unit;
	char *name;
{
	ipf_dstnode_t *node;
	ippool_dst_t *d;

	d = ipf_dstlist_table_find(unit, name);
	if (d == NULL) {
		return (void *)-1;
	}

	node = ipf_dstlist_select(d);
	if (node == NULL) {
		return (void *)-1;
	}

	MUTEX_ENTER(&node->ipfd_lock);
	node->ipfd_states++;
	node->ipfd_ref++;
	MUTEX_EXIT(&node->ipfd_lock);

	return node;
}


void
ipf_dstlist_unselect_deref(node)
	ipf_dstnode_t *node;
{

	if (node == NULL || node == (void *)-1)
		return;

	MUTEX_ENTER(&node->ipfd_lock);
	node->ipfd_states--;

	if (node->ipfd_ref > 1) {
		node->ipfd_ref--;
		MUTEX_EXIT(&node->ipfd_lock);
	} else {
		ipf_dstlist_node_free(node);
	}
}
