/*
 * Copyright (C) 1993-2001, 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 */
#if defined(KERNEL) || defined(_KERNEL)
# undef KERNEL
# undef _KERNEL
# define        KERNEL	1
# define        _KERNEL	1
#endif
#include <sys/param.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/file.h>
#if !defined(_KERNEL)
# include <stdlib.h>
# include <string.h>
# define _KERNEL
# ifdef __OpenBSD__
struct file;
# endif
# include <sys/uio.h>
# undef _KERNEL
#endif
#include <sys/socket.h>
#if defined(__FreeBSD_version) && (__FreeBSD_version >= 300000)
# include <sys/malloc.h>
#endif
#if defined(__FreeBSD__)
#  include <sys/cdefs.h>
#  include <sys/proc.h>
#endif
#if !defined(__svr4__) && !defined(__SVR4) && !defined(__hpux) && \
    !defined(linux)
# include <sys/mbuf.h>
#endif
#if defined(_KERNEL)
# include <sys/systm.h>
#else
# include <stdio.h>
#endif
#include <netinet/in.h>
#include <net/if.h>

#include "netinet/ip_compat.h"
#include "netinet/ip_fil.h"
#include "netinet/ip_lookup.h"
#include "netinet/ip_htable.h"
/* END OF INCLUDES */

#if !defined(lint)
static const char rcsid[] = "@(#)$Id$";
#endif

#ifdef	IPFILTER_LOOKUP
static iphtent_t *ipf_iphmfind __P((iphtable_t *, struct in_addr *));
# ifdef USE_INET6
static iphtent_t *ipf_iphmfind6 __P((iphtable_t *, i6addr_t *));
# endif
static	u_long	ipht_nomem[IPL_LOGSIZE] = { 0, 0, 0, 0, 0, 0, 0, 0 };
static	u_long	ipf_nhtables[IPL_LOGSIZE] = { 0, 0, 0, 0, 0, 0, 0, 0 };
static	u_long	ipf_nhtnodes[IPL_LOGSIZE] = { 0, 0, 0, 0, 0, 0, 0, 0 };

iphtable_t *ipf_htables[IPL_LOGSIZE] = { NULL, NULL, NULL, NULL,
					 NULL, NULL, NULL, NULL };


void
ipf_htable_unload()
{
	iplookupflush_t fop;

	fop.iplf_unit = IPL_LOGALL;
	ipf_htable_flush(&fop);
}


int
ipf_htable_getstats(op)
	iplookupop_t *op;
{
	iphtstat_t stats;

	if (op->iplo_size != sizeof(stats)) {
		ipf_interror = 30001;
		return EINVAL;
	}

	stats.iphs_tables = ipf_htables[op->iplo_unit];
	stats.iphs_numtables = ipf_nhtables[op->iplo_unit];
	stats.iphs_numnodes = ipf_nhtnodes[op->iplo_unit];
	stats.iphs_nomem = ipht_nomem[op->iplo_unit];

	if (COPYOUT(&stats, op->iplo_struct, sizeof(stats)) != 0) {
		ipf_interror = 30013;
		return EFAULT;
	}
	return 0;

}


/*
 * Create a new hash table using the template passed.
 */
int
ipf_htable_create(op)
	iplookupop_t *op;
{
	iphtable_t *iph, *oiph;
	char name[FR_GROUPLEN];
	int err, i, unit;

	unit = op->iplo_unit;
	if ((op->iplo_arg & IPHASH_ANON) == 0) {
		iph = ipf_htable_exists(unit, op->iplo_name);
		if (iph != NULL) {
			if ((iph->iph_flags & IPHASH_DELETE) == 0) {
				ipf_interror = 30004;
				return EEXIST;
			}
			iph->iph_flags &= ~IPHASH_DELETE;
			return 0;
		}
	}

	KMALLOC(iph, iphtable_t *);
	if (iph == NULL) {
		ipht_nomem[op->iplo_unit]++;
		ipf_interror = 30002;
		return ENOMEM;
	}
	err = COPYIN(op->iplo_struct, iph, sizeof(*iph));
	if (err != 0) {
		KFREE(iph);
		ipf_interror = 30003;
		return EFAULT;
	}

	if (iph->iph_unit != unit) {
		ipf_interror = 30005;
		return EINVAL;
	}

	if ((op->iplo_arg & IPHASH_ANON) != 0) {
		i = IPHASH_ANON;
		do {
			i++;
#if defined(SNPRINTF) && defined(_KERNEL)
			SNPRINTF(name, sizeof(name), "%u", i);
#else
			(void)sprintf(name, "%u", i);
#endif
			for (oiph = ipf_htables[unit]; oiph != NULL;
			     oiph = oiph->iph_next)
				if (strncmp(oiph->iph_name, name,
					    sizeof(oiph->iph_name)) == 0)
					break;
		} while (oiph != NULL);

		(void)strncpy(iph->iph_name, name, sizeof(iph->iph_name));
		(void)strncpy(op->iplo_name, name, sizeof(op->iplo_name));
		iph->iph_type |= IPHASH_ANON;
	}

	KMALLOCS(iph->iph_table, iphtent_t **,
		 iph->iph_size * sizeof(*iph->iph_table));
	if (iph->iph_table == NULL) {
		KFREE(iph);
		ipht_nomem[unit]++;
		ipf_interror = 30006;
		return ENOMEM;
	}

	bzero((char *)iph->iph_table, iph->iph_size * sizeof(*iph->iph_table));
	iph->iph_maskset[0] = 0;
	iph->iph_maskset[1] = 0;
	iph->iph_maskset[2] = 0;
	iph->iph_maskset[3] = 0;
	iph->iph_list = NULL;

	iph->iph_ref = 1;
	iph->iph_next = ipf_htables[unit];
	iph->iph_pnext = &ipf_htables[unit];
	if (ipf_htables[unit] != NULL)
		ipf_htables[unit]->iph_pnext = &iph->iph_next;
	ipf_htables[unit] = iph;

	ipf_nhtables[unit]++;

	return 0;
}


/*
 */
int
ipf_htable_destroy(unit, name)
	int unit;
	char *name;
{
	iphtable_t *iph;

	iph = ipf_htable_find(unit, name);
	if (iph == NULL) {
		ipf_interror = 30007;
		return ESRCH;
	}

	if (iph->iph_unit != unit) {
		ipf_interror = 30008;
		return EINVAL;
	}

	if (iph->iph_ref != 0) {
		ipf_htable_clear(iph);
		iph->iph_flags |= IPHASH_DELETE;
		return 0;
	}

	ipf_htable_remove(iph);

	return 0;
}


int
ipf_htable_clear(iph)
	iphtable_t *iph;
{
	iphtent_t *ipe;

	while ((ipe = iph->iph_list) != NULL)
		if (ipf_htent_remove(iph, ipe) != 0)
			return 1;
	return 0;
}


int
ipf_htable_remove(iph)
	iphtable_t *iph;
{

	if (ipf_htable_clear(iph) != 0)
		return 1;

	if (iph->iph_pnext != NULL)
		*iph->iph_pnext = iph->iph_next;
	if (iph->iph_next != NULL)
		iph->iph_next->iph_pnext = iph->iph_pnext;

	ipf_nhtables[iph->iph_unit]--;

	return ipf_htable_deref(iph);
}


/*
 * Delete an entry from a hash table.
 */
int
ipf_htent_remove(iph, ipe)
	iphtable_t *iph;
	iphtent_t *ipe;
{

	if (ipe->ipe_phnext != NULL)
		*ipe->ipe_phnext = ipe->ipe_hnext;
	if (ipe->ipe_hnext != NULL)
		ipe->ipe_hnext->ipe_phnext = ipe->ipe_phnext;

	if (ipe->ipe_pnext != NULL)
		*ipe->ipe_pnext = ipe->ipe_next;
	if (ipe->ipe_next != NULL)
		ipe->ipe_next->ipe_pnext = ipe->ipe_pnext;

	switch (iph->iph_type & ~IPHASH_ANON)
	{
	case IPHASH_GROUPMAP :
		if (ipe->ipe_group != NULL)
			ipf_group_del(ipe->ipe_group, IPL_LOGIPF, ipf_active);
		break;

	default :
		ipe->ipe_ptr = NULL;
		ipe->ipe_value = 0;
		break;
	}

	return ipf_htent_deref(ipe);
}


int
ipf_htable_deref(iph)
	iphtable_t *iph;
{
	int refs;

	iph->iph_ref--;
	refs = iph->iph_ref;

	if (iph->iph_ref == 0) {
		KFREES(iph->iph_table, iph->iph_size * sizeof(*iph->iph_table));
		KFREE(iph);
	}

	return refs;
}


int
ipf_htent_deref(ipe)
	iphtent_t *ipe;
{

	ipe->ipe_ref--;
	if (ipe->ipe_ref == 0) {
		ipf_nhtnodes[ipe->ipe_unit]--;

		KFREE(ipe);

		return 0;
	}

	return ipe->ipe_ref;
}


iphtable_t *
ipf_htable_exists(unit, name)
	int unit;
	char *name;
{
	iphtable_t *iph;

	for (iph = ipf_htables[unit]; iph != NULL; iph = iph->iph_next)
		if (strncmp(iph->iph_name, name, sizeof(iph->iph_name)) == 0)
			break;
	return iph;
}


iphtable_t *
ipf_htable_find(unit, name)
	int unit;
	char *name;
{
	iphtable_t *iph;

	iph = ipf_htable_exists(unit, name);
	if ((iph != NULL) && (iph->iph_flags & IPHASH_DELETE) == 0)
		return iph;

	return NULL;
}


size_t
ipf_htable_flush(op)
	iplookupflush_t *op;
{
	iphtable_t *iph;
	size_t freed;
	int i;

	freed = 0;

	for (i = 0; i <= IPL_LOGMAX; i++) {
		if (op->iplf_unit == i || op->iplf_unit == IPL_LOGALL) {
			while ((iph = ipf_htables[i]) != NULL) {
				if (ipf_htable_remove(iph) == 0) {
					freed++;
				} else {
					iph->iph_flags |= IPHASH_DELETE;
				}
			}
		}
	}

	return freed;
}


/*
 * Add an entry to a hash table.
 */
int
ipf_htent_insert(iph, ipeo)
	iphtable_t *iph;
	iphtent_t *ipeo;
{
	iphtent_t *ipe;
	u_int hv;
	int bits;

	KMALLOC(ipe, iphtent_t *);
	if (ipe == NULL)
		return -1;

	bcopy((char *)ipeo, (char *)ipe, sizeof(*ipe));
	ipe->ipe_addr.i6[0] &= ipe->ipe_mask.i6[0];
	ipe->ipe_addr.i6[1] &= ipe->ipe_mask.i6[1];
	ipe->ipe_addr.i6[2] &= ipe->ipe_mask.i6[2];
	ipe->ipe_addr.i6[3] &= ipe->ipe_mask.i6[3];
	if (ipe->ipe_family == AF_INET) {
		bits = count4bits(ipe->ipe_mask.in4_addr);
		ipe->ipe_addr.i6[0] = ntohl(ipe->ipe_addr.i6[0]);
		ipe->ipe_mask.i6[0] = ntohl(ipe->ipe_mask.i6[0]);
		hv = IPE_V4_HASH_FN(ipe->ipe_addr.in4_addr,
				    ipe->ipe_mask.in4_addr, iph->iph_size);
	} else
#ifdef USE_INET6
	if (ipe->ipe_family == AF_INET6) {
		bits = count6bits(ipe->ipe_mask.i6);
		ipe->ipe_addr.i6[0] = ntohl(ipe->ipe_addr.i6[0]);
		ipe->ipe_addr.i6[1] = ntohl(ipe->ipe_addr.i6[1]);
		ipe->ipe_addr.i6[2] = ntohl(ipe->ipe_addr.i6[2]);
		ipe->ipe_addr.i6[3] = ntohl(ipe->ipe_addr.i6[3]);
		ipe->ipe_mask.i6[0] = ntohl(ipe->ipe_mask.i6[0]);
		ipe->ipe_mask.i6[1] = ntohl(ipe->ipe_mask.i6[1]);
		ipe->ipe_mask.i6[2] = ntohl(ipe->ipe_mask.i6[2]);
		ipe->ipe_mask.i6[3] = ntohl(ipe->ipe_mask.i6[3]);
		hv = IPE_V6_HASH_FN(ipe->ipe_addr.i6,
				    ipe->ipe_mask.i6, iph->iph_size);
	} else
#endif
		return -1;

	ipe->ipe_ref = 1;
	ipe->ipe_hnext = iph->iph_table[hv];
	ipe->ipe_phnext = iph->iph_table + hv;

	if (iph->iph_table[hv] != NULL)
		iph->iph_table[hv]->ipe_phnext = &ipe->ipe_hnext;

	ipe->ipe_next = iph->iph_list;
	ipe->ipe_pnext = &iph->iph_list;
	if (ipe->ipe_next != NULL)
		ipe->ipe_next->ipe_pnext = &ipe->ipe_next;
	iph->iph_list = ipe;

	iph->iph_table[hv] = ipe;
	if (ipe->ipe_family == AF_INET) {
		if ((bits >= 0) && (bits != 32))
			iph->iph_maskset[0] |= 1 << bits;
	}
#ifdef USE_INET6
	else if (ipe->ipe_family == AF_INET6) {
		if ((bits >= 0) && (bits != 128)) {
			if (bits >= 96)
				iph->iph_maskset[3] |= 1 << (bits - 96);
			else if (bits >= 64)
				iph->iph_maskset[2] |= 1 << (bits - 64);
			else if (bits >= 32)
				iph->iph_maskset[1] |= 1 << (bits - 32);
			else
				iph->iph_maskset[0] |= 1 << bits;
		}
	}
#endif

	switch (iph->iph_type & ~IPHASH_ANON)
	{
	case IPHASH_GROUPMAP :
		ipe->ipe_ptr = ipf_group_add(ipe->ipe_group, NULL,
					   iph->iph_flags, IPL_LOGIPF,
					   ipf_active);
		break;

	default :
		ipe->ipe_ptr = NULL;
		ipe->ipe_value = 0;
		break;
	}

	ipe->ipe_unit = iph->iph_unit;
	ipf_nhtnodes[ipe->ipe_unit]++;

	return 0;
}


/* search a hash table for a matching entry and return the pointer stored in */
/* it for use as the next group of rules to search.                          */
void *
ipf_iphmfindgroup(tptr, aptr)
	void *tptr, *aptr;
{
	struct in_addr *addr;
	iphtable_t *iph;
	iphtent_t *ipe;
	void *rval;

	READ_ENTER(&ipf_poolrw);
	iph = tptr;
	addr = aptr;

	ipe = ipf_iphmfind(iph, addr);
	if (ipe != NULL)
		rval = ipe->ipe_ptr;
	else
		rval = NULL;
	RWLOCK_EXIT(&ipf_poolrw);
	return rval;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_iphmfindip                                              */
/* Returns:     int     - 0 == +ve match, -1 == error, 1 == -ve/no match    */
/* Parameters:  tptr(I)      - pointer to the pool to search                */
/*              ipversion(I) - IP protocol version (4 or 6)                 */
/*              aptr(I)      - pointer to address information               */
/*                                                                          */
/* Search the hash table for a given address and return a search result.    */
/* ------------------------------------------------------------------------ */
int
ipf_iphmfindip(tptr, ipversion, aptr)
	void *tptr, *aptr;
	int ipversion;
{
	struct in_addr *addr;
	iphtable_t *iph;
	iphtent_t *ipe;
	int rval;

	if (tptr == NULL || aptr == NULL)
		return -1;

	iph = tptr;
	addr = aptr;

	READ_ENTER(&ipf_poolrw);
	if (ipversion == 4) {
		ipe = ipf_iphmfind(iph, addr);
#ifdef USE_INET6
	} else if (ipversion == 6) {
		ipe = ipf_iphmfind6(iph, (i6addr_t *)addr);
#endif
	} else {
		ipe = NULL;
	}

	if (ipe != NULL)
		rval = 0;
	else
		rval = 1;
	RWLOCK_EXIT(&ipf_poolrw);
	return rval;
}


/* Locks:  ipf_poolrw */
static iphtent_t *
ipf_iphmfind(iph, addr)
	iphtable_t *iph;
	struct in_addr *addr;
{
	u_32_t hmsk, msk, ips;
	iphtent_t *ipe;
	u_int hv;

	hmsk = iph->iph_maskset[0];
	msk = 0xffffffff;
maskloop:
	ips = ntohl(addr->s_addr) & msk;
	hv = IPE_V4_HASH_FN(ips, msk, iph->iph_size);
	for (ipe = iph->iph_table[hv]; (ipe != NULL); ipe = ipe->ipe_hnext) {
		if ((ipe->ipe_family != AF_INET) ||
		    (ipe->ipe_mask.in4_addr != msk) ||
		    (ipe->ipe_addr.in4_addr != ips)) {
			continue;
		}
		break;
	}

	if ((ipe == NULL) && (hmsk != 0)) {
		while (hmsk != 0) {
			msk <<= 1;
			if (hmsk & 0x80000000)
				break;
			hmsk <<= 1;
		}
		if (hmsk != 0) {
			hmsk <<= 1;
			goto maskloop;
		}
	}
	return ipe;
}


int
ipf_htable_getnext(token, ilp)
	ipftoken_t *token;
	ipflookupiter_t *ilp;
{
	iphtent_t *node, zn, *nextnode;
	iphtable_t *iph, zp, *nextiph;
	int err;

	err = 0;
	iph = NULL;
	node = NULL;
	nextiph = NULL;
	nextnode = NULL;

	READ_ENTER(&ipf_poolrw);

	switch (ilp->ili_otype)
	{
	case IPFLOOKUPITER_LIST :
		iph = token->ipt_data;
		if (iph == NULL) {
			nextiph = ipf_htables[(int)ilp->ili_unit];
		} else {
			nextiph = iph->iph_next;
		}

		if (nextiph != NULL) {
			ATOMIC_INC(nextiph->iph_ref);
			token->ipt_data = nextiph;
		} else {
			bzero((char *)&zp, sizeof(zp));
			nextiph = &zp;
			token->ipt_data = NULL;
		}
		break;

	case IPFLOOKUPITER_NODE :
		node = token->ipt_data;
		if (node == NULL) {
			iph = ipf_htable_find(ilp->ili_unit, ilp->ili_name);
			if (iph == NULL) {
				ipf_interror = 30009;
				err = ESRCH;
			} else {
				nextnode = iph->iph_list;
			}
		} else {
			nextnode = node->ipe_next;
		}

		if (nextnode != NULL) {
			ATOMIC_INC(nextnode->ipe_ref);
			token->ipt_data = nextnode;
		} else {
			bzero((char *)&zn, sizeof(zn));
			nextnode = &zn;
			token->ipt_data = NULL;
		}
		break;
	default :
		ipf_interror = 30010;
		err = EINVAL;
		break;
	}

	RWLOCK_EXIT(&ipf_poolrw);
	if (err != 0)
		return err;

	switch (ilp->ili_otype)
	{
	case IPFLOOKUPITER_LIST :
		if (iph != NULL) {
			WRITE_ENTER(&ipf_poolrw);
			ipf_htable_deref(iph);
			RWLOCK_EXIT(&ipf_poolrw);
		}

		err = COPYOUT(nextiph, ilp->ili_data, sizeof(*nextiph));
		if (err != 0) {
			ipf_interror = 30011;
			err = EFAULT;
		}
		break;

	case IPFLOOKUPITER_NODE :
		if (node != NULL) {
			WRITE_ENTER(&ipf_poolrw);
			ipf_htent_deref(node);
			RWLOCK_EXIT(&ipf_poolrw);
		}

		err = COPYOUT(nextnode, ilp->ili_data, sizeof(*nextnode));
		if (err != 0) {
			ipf_interror = 30012;
			err = EFAULT;
		}
		break;
	}

	return err;
}


void
ipf_htable_iterderef(otype, unit, data)
	u_int otype;
	int unit;
	void *data;
{

	if (data == NULL)
		return;

	if (unit < 0 || unit > IPL_LOGMAX)
		return;

	switch (otype)
	{
	case IPFLOOKUPITER_LIST :
		WRITE_ENTER(&ipf_poolrw);
		ipf_htable_deref((iphtable_t *)data);
		RWLOCK_EXIT(&ipf_poolrw);
		break;

	case IPFLOOKUPITER_NODE :
		WRITE_ENTER(&ipf_poolrw);
		ipf_htent_deref((iphtent_t *)data);
		RWLOCK_EXIT(&ipf_poolrw);
		break;
	default :
		break;
	}
}


# ifdef USE_INET6
/* Locks:  ipf_poolrw */
static iphtent_t *
ipf_iphmfind6(iph, addr)
	iphtable_t *iph;
	i6addr_t *addr;
{
	i6addr_t msk, ips;
	iphtent_t *ipe;
	u_32_t hmsk;
	u_int hv;
	int i;

	for (i = 3, hmsk = iph->iph_maskset[3]; (hmsk == 0) && (i >= 0); i--)
		hmsk = iph->iph_maskset[i];

	msk.i6[0] = 0xffffffff;
	msk.i6[1] = 0xffffffff;
	msk.i6[2] = 0xffffffff;
	msk.i6[3] = 0xffffffff;
	ips.i6[0] = ntohl(addr->i6[0]);
	ips.i6[1] = ntohl(addr->i6[1]);
	ips.i6[2] = ntohl(addr->i6[2]);
	ips.i6[3] = ntohl(addr->i6[3]);
maskloop:
	if (i >= 0)
		ips.i6[i] = ntohl(addr->i6[i]) & msk.i6[i];
	hv = IPE_V6_HASH_FN(ips.i6, msk.i6, iph->iph_size);
	for (ipe = iph->iph_table[hv]; (ipe != NULL); ipe = ipe->ipe_next) {
		if ((ipe->ipe_family != AF_INET6) ||
		    IP6_NEQ(&ipe->ipe_mask, &msk) ||
		    IP6_NEQ(&ipe->ipe_addr, &ips)) {
			continue;
		}
		break;
	}

	if ((ipe == NULL) && (i >= 0)) {
nextmask:
		if (hmsk != 0) {
			while (hmsk != 0) {
				msk.i6[i] <<= 1;
				if (hmsk & 0x80000000)
					break;
				hmsk <<= 1;
			}
			if (hmsk != 0) {
				hmsk <<= 1;
				goto maskloop;
			}
		} else if (i >= 0) {
			ips.i6[i] = 0;
			msk.i6[i] = 0;
			i--;
			hmsk = iph->iph_maskset[i];
			goto nextmask;
		}
	}
	return ipe;
}
# endif
#endif /* IPFILTER_LOOKUP */
