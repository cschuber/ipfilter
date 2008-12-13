/*
 * Copyright (c) 1988, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)radix.c	8.6 (Berkeley) 10/17/95
 */

/*
 * Routines to build and maintain radix trees for routing lookups.
 */
#if defined(KERNEL) || defined(_KERNEL)
# undef KERNEL
# undef _KERNEL
# define        KERNEL  1
# define        _KERNEL 1
#endif
#define __SYS_ATOMIC_OPS_H__
#if !defined(__svr4__) && !defined(__SVR4) && !defined(__osf__) && \
    !defined(__hpux) && !defined(__sgi)
#include <sys/cdefs.h>
#endif
#ifndef __P
# ifdef __STDC__
#  define       __P(x)  x
# else
#  define       __P(x)  ()
# endif
#endif
#ifdef __osf__
# define CONST
# define _IPV6_SWTAB_H
# define _PROTO_NET_H_
# define _PROTO_IPV6_H
# include <sys/malloc.h>
#endif

#include <sys/param.h>
#ifdef	_KERNEL
#include <sys/systm.h>
#else
void panic __P((char *str));
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#endif
#ifdef __hpux
#include <syslog.h>
#else
#include <sys/syslog.h>
#endif
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#ifdef SOLARIS2
# define _RADIX_H_
#endif
#include "netinet/ip_compat.h"
#include "netinet/ip_fil.h"
#ifdef SOLARIS2
# undef _RADIX_H_
#endif
/* END OF INCLUDES */
#include "radix_ipf.h"
#ifndef min
# define	min	MIN
#endif
#ifndef max
# define	max	MAX
#endif

typedef struct radix_softc_s {
	int			max_keylen;
	struct ipf_radix_mask	*rn_mkfreelist;
	struct ipf_radix_node_head	*mask_rnhead;
	u_char			*addmask_key;
	u_char			*rn_zeros;
	u_char			*rn_ones;
#ifdef RN_DEBUG
	int			rn_nodenum;
	struct ipf_radix_node	*rn_clist;
	int			rn_saveinfo;
	int			rn_debug;
#endif
} radix_softc_t;

static u_char normal_chars[] = {0, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff};

#undef bcmp
#define bcmp(a, b, l) (l == 0 ? 0 : bcmp((void *)(a), (void *)(b), (u_long)l))

static int ipf_rn_satisfies_leaf __P((radix_softc_t *, u_char *, struct ipf_radix_node *, int));
static int ipf_rn_lexobetter __P((void *, void *));
static struct ipf_radix_mask *ipf_rn_new_ipf_radix_mask __P((radix_softc_t *, struct ipf_radix_node *,
    struct ipf_radix_mask *));
static int ipf_rn_freenode __P((void *, struct ipf_radix_node *, void *));
#if defined(AIX) && !defined(_KERNEL)
struct ipf_radix_node *ipf_rn_match __P((void *, struct ipf_radix_node_head *));
struct ipf_radix_node *ipf_rn_addmask __P((radix_softc_t *, void *, int, int));
#define	Bcopy(x, y, z)	bcopy(x, y, z)
#endif

/*
 * The data structure for the keys is a radix tree with one way
 * branching removed.  The index rn_b at an internal node n represents a bit
 * position to be tested.  The tree is arranged so that all descendants
 * of a node n have keys whose bits all agree up to position rn_b - 1.
 * (We say the index of n is rn_b.)
 *
 * There is at least one descendant which has a one bit at position rn_b,
 * and at least one with a zero there.
 *
 * A route is determined by a pair of key and mask.  We require that the
 * bit-wise logical and of the key and mask to be the key.
 * We define the index of a route to associated with the mask to be
 * the first bit number in the mask where 0 occurs (with bit number 0
 * representing the highest order bit).
 *
 * We say a mask is normal if every bit is 0, past the index of the mask.
 * If a node n has a descendant (k, m) with index(m) == index(n) == rn_b,
 * and m is a normal mask, then the route applies to every descendant of n.
 * If the index(m) < rn_b, this implies the trailing last few bits of k
 * before bit b are all 0, (and hence consequently true of every descendant
 * of n), so the route applies to all descendants of the node as well.
 *
 * Similar logic shows that a non-normal mask m such that
 * index(m) <= index(n) could potentially apply to many children of n.
 * Thus, for each non-host route, we attach its mask to a list at an internal
 * node as high in the tree as we can go.
 *
 * The present version of the code makes use of normal routes in short-
 * circuiting an explicit mask and compare operation when testing whether
 * a key satisfies a normal route, and also in remembering the unique leaf
 * that governs a subtree.
 */

struct ipf_radix_node *
ipf_rn_search(v_arg, head)
	void *v_arg;
	struct ipf_radix_node *head;
{
	struct ipf_radix_node *x;
	u_char *v;

	for (x = head, v = v_arg; x->rn_b >= 0;) {
		if (x->rn_bmask & v[x->rn_off])
			x = x->rn_r;
		else
			x = x->rn_l;
	}
	return (x);
}

struct ipf_radix_node *
ipf_rn_search_m(v_arg, head, m_arg)
	struct ipf_radix_node *head;
	void *v_arg, *m_arg;
{
	struct ipf_radix_node *x;
	u_char *v = v_arg, *m = m_arg;

	for (x = head; x->rn_b >= 0;) {
		if ((x->rn_bmask & m[x->rn_off]) &&
		    (x->rn_bmask & v[x->rn_off]))
			x = x->rn_r;
		else
			x = x->rn_l;
	}
	return x;
}

int
ipf_rn_refines(m_arg, n_arg)
	void *m_arg, *n_arg;
{
	u_char *m = m_arg, *n = n_arg;
	u_char *lim, *lim2 = lim = n + *(u_char *)n;
	int longer = (*(u_char *)n++) - (int)(*(u_char *)m++);
	int masks_are_equal = 1;

	if (longer > 0)
		lim -= longer;
	while (n < lim) {
		if (*n & ~(*m))
			return 0;
		if (*n++ != *m++)
			masks_are_equal = 0;
	}
	while (n < lim2)
		if (*n++)
			return 0;
	if (masks_are_equal && (longer < 0))
		for (lim2 = m - longer; m < lim2; )
			if (*m++)
				return 1;
	return (!masks_are_equal);
}

struct ipf_radix_node *
ipf_rn_lookup(soft, v_arg, m_arg, head)
	void *soft, *v_arg, *m_arg;
	struct ipf_radix_node_head *head;
{
	radix_softc_t *softr = soft;
	struct ipf_radix_node *x;
	u_char *netmask = 0;

	if (m_arg) {
		if ((x = ipf_rn_addmask(softr, m_arg, 1,
					head->rnh_treetop->rn_off)) == 0)
			return (0);
		netmask = x->rn_key;
	}
	x = ipf_rn_match(soft, v_arg, head);
	if (x && netmask) {
		while (x && x->rn_mask != netmask)
			x = x->rn_dupedkey;
	}
	return x;
}

static int
ipf_rn_satisfies_leaf(softr, trial, leaf, skip)
	radix_softc_t *softr;
	u_char *trial;
	struct ipf_radix_node *leaf;
	int skip;
{
	u_char *cp = trial, *cp2 = leaf->rn_key, *cp3 = leaf->rn_mask;
	u_char *cplim;
	int length = min(*(u_char *)cp, *(u_char *)cp2);

	if (cp3 == 0)
		cp3 = softr->rn_ones;
	else
		length = min(length, *(u_char *)cp3);
	cplim = cp + length;
	cp3 += skip;
	cp2 += skip;
	for (cp += skip; cp < cplim; cp++, cp2++, cp3++)
		if ((*cp ^ *cp2) & *cp3)
			return 0;
	return 1;
}

struct ipf_radix_node *
ipf_rn_match(soft, v_arg, head)
	void *soft, *v_arg;
	struct ipf_radix_node_head *head;
{
	radix_softc_t *softr = soft;
	u_char *v = v_arg;
	struct ipf_radix_node *t = head->rnh_treetop, *x;
	u_char *cp = v, *cp2;
	u_char *cplim;
	struct ipf_radix_node *saved_t, *top = t;
	int off = t->rn_off, vlen = *(u_char *)cp, matched_off;
	int test, b, rn_b;

	/*
	 * Open code rn_search(v, top) to avoid overhead of extra
	 * subroutine call.
	 */
	for (; t->rn_b >= 0; ) {
		if (t->rn_bmask & cp[t->rn_off])
			t = t->rn_r;
		else
			t = t->rn_l;
	}
	/*
	 * See if we match exactly as a host destination
	 * or at least learn how many bits match, for normal mask finesse.
	 *
	 * It doesn't hurt us to limit how many bytes to check
	 * to the length of the mask, since if it matches we had a genuine
	 * match and the leaf we have is the most specific one anyway;
	 * if it didn't match with a shorter length it would fail
	 * with a long one.  This wins big for class B&C netmasks which
	 * are probably the most common case...
	 */
	if (t->rn_mask)
		vlen = *(u_char *)t->rn_mask;
	cp += off;
	cp2 = t->rn_key + off;
	cplim = v + vlen;
	for (; cp < cplim; cp++, cp2++)
		if (*cp != *cp2)
			goto on1;
	/*
	 * This extra grot is in case we are explicitly asked
	 * to look up the default.  Ugh!
	 */
	if ((t->rn_flags & RNF_ROOT) && t->rn_dupedkey)
		t = t->rn_dupedkey;
	return t;
on1:
	test = (*cp ^ *cp2) & 0xff; /* find first bit that differs */
	for (b = 7; (test >>= 1) > 0;)
		b--;
	matched_off = cp - v;
	b += matched_off << 3;
	rn_b = -1 - b;
	/*
	 * If there is a host route in a duped-key chain, it will be first.
	 */
	if ((saved_t = t)->rn_mask == 0)
		t = t->rn_dupedkey;
	for (; t; t = t->rn_dupedkey)
		/*
		 * Even if we don't match exactly as a host,
		 * we may match if the leaf we wound up at is
		 * a route to a net.
		 */
		if (t->rn_flags & RNF_NORMAL) {
			if (rn_b <= t->rn_b)
				return t;
		} else if (ipf_rn_satisfies_leaf(softr, v, t, matched_off))
				return t;
	t = saved_t;
	/* start searching up the tree */
	do {
		struct ipf_radix_mask *m;
		t = t->rn_p;
		m = t->rn_mklist;
		if (m) {
			/*
			 * If non-contiguous masks ever become important
			 * we can restore the masking and open coding of
			 * the search and satisfaction test and put the
			 * calculation of "off" back before the "do".
			 */
			do {
				if (m->rm_flags & RNF_NORMAL) {
					if (rn_b <= m->rm_b)
						return (m->rm_leaf);
				} else {
					off = min(t->rn_off, matched_off);
					x = ipf_rn_search_m(v, t, m->rm_mask);
					while (x && x->rn_mask != m->rm_mask)
						x = x->rn_dupedkey;
					if (x && ipf_rn_satisfies_leaf(softr, v, x, off))
						return x;
				}
				m = m->rm_mklist;
			} while (m);
		}
	} while (t != top);
	return 0;
}


struct ipf_radix_node *
ipf_rn_newpair(v, b, nodes)
	void *v;
	int b;
	struct ipf_radix_node nodes[2];
{
	struct ipf_radix_node *tt = nodes, *t = tt + 1;
	t->rn_b = b;
	t->rn_bmask = 0x80 >> (b & 7);
	t->rn_l = tt;
	t->rn_off = b >> 3;
	tt->rn_b = -1;
	tt->rn_key = (void *)v;
	tt->rn_p = t;
	tt->rn_flags = t->rn_flags = RNF_ACTIVE;
#ifdef RN_DEBUG
	tt->rn_info = rn_nodenum++;
	t->rn_info = rn_nodenum++;
	tt->rn_twin = t;
	tt->rn_ybro = rn_clist;
	rn_clist = tt;
#endif
	return t;
}

struct ipf_radix_node *
ipf_rn_insert(soft, v_arg, head, dupentry, nodes)
	void *soft, *v_arg;
	struct ipf_radix_node_head *head;
	int *dupentry;
	struct ipf_radix_node nodes[2];
{
	u_char *v = v_arg;
	struct ipf_radix_node *top = head->rnh_treetop;
	int head_off = top->rn_off, vlen = (int)*((u_char *)v);
	struct ipf_radix_node *t = ipf_rn_search(v_arg, top);
	u_char *cp = v + head_off;
	int b;
	struct ipf_radix_node *tt;

#ifdef	RN_DEBUG
	if (softr->rn_debug)
		log(LOG_DEBUG, "rn_insert(%p,%p,%p,%p)\n", v_arg, head, dupentry, nodes);
#endif
    	/*
	 * Find first bit at which v and t->rn_key differ
	 */
    {
	u_char *cp2 = t->rn_key + head_off;
	int cmp_res;
	u_char *cplim = v + vlen;

	while (cp < cplim)
		if (*cp2++ != *cp++)
			goto on1;
	*dupentry = 1;
	return t;
on1:
	*dupentry = 0;
	cmp_res = (cp[-1] ^ cp2[-1]) & 0xff;
	for (b = (cp - v) << 3; cmp_res; b--)
		cmp_res >>= 1;
    }
    {
	struct ipf_radix_node *p, *x = top;
	cp = v;
	do {
		p = x;
		if (cp[x->rn_off] & x->rn_bmask)
			x = x->rn_r;
		else
			x = x->rn_l;
	} while (b > (unsigned) x->rn_b); /* x->rn_b < b && x->rn_b >= 0 */
#ifdef RN_DEBUG
	if (softr->rn_debug)
		log(LOG_DEBUG, "rn_insert: Going In:\n"); // traverse(p);
#endif
	t = ipf_rn_newpair(v_arg, b, nodes);
	tt = t->rn_l;
	if ((cp[p->rn_off] & p->rn_bmask) == 0)
		p->rn_l = t;
	else
		p->rn_r = t;
	x->rn_p = t;
	t->rn_p = p; /* frees x, p as temp vars below */
	if ((cp[t->rn_off] & t->rn_bmask) == 0) {
		t->rn_r = x;
	} else {
		t->rn_r = tt;
		t->rn_l = x;
	}
#ifdef RN_DEBUG
	if (softr->rn_debug)
		log(LOG_DEBUG, "rn_insert: Coming Out:\n"); // traverse(p);
#endif
    }
	return (tt);
}

struct ipf_radix_node *
ipf_rn_addmask(soft, n_arg, search, skip)
	int search, skip;
	void *soft, *n_arg;
{
	radix_softc_t *softr = soft;
	u_char  *netmask = (u_char *)n_arg;
	struct ipf_radix_node *x;
	u_char *cp, *cplim;
	int b = 0, mlen, j;
	int maskduplicated, m0, isnormal;
	struct ipf_radix_node *saved_x;
	static int last_zeroed = 0;

#ifdef	RN_DEBUG
	if (softr->rn_debug)
		log(LOG_DEBUG, "rn_addmask(%p,%d,%d)\n", n_arg, search, skip);
#endif
	mlen = *(u_char *)netmask;
	if ((mlen = *(u_char *)netmask) > softr->max_keylen)
		mlen = softr->max_keylen;
	if (skip == 0)
		skip = 1;
	if (mlen <= skip)
		return (softr->mask_rnhead->rnh_nodes);
	if (skip > 1)
		Bcopy(softr->rn_ones + 1, softr->addmask_key + 1, skip - 1);
	if ((m0 = mlen) > skip)
		Bcopy(netmask + skip, softr->addmask_key + skip, mlen - skip);
	/*
	 * Trim trailing zeroes.
	 */
	for (cp = softr->addmask_key + mlen; (cp > softr->addmask_key) && cp[-1] == 0;)
		cp--;
	mlen = cp - softr->addmask_key;
	if (mlen <= skip) {
		if (m0 >= last_zeroed)
			last_zeroed = mlen;
		return (softr->mask_rnhead->rnh_nodes);
	}
	if (m0 < last_zeroed)
		bzero(softr->addmask_key + m0, last_zeroed - m0);
	*softr->addmask_key = last_zeroed = mlen;
	x = ipf_rn_search(softr->addmask_key, softr->mask_rnhead->rnh_treetop);
	if (bcmp(softr->addmask_key, x->rn_key, mlen) != 0)
		x = 0;
	if (x || search)
		return (x);
	KMALLOCS(x, struct ipf_radix_node *, softr->max_keylen + 2 * sizeof (*x));
	if ((saved_x = x) == 0)
		return (0);
	bzero(x, softr->max_keylen + 2 * sizeof (*x));
	netmask = cp = (u_char *)(x + 2);
	Bcopy(softr->addmask_key, cp, mlen);
	x = ipf_rn_insert(soft, cp, softr->mask_rnhead, &maskduplicated, x);
	if (maskduplicated) {
#if 0
		log(LOG_ERR, "rn_addmask: mask impossibly already in tree\n");
#endif
		KFREE(saved_x);
		return (x);
	}
	/*
	 * Calculate index of mask, and check for normalcy.
	 */
	cplim = netmask + mlen;
	isnormal = 1;
	for (cp = netmask + skip; (cp < cplim) && *(u_char *)cp == 0xff;)
		cp++;
	if (cp != cplim) {
		for (j = 0x80; (j & *cp) != 0; j >>= 1)
			b++;
		if (*cp != normal_chars[b] || cp != (cplim - 1))
			isnormal = 0;
	}
	b += (cp - netmask) << 3;
	x->rn_b = -1 - b;
	if (isnormal)
		x->rn_flags |= RNF_NORMAL;
	return (x);
}

static int	/* XXX: arbitrary ordering for non-contiguous masks */
ipf_rn_lexobetter(m_arg, n_arg)
	void *m_arg, *n_arg;
{
	u_char *mp = m_arg, *np = n_arg, *lim;

	if (*mp > *np)
		return 1;  /* not really, but need to check longer one first */
	if (*mp == *np)
		for (lim = mp + *mp; mp < lim;)
			if (*mp++ > *np++)
				return 1;
	return 0;
}

static struct ipf_radix_mask *
ipf_rn_new_ipf_radix_mask(softr, tt, next)
	radix_softc_t *softr;
	struct ipf_radix_node *tt;
	struct ipf_radix_mask *next;
{
	struct ipf_radix_mask *m;

	MKGet(softr, m);
	if (m == 0) {
#if 0
		log(LOG_ERR, "Mask for route not entered\n");
#endif
		return (0);
	}
	bzero(m, sizeof *m);
	m->rm_b = tt->rn_b;
	m->rm_flags = tt->rn_flags;
	if (tt->rn_flags & RNF_NORMAL)
		m->rm_leaf = tt;
	else
		m->rm_mask = tt->rn_mask;
	m->rm_mklist = next;
	tt->rn_mklist = m;
	return m;
}

struct ipf_radix_node *
ipf_rn_addroute(soft, v_arg, n_arg, head, treenodes)
	void *soft, *v_arg, *n_arg;
	struct ipf_radix_node_head *head;
	struct ipf_radix_node treenodes[2];
{
	radix_softc_t *softr = soft;
	u_char *v = (u_char *)v_arg, *netmask = (u_char *)n_arg;
	struct ipf_radix_node *t, *x = NULL, *tt;
	struct ipf_radix_node *saved_tt, *top = head->rnh_treetop;
	short b = 0, b_leaf = 0;
	int keyduplicated;
	u_char *mmask;
	struct ipf_radix_mask *m, **mp;

#ifdef	RN_DEBUG
	if (softr->rn_debug)
		log(LOG_DEBUG, "rn_addroute(%p,%p,%p,%p)\n", v_arg, n_arg, head, treenodes);
#endif
	/*
	 * In dealing with non-contiguous masks, there may be
	 * many different routes which have the same mask.
	 * We will find it useful to have a unique pointer to
	 * the mask to speed avoiding duplicate references at
	 * nodes and possibly save time in calculating indices.
	 */
	if (netmask) {
		if ((x = ipf_rn_addmask(softr, netmask, 0, top->rn_off)) == 0)
			return (0);
		b_leaf = x->rn_b;
		b = -1 - x->rn_b;
		netmask = x->rn_key;
	}
	/*
	 * Deal with duplicated keys: attach node to previous instance
	 */
	saved_tt = tt = ipf_rn_insert(soft, v, head, &keyduplicated, treenodes);
	if (keyduplicated) {
		for (t = tt; tt; t = tt, tt = tt->rn_dupedkey) {
			if (tt->rn_mask == netmask)
				return (0);
			if (netmask == 0 ||
			    (tt->rn_mask &&
			     ((b_leaf < tt->rn_b) || /* index(netmask) > node */
			       ipf_rn_refines(netmask, tt->rn_mask) ||
			       ipf_rn_lexobetter(netmask, tt->rn_mask))))
				break;
		}
		/*
		 * If the mask is not duplicated, we wouldn't
		 * find it among possible duplicate key entries
		 * anyway, so the above test doesn't hurt.
		 *
		 * We sort the masks for a duplicated key the same way as
		 * in a masklist -- most specific to least specific.
		 * This may require the unfortunate nuisance of relocating
		 * the head of the list.
		 *
		 * We also reverse, or doubly link the list through the
		 * parent pointer.
		 */
		if (tt == saved_tt) {
			struct	ipf_radix_node *xx = x;
			/* link in at head of list */
			(tt = treenodes)->rn_dupedkey = t;
			tt->rn_flags = t->rn_flags;
			tt->rn_p = x = t->rn_p;
			t->rn_p = tt;
			if (x->rn_l == t)
				x->rn_l = tt;
			else
				x->rn_r = tt;
			saved_tt = tt;
			x = xx;
		} else {
			(tt = treenodes)->rn_dupedkey = t->rn_dupedkey;
			t->rn_dupedkey = tt;
			tt->rn_p = t;
			if (tt->rn_dupedkey)
				tt->rn_dupedkey->rn_p = tt;
		}
#ifdef RN_DEBUG
		t=tt+1;
		tt->rn_info = rn_nodenum++;
		t->rn_info = rn_nodenum++;
		tt->rn_twin = t;
		tt->rn_ybro = rn_clist;
		rn_clist = tt;
#endif
		tt->rn_key = (u_char *) v;
		tt->rn_b = -1;
		tt->rn_flags = RNF_ACTIVE;
	}
	/*
	 * Put mask in tree.
	 */
	if (netmask) {
		tt->rn_mask = netmask;
		tt->rn_b = x->rn_b;
		tt->rn_flags |= x->rn_flags & RNF_NORMAL;
	}
	t = saved_tt->rn_p;
	if (keyduplicated)
		goto on2;
	b_leaf = -1 - t->rn_b;
	if (t->rn_r == saved_tt)
		x = t->rn_l;
	else
		x = t->rn_r;
	/* Promote general routes from below */
	if (x->rn_b < 0) {
	    for (mp = &t->rn_mklist; x; x = x->rn_dupedkey)
		if (x->rn_mask && (x->rn_b >= b_leaf) && x->rn_mklist == 0) {
			*mp = m = ipf_rn_new_ipf_radix_mask(softr, x, 0);
			if (m)
				mp = &m->rm_mklist;
		}
	} else if (x->rn_mklist) {
		/*
		 * Skip over masks whose index is > that of new node
		 */
		for (mp = &x->rn_mklist; (m = *mp) != NULL; mp = &m->rm_mklist)
			if (m->rm_b >= b_leaf)
				break;
		t->rn_mklist = m;
		*mp = 0;
	}
on2:
	/* Add new route to highest possible ancestor's list */
	if ((netmask == 0) || (b > t->rn_b ))
		return tt; /* can't lift at all */
	b_leaf = tt->rn_b;
	do {
		x = t;
		t = t->rn_p;
	} while (b <= t->rn_b && x != top);
	/*
	 * Search through routes associated with node to
	 * insert new route according to index.
	 * Need same criteria as when sorting dupedkeys to avoid
	 * double loop on deletion.
	 */
	for (mp = &x->rn_mklist; (m = *mp) != NULL; mp = &m->rm_mklist) {
		if (m->rm_b < b_leaf)
			continue;
		if (m->rm_b > b_leaf)
			break;
		if (m->rm_flags & RNF_NORMAL) {
			mmask = m->rm_leaf->rn_mask;
			if (tt->rn_flags & RNF_NORMAL) {
#if 0
				log(LOG_ERR, "Non-unique normal route,"
				    " mask not entered\n");
#endif
				return tt;
			}
		} else
			mmask = m->rm_mask;
		if (mmask == netmask) {
			m->rm_refs++;
			tt->rn_mklist = m;
			return tt;
		}
		if (ipf_rn_refines(netmask, mmask)
		    || ipf_rn_lexobetter(netmask, mmask))
			break;
	}
	*mp = ipf_rn_new_ipf_radix_mask(softr, tt, *mp);
	return tt;
}

struct ipf_radix_node *
ipf_rn_delete(soft, v_arg, netmask_arg, head)
	void *soft, *v_arg, *netmask_arg;
	struct ipf_radix_node_head *head;
{
	radix_softc_t *softr = soft;
	struct ipf_radix_node *t, *p, *x, *tt;
	struct ipf_radix_mask *m, *saved_m, **mp;
	struct ipf_radix_node *dupedkey, *saved_tt, *top;
	u_char *v, *netmask;
	int b, head_off, vlen;

	v = v_arg;
	netmask = netmask_arg;
	x = head->rnh_treetop;
	tt = ipf_rn_search(v, x);
	head_off = x->rn_off;
	vlen =  *(u_char *)v;
	saved_tt = tt;
	top = x;
	if (tt == 0 ||
	    bcmp(v + head_off, tt->rn_key + head_off, vlen - head_off))
		return (0);
	/*
	 * Delete our route from mask lists.
	 */
	if (netmask) {
		if ((x = ipf_rn_addmask(softr, netmask, 1, head_off)) == 0)
			return (0);
		netmask = x->rn_key;
		while (tt->rn_mask != netmask)
			if ((tt = tt->rn_dupedkey) == 0)
				return (0);
	}
	if (tt->rn_mask == 0 || (saved_m = m = tt->rn_mklist) == 0)
		goto on1;
	if (tt->rn_flags & RNF_NORMAL) {
		if (m->rm_leaf != tt || m->rm_refs > 0) {
#if 0
			log(LOG_ERR, "rn_delete: inconsistent annotation\n");
#endif
			return 0;  /* dangling ref could cause disaster */
		}
	} else {
		if (m->rm_mask != tt->rn_mask) {
#if 0
			log(LOG_ERR, "rn_delete: inconsistent annotation\n");
#endif
			goto on1;
		}
		if (--m->rm_refs >= 0)
			goto on1;
	}
	b = -1 - tt->rn_b;
	t = saved_tt->rn_p;
	if (b > t->rn_b)
		goto on1; /* Wasn't lifted at all */
	do {
		x = t;
		t = t->rn_p;
	} while (b <= t->rn_b && x != top);
	for (mp = &x->rn_mklist; (m = *mp) != NULL; mp = &m->rm_mklist)
		if (m == saved_m) {
			*mp = m->rm_mklist;
			MKFree(softr, m);
			break;
		}
	if (m == 0) {
#if 0
		log(LOG_ERR, "rn_delete: couldn't find our annotation\n");
#endif
		if (tt->rn_flags & RNF_NORMAL)
			return (0); /* Dangling ref to us */
	}
on1:
	/*
	 * Eliminate us from tree
	 */
	if (tt->rn_flags & RNF_ROOT)
		return (0);
#ifdef RN_DEBUG
	/* Get us out of the creation list */
	for (t = rn_clist; t && t->rn_ybro != tt; t = t->rn_ybro)
		;
	if (t) t->rn_ybro = tt->rn_ybro;
#endif
	t = tt->rn_p;
	dupedkey = saved_tt->rn_dupedkey;
	if (dupedkey) {
		/*
		 * Here, tt is the deletion target and
		 * saved_tt is the head of the dupedkey chain.
		 */
		if (tt == saved_tt) {
			x = dupedkey;
			x->rn_p = t;
			if (t->rn_l == tt)
				t->rn_l = x;
			else
				t->rn_r = x;
		} else {
			/* find node in front of tt on the chain */
			for (x = p = saved_tt; p && p->rn_dupedkey != tt;)
				p = p->rn_dupedkey;
			if (p) {
				p->rn_dupedkey = tt->rn_dupedkey;
				if (tt->rn_dupedkey)
					tt->rn_dupedkey->rn_p = p;
			}
#if 0
			else
				log(LOG_ERR, "rn_delete: couldn't find us\n");
#endif
		}
		t = tt + 1;
		if  (t->rn_flags & RNF_ACTIVE) {
#ifndef RN_DEBUG
			*++x = *t;
			p = t->rn_p;
#else
			b = t->rn_info;
			*++x = *t;
			t->rn_info = b;
			p = t->rn_p;
#endif
			if (p->rn_l == t)
				p->rn_l = x;
			else
				p->rn_r = x;
			x->rn_l->rn_p = x;
			x->rn_r->rn_p = x;
		}
		goto out;
	}
	if (t->rn_l == tt)
		x = t->rn_r;
	else
		x = t->rn_l;
	p = t->rn_p;
	if (p->rn_r == t)
		p->rn_r = x;
	else
		p->rn_l = x;
	x->rn_p = p;
	/*
	 * Demote routes attached to us.
	 */
	if (t->rn_mklist) {
		if (x->rn_b >= 0) {
			for (mp = &x->rn_mklist; (m = *mp) != NULL;)
				mp = &m->rm_mklist;
			*mp = t->rn_mklist;
		} else {
			/* If there are any key,mask pairs in a sibling
			   duped-key chain, some subset will appear sorted
			   in the same order attached to our mklist */
			for (m = t->rn_mklist; m && x; x = x->rn_dupedkey)
				if (m == x->rn_mklist) {
					struct ipf_radix_mask *mm = m->rm_mklist;
					x->rn_mklist = 0;
					if (--(m->rm_refs) < 0)
						MKFree(softr, m);
					m = mm;
				}
#if 0
			if (m)
				log(LOG_ERR, "%s %p at %p\n",
				    "rn_delete: Orphaned Mask", m, x);
#endif
		}
	}
	/*
	 * We may be holding an active internal node in the tree.
	 */
	x = tt + 1;
	if (t != x) {
#ifndef RN_DEBUG
		*t = *x;
#else
		b = t->rn_info;
		*t = *x;
		t->rn_info = b;
#endif
		t->rn_l->rn_p = t;
		t->rn_r->rn_p = t;
		p = x->rn_p;
		if (p->rn_l == x)
			p->rn_l = t;
		else
			p->rn_r = t;
	}
out:
	tt->rn_flags &= ~RNF_ACTIVE;
	tt[1].rn_flags &= ~RNF_ACTIVE;
	return (tt);
}

int
ipf_rn_walktree(soft, h, f, w)
	struct ipf_radix_node_head *h;
	int (*f) __P((void *, struct ipf_radix_node *, void *));
	void *soft, *w;
{
	radix_softc_t *softr = soft;
	int error;
	struct ipf_radix_node *base, *next;
	struct ipf_radix_node *rn = h->rnh_treetop;
	/*
	 * This gets complicated because we may delete the node
	 * while applying the function f to it, so we need to calculate
	 * the successor node in advance.
	 */
	/* First time through node, go left */
	while (rn->rn_b >= 0)
		rn = rn->rn_l;
	for (;;) {
		base = rn;
		/* If at right child go back up, otherwise, go right */
		while (rn->rn_p->rn_r == rn && (rn->rn_flags & RNF_ROOT) == 0)
			rn = rn->rn_p;
		/* Find the next *leaf* since next node might vanish, too */
		for (rn = rn->rn_p->rn_r; rn->rn_b >= 0;)
			rn = rn->rn_l;
		next = rn;
		/* Process leaves */
		while ((rn = base) != NULL) {
			base = rn->rn_dupedkey;
			if (!(rn->rn_flags & RNF_ROOT)
			    && (error = (*f)(softr, rn, w)))
				return (error);
		}
		rn = next;
		if (rn->rn_flags & RNF_ROOT)
			return (0);
	}
	/* NOTREACHED */
}

int
ipf_rn_inithead(soft, head, off)
	void *soft, **head;
	int off;
{
	struct ipf_radix_node_head *rnh;

	if (*head)
		return (1);
	KMALLOCS(rnh, struct ipf_radix_node_head *, sizeof (*rnh));
	if (rnh == 0)
		return (0);
	*head = rnh;
	return ipf_rn_inithead0(soft, rnh, off);
}

int
ipf_rn_inithead0(soft, rnh, off)
	void *soft;
	struct ipf_radix_node_head *rnh;
	int off;
{
	radix_softc_t *softr = soft;
	struct ipf_radix_node *t, *tt, *ttt;

	bzero(rnh, sizeof (*rnh));
	t = ipf_rn_newpair(softr->rn_zeros, off, rnh->rnh_nodes);
	ttt = rnh->rnh_nodes + 2;
	t->rn_r = ttt;
	t->rn_p = t;
	tt = t->rn_l;
	tt->rn_flags = t->rn_flags = RNF_ROOT | RNF_ACTIVE;
	tt->rn_b = -1 - off;
	*ttt = *tt;
	ttt->rn_key = softr->rn_ones;
	rnh->rnh_addaddr = ipf_rn_addroute;
	rnh->rnh_deladdr = ipf_rn_delete;
	rnh->rnh_matchaddr = ipf_rn_match;
	rnh->rnh_lookup = ipf_rn_lookup;
	rnh->rnh_walktree = ipf_rn_walktree;
	rnh->rnh_treetop = t;
	return (1);
}

void *
ipf_rn_create()
{
	radix_softc_t *softr;

	KMALLOC(softr, radix_softc_t *);
	if (softr == NULL)
		return NULL;

	bzero((char *)softr, sizeof(*softr));

	softr->max_keylen = sizeof(addrfamily_t);
#ifdef RN_DEBUG
	softr->rn_debug = 1;
#endif

	return softr;
}


void
ipf_rn_init(soft)
	void *soft;
{
	radix_softc_t *softr = soft;
	u_char *cp, *cplim;

	if (softr->rn_zeros == NULL) {
		KMALLOCS(softr->rn_zeros, u_char *, 3 * softr->max_keylen);
	}
	if (softr->rn_zeros == NULL)
		panic("rn_init");

	bzero(softr->rn_zeros, 3 * softr->max_keylen);

	softr->rn_ones = cp = softr->rn_zeros + softr->max_keylen;
	softr->addmask_key = cplim = softr->rn_ones + softr->max_keylen;
	while (cp < cplim)
		*cp++ = -1;

	if (ipf_rn_inithead(softr, (void *)&softr->mask_rnhead, 0) == 0)
		panic("rn_init 2");
}


static int
ipf_rn_freenode(void *soft, struct ipf_radix_node *n, void *p)
{
	radix_softc_t *softr = soft;
	struct ipf_radix_node_head *rnh = p;
	struct ipf_radix_node *d;

	d = rnh->rnh_deladdr(softr, n->rn_key, NULL, rnh);
	if (d != NULL) {
		KFREES(d, softr->max_keylen + 2 * sizeof (*d));
	}
	return 0;
}


void
ipf_rn_freehead(void *soft, struct ipf_radix_node_head *rnh)
{

	(void)ipf_rn_walktree(soft, rnh, ipf_rn_freenode, rnh);

	rnh->rnh_addaddr = NULL;
	rnh->rnh_deladdr = NULL;
	rnh->rnh_matchaddr = NULL;
	rnh->rnh_lookup = NULL;
	rnh->rnh_walktree = NULL;

        KFREE(rnh);

}


void
ipf_rn_destroy(soft)
	void *soft;
{
	radix_softc_t *softr = soft;
	struct ipf_radix_mask *m;

	if (softr->rn_zeros != NULL) {
		KFREES(softr->rn_zeros, 3 * softr->max_keylen);
		softr->rn_zeros = NULL;
	}

	if (softr->mask_rnhead != NULL) {
		ipf_rn_freehead(softr, softr->mask_rnhead);
		softr->mask_rnhead = NULL;
	}

	while ((m = softr->rn_mkfreelist) != NULL) {
		softr->rn_mkfreelist = m->rm_mklist;
		KFREE(m);
	}

	KFREE(softr);
}


#ifdef	USE_MAIN

typedef struct myst {
	addrfamily_t	dst;
	addrfamily_t	mask;
	struct ipf_radix_node nodes[2];
} myst_t;

int
main(int argc, char *argv[])
{
	struct ipf_radix_node_head *rnh;
	struct ipf_radix_node *rn;
	addrfamily_t af, mf;
	myst_t st1, st2, *stp;

	memset(&st1, 0, sizeof(st1));
	memset(&st2, 0, sizeof(st2));
	memset(&af, 0, sizeof(af));

	ipf_rn_init();

	rnh = NULL;
	ipf_rn_inithead(&rnh, offsetof(addrfamily_t, adf_addr) << 3);

	st1.dst.adf_len = sizeof(st1);
	st1.mask.adf_len = sizeof(st1);
	st1.dst.adf_addr.in4.s_addr = inet_addr("127.0.0.0");
	st1.mask.adf_addr.in4.s_addr = inet_addr("255.0.0.0");
	rn = rnh->rnh_addaddr(&st1.dst, &st1.mask, rnh, st1.nodes);
	printf("add.1 %p\n", rn);

	st2.dst.adf_len = sizeof(st2);
	st2.mask.adf_len = sizeof(st2);
	st2.dst.adf_addr.in4.s_addr = inet_addr("127.0.1.0");
	st2.mask.adf_addr.in4.s_addr = inet_addr("255.255.255.0");
	rn = rnh->rnh_addaddr(&st2.dst, &st2.mask, rnh, st2.nodes);
	printf("add.2 %p\n", rn);

	af.adf_len = sizeof(af);
	af.adf_addr.in4.s_addr = inet_addr("127.0.1.0");
	rn = rnh->rnh_matchaddr(&af, rnh);
	if (rn != NULL) {
		printf("1.lookup = %p key %p mask %p\n", rn, rn->rn_key, rn->rn_mask);
		stp = rn->rn_key;
		printf("%s/", inet_ntoa(stp->dst.adf_addr.in4));
		stp = rn->rn_mask;
		printf("%s\n", inet_ntoa(stp->dst.adf_addr.in4));
	}

	mf.adf_len = sizeof(mf);
	mf.adf_addr.in4.s_addr = inet_addr("255.255.255.0");
	rn = rnh->rnh_lookup(&af, &mf, rnh);
	if (rn != NULL) {
		printf("2.lookup = %p key %p mask %p\n", rn, rn->rn_key, rn->rn_mask);
		stp = rn->rn_key;
		printf("%s/", inet_ntoa(stp->dst.adf_addr.in4));
		stp = rn->rn_mask;
		printf("%s\n", inet_ntoa(stp->dst.adf_addr.in4));
	}

	af.adf_len = sizeof(af);
	af.adf_addr.in4.s_addr = inet_addr("126.0.0.1");
	rn = rnh->rnh_matchaddr(&af, rnh);
	if (rn != NULL) {
		printf("3.lookup = %p key %p mask %p\n", rn, rn->rn_key, rn->rn_mask);
		stp = rn->rn_key;
		printf("%s/", inet_ntoa(stp->dst.adf_addr.in4));
		stp = rn->rn_mask;
		printf("%s\n", inet_ntoa(stp->dst.adf_addr.in4));
	}

	return 0;
}


void
log(int level, char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}
#endif


#ifndef	_KERNEL
void
panic(char *str)
{
	fputs(str, stderr);
	abort();
}
#endif
