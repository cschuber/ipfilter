/*
 * Copyright (C) 2000, 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 */
#pragma ident "@(#)$Id$"

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/rwlock.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#if SOLARIS2 >= 8
# include <netinet/ip6.h>
#else
# include <net/if_dl.h>
#endif
#include <netinet/tcp.h>

#undef IPOPT_EOL
#undef IPOPT_NOP
#undef IPOPT_RR
#undef IPOPT_LSRR
#undef IPOPT_SSRR
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip_ire.h>
#include <inet/ip_if.h>
#include <inet/arp.h>

#include "compat.h"
#include "qif.h"


#define	MI_BCOPY(_i, _m, _o, _l)					\
				{ u_char *_s;				\
				  _s = mi_offset_param(_m, _o, _l);	\
				  if ((_s) == NULL) {			\
					freemsg(_m);			\
					return -1; 			\
				  }					\
				  bcopy((char *)_i, _s, _l);		\
				}


extern krwlock_t pfil_rw;
extern int pfildebug;

static int pfil_makearpreq(ill_t *, struct in_addr, queue_t *, mblk_t *, ire_t *);


/* ------------------------------------------------------------------------ */
/* Function:    pfil_sendbuf                                                */
/* Returns:     int  - 0 == success, 1 == failure                           */
/* Parameters:  m(I) - pointer to streams message                           */
/*                                                                          */
/* Output an IPv4 packet to whichever interface has the correct route.      */
/* For sending out a packet from Solaris, we look in the IRE cache to check */
/* for an entry that has a fast path header.  If present, prepend it to the */
/* mblk being sent out, either as part of the one passed in (if there is    */
/* room at the front) or as another whole mblk.  If there is no such entry  */
/* in the IRE cache, compose a request message for one to be added and send */
/* that into the system.                                                    */
/* ------------------------------------------------------------------------ */
int pfil_sendbuf(qif, mb, ip, dstp)
qif_t *qif;
mblk_t *mb;
struct ip *ip;
void *dstp;
{
	struct in_addr addr;
	struct tcphdr *tcp;
	queue_t *q = NULL;
	size_t hlen;
	ire_t *dir;
	mblk_t *mp;
	u_char *s;
	ill_t *il;
	int i;


	addr = *(struct in_addr *)dstp;
#ifdef	MATCH_IRE_DSTONLY
	dir = ire_route_lookup(addr.s_addr, 0xffffffff, 0, 0,
				NULL, NULL, NULL,
# ifdef IP_ULP_OUT_LABELED
				NULL,
# endif
				MATCH_IRE_DSTONLY|MATCH_IRE_DEFAULT|
				MATCH_IRE_RECURSIVE);
#else
	dir = ire_lookup(addr);
#endif

	q = NULL;
	il = NULL;
	if (dir == NULL)
		goto bad_nexthop;

	if (qif == NULL) {
		il = ire_to_ill(dir);
	} else
		il = qif->qf_ill;

	if (il == NULL)
		goto bad_nexthop;

	if (dir->ire_stq)
		q = WR(dir->ire_stq);
	else if (dir->ire_rfq)
		q = WR(dir->ire_rfq);
	if (q == NULL)
		goto bad_nexthop;

	tcp = (struct tcphdr *)((char *)ip + (ip->ip_hl << 2));

#if (SOLARIS2 >= 6) && defined(ICK_M_CTL_MAGIC)
	if ((ip->ip_p == IPPROTO_TCP) && dohwcksum &&
	    (il->ill_ick.ick_magic == ICK_M_CTL_MAGIC)) {
		uint32_t t;

		t = ip->ip_src.s_addr;
		t += ip->ip_dst.s_addr;
		t += 30;
		t = (t & 0xffff) + (t >> 16);
		tcp->th_sum = t & 0xffff;
	}
#endif

#if SOLARIS2 >= 8
	mp = dir->ire_fp_mp;
	if (mp != NULL)
		hlen = mp->b_wptr - mp->b_rptr;
	else
		hlen = 0;
#else
	mp = dir->ire_ll_hdr_mp;
	hlen = dir->ire_ll_hdr_length;
#endif

	if (mp != NULL && hlen != 0) {
		q = q->q_next;
		if (q == NULL)
			goto bad_nexthop;
	} else {
		qif_t *qf;

		qf = qif_illrouteto(4, dstp);
		if (qf == NULL || qf->qf_ill == NULL)
			goto bad_nexthop;

		/*
		 * Nothing in the ARP cache so we have to cause it to be
		 * populated ourselves.
		 */
		if (pfil_makearpreq(il, addr, RD(q), mb, dir) == -1)
			freemsg(mb);
		mb = NULL;

		goto bad_nexthop;
	}

	s = (u_char *)ip;

	if (hlen &&
#ifdef	ICK_M_CTL_MAGIC
	    (il->ill_ick.ick_magic != ICK_M_CTL_MAGIC) &&
#endif
	    (s - mb->b_datap->db_base) >= hlen) {
		s -= hlen;
		mb->b_rptr = (u_char *)s;
		bcopy((char *)mp->b_rptr, (char *)s, hlen);
	} else {
		mblk_t *mp2;

		mp2 = copyb(mp);
		if (mp2 == NULL)
			goto bad_nexthop;
		mp2->b_cont = mb;
		mb = mp2;
	}
	putnext(q, mb);
#if SOLARIS2 >= 10
	if (qif == NULL)
		ill_refrele(il);
#endif
#if SOLARIS2 >= 8
	ire_refrele(dir);
#endif
	return 0;

bad_nexthop:
#if SOLARIS2 >= 10
	if ((il != NULL) && (qif == NULL))
		ill_refrele(il);
#endif
#if SOLARIS2 >= 8
	if (dir != NULL)
		ire_refrele(dir);
#endif
	if (mb != NULL)
		freemsg(mb);
	return 1;
}


/* ------------------------------------------------------------------------ */
/* Function:    pfil-timeoutsend                                            */
/* Returns:     void                                                        */
/* Parameters:  arg(I) - callback arg                                       */
/*                                                                          */
/* This function is used to deliver a packet in a manner that won't cause   */
/* a loop back from the same thread to happen through fr_check, thus leading*/
/* to a bad situation where we try and grab a lock that we already have.    */
/* The danger here is that the queue is not guaranteed to survive the time  */
/* window between when the callout is made and this function executing, so  */
/* an "unplumb" operation at the wrong time could lead to a panic.          */
/* ------------------------------------------------------------------------ */
void
pfil_timeoutsend(void *arg)
{
	mblk_t *m = arg;

	putnext(m->b_queue, m);
}


/* ------------------------------------------------------------------------ */
/* Function:    pfil_makearpreq                                             */
/* Returns:     int  - 0 == success, 1 == failure                           */
/* Parameters:  ill(I) - pointer to ill to send packet out of               */
/*              dst(I) - next hop address                                   */
/*              q(I)   - queue to use for sending packet                    */
/*              mb(I)  - pointer to mblk chain with packet                  */
/*                                                                          */
/* This function tkaes an IP packet in the mblk_t chain 'mb' and creates an */
/* ARP request from it.  Addresses stored on the ill (via ipif's) are also  */
/* used to build the ARP message contents.                                  */
/* ------------------------------------------------------------------------ */
static int
pfil_makearpreq(ill_t *ill, struct in_addr dst, queue_t *q, mblk_t *mb, ire_t *ire)
{
	ipaddr_t addr = dst.s_addr;
	struct in_addr src;
	ipif_t *ipif;
	u_short sap;
	mblk_t *n;
	uint32_t mask;
	ire_t *new, *sif;
	areq_t *a;
	char *s;
	int i;

	if (ire == NULL || ire->ire_stq == NULL)
		return -1;

#if SOLARIS2 >= 8
	sif = ire_ftable_lookup(addr, 0, 0, IRE_INTERFACE, NULL, NULL, 0, 0,
# ifdef IP_ULP_OUT_LABELED
				NULL,
# endif
				MATCH_IRE_TYPE);
#else
	sif = ire_ftable_lookup(addr, 0, 0, IRE_INTERFACE, NULL, NULL, 0,
				MATCH_IRE_TYPE);
#endif

	/*
	 * Get the first mblk on an aligned boundary.
	 */
	if (pullupmsg(mb, mb->b_wptr - mb->b_rptr) != 1)
		return -1;
	n = copymsg(ill->ill_resolver_mp);
	if (n == NULL)
		return -1;

	a = (areq_t *)n->b_rptr;
	a->areq_cmd = AR_ENTRY_QUERY;

	MI_BCOPY(ill->ill_name, n, a->areq_name_offset, ill->ill_name_length);

	sap = ill->ill_sap;
	bcopy(&sap, a->areq_sap, sizeof(sap));

	MI_BCOPY(&dst, n, a->areq_target_addr_offset, 4);
	ipif = ire->ire_ipif;
#if SOLARIS2 >= 8
	src.s_addr = ipif->ipif_lcl_addr;
#else
	src.s_addr = ipif->ipif_local_addr;
#endif

	MI_BCOPY(&src, n, a->areq_sender_addr_offset, 4);

#if SOLARIS2 >= 8
	mask = 0xffffffff;
	if (sif == NULL) {
		new = ire_create_mp((uchar_t *)&dst, (uchar_t *)&mask,
				    (uchar_t *)&src,
				    (uchar_t *)&ire->ire_gateway_addr,
				    NULL, 0, NULL, ill->ill_rq, ill->ill_wq,
				    IRE_CACHE, ill->ill_resolver_mp, ipif,
				    NULL, ire->ire_mask, 0, ire->ire_ihandle,
				    0, &ire_uinfo_null
# ifdef IP_ULP_OUT_LABELED
				    , NULL, NULL
# endif
				    );
	} else {
		new = ire_create_mp((uchar_t *)&dst, (uchar_t *)&mask,
				    (uchar_t *)&src,
				    (uchar_t *)&ire->ire_gateway_addr,
				    NULL, 0, NULL, ill->ill_rq, ill->ill_wq,
				    IRE_CACHE, ill->ill_resolver_mp, ipif,
				    0, sif->ire_mask, 0, sif->ire_ihandle,
				    0, &sif->ire_uinfo
# ifdef IP_ULP_OUT_LABELED
				    , NULL, NULL
# endif
				    );
	}
	if (sif != NULL)
		ire_refrele(sif);
#endif

	if (new == NULL) {
		freemsg(n);
		return -1;
	}

	linkb(new->ire_mp, mb);
	linkb(n, new->ire_mp);
	n->b_queue = q;
	timeout(pfil_timeoutsend, n, 2);
	return 0;
}
