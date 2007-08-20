/*
 * Copyright (C) 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 */

struct uio;
#include <sys/types.h>
#include <sys/stream.h>
#include <sys/cmn_err.h>
#include "../netinet/ip_info.h"

#undef IPOPT_EOL
#undef IPOPT_NOP
#undef IPOPT_RR
#undef IPOPT_LSRR
#undef IPOPT_SSRR

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "compat.h"
#include "pfil.h"

extern krwlock_t pfil_rw;


int pfil_sendbuf(m)
mblk_t *m;
{
	struct in_addr in;
	mblk_t *mp, *mp2;
	struct ip *ip;
	size_t hlen;
	irinfo_t ir;
	queue_t *q;
	u_char *s;
	void *il;

	bzero((char *)&ir, sizeof(ir));
	ip = (struct ip *)m->b_rptr;
	in.s_addr = 0;

	if (ir_lookup(&ir, &ip->ip_dst.s_addr, &in,
		      ~(IR_ROUTE|IR_ROUTE_ASSOC|IR_ROUTE_REDIRECT), 4) == 0)
		return 1;

	mp = ir.ir_ll_hdr_mp;
	if (!mp || !ir.ir_ll_hdr_length) {
		if (mp)
			freeb(mp);
		return 2;
	}

	q = NULL;
	mp = ir.ir_ll_hdr_mp;
	hlen = ir.ir_ll_hdr_length;
	s = (u_char *)ip;

	if (hlen && (s - m->b_datap->db_base) >= hlen) {
		s -= hlen;
		m->b_rptr = (u_char *)s;
		bcopy((char *)mp->b_rptr, (char *)s, hlen);
		freeb(mp);
	} else {
		linkb(mp, m);
		m = mp;
	}

	if (ir.ir_stq)
		q = ir.ir_stq;
	else if (ir.ir_rfq)
		q = WR(ir.ir_rfq);
	if (q)
		q = q->q_next;
	if (q) {
		m->b_prev = NULL;
		RW_EXIT(&pfil_rw);
		putnext(q, m);
		READ_ENTER(&pfil_rw);
		return 0;
	}
bad_nexthop:
	m->b_prev = NULL;
	m->b_next = NULL;
	freemsg(m);
	return 1;
}
