/*
 * Copyright (C) 1993-2001, 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 */
#if !defined(lint)
static const char sccsid[] = "%W% %G% (C) 1993-2000 Darren Reed";
static const char rcsid[] = "@(#)$Id$";
#endif

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/cpuvar.h>
#include <sys/open.h>
#include <sys/ioctl.h>
#include <sys/filio.h>
#include <sys/systm.h>
#if SOLARIS2 >= 10
# include <sys/cred_impl.h>
#else
# include <sys/cred.h>
#endif
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/mkdev.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/dditypes.h>
#include <sys/cmn_err.h>
#include <net/if.h>
#include <net/af.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/tcpip.h>
#include <netinet/ip_icmp.h>
#include "netinet/ip_compat.h"
#ifdef	USE_INET6
# include <netinet/icmp6.h>
#endif
#include "netinet/ip_fil.h"
#include "netinet/ip_nat.h"
#include "netinet/ip_frag.h"
#include "netinet/ip_state.h"
#include "netinet/ip_auth.h"
#include "netinet/ip_proxy.h"
#ifdef	IPFILTER_LOOKUP
# include "netinet/ip_lookup.h"
#endif
#include <inet/ip_ire.h>

#include "md5.h"

static	int	ipf_send_ip __P((fr_info_t *fin, mblk_t *m, mblk_t **mp));
static	void	ipf_fixl4sum __P((fr_info_t *));

ipfmutex_t	ipl_mutex, ipf_auth_mx, ipf_rw, ipf_stinsert;
ipfmutex_t	ipf_nat_new, ipf_natio, ipf_timeoutlock;
ipfrwlock_t	ipf_mutex, ipf_global, ipf_ipidfrag, ipf_frcache, ipf_tokens;
ipfrwlock_t	ipf_frag, ipf_state, ipf_nat, ipf_natfrag, ipf_authlk;
kcondvar_t	iplwait, ipfauthwait;
#if SOLARIS2 >= 7
timeout_id_t	ipf_timer_id;
u_int		*ip_ttl_ptr = NULL;
u_int		*ip_mtudisc = NULL;
# if SOLARIS2 >= 8
int		*ip_forwarding = NULL;
u_int		*ip6_forwarding = NULL;
# else
u_int		*ip_forwarding = NULL;
# endif
#else
int		ipf_timer_id;
u_long		*ip_ttl_ptr = NULL;
u_long		*ip_mtudisc = NULL;
u_long		*ip_forwarding = NULL;
#endif
int		ipf_locks_done = 0;


/* ------------------------------------------------------------------------ */
/* Function:    ipfdetach                                                   */
/* Returns:     int - 0 == success, else error.                             */
/* Parameters:  Nil                                                         */
/*                                                                          */
/* This function is responsible for undoing anything that might have been   */
/* done in a call to ipfattach().  It must be able to clean up from a call  */
/* to ipfattach() that did not succeed.  Why might that happen?  Someone    */
/* configures a table to be so large that we cannot allocate enough memory  */
/* for it.                                                                  */
/* ------------------------------------------------------------------------ */
int
ipfdetach()
{

	ASSERT(rw_read_locked(&ipf_global.ipf_lk) == 0);

	if (ipf_control_forwarding & 2) {
		if (ip_forwarding != NULL)
			*ip_forwarding = 0;
#if SOLARIS2 >= 8
		if (ip6_forwarding != NULL)
			*ip6_forwarding = 0;
#endif
	}

#ifdef	IPFDEBUG
	cmn_err(CE_CONT, "ipfdetach()\n");
#endif

	ipf_deinitialise();

	(void) ipf_flush(IPL_LOGIPF, FR_INQUE|FR_OUTQUE|FR_INACTIVE);
	(void) ipf_flush(IPL_LOGIPF, FR_INQUE|FR_OUTQUE);

	if (ipf_locks_done == 1) {
		MUTEX_DESTROY(&ipf_timeoutlock);
		MUTEX_DESTROY(&ipf_rw);
		RW_DESTROY(&ipf_tokens);
		RW_DESTROY(&ipf_ipidfrag);
		ipf_locks_done = 0;
	}
	return 0;
}


int
ipfattach __P((void))
{
	int i;

#ifdef	IPFDEBUG
	cmn_err(CE_CONT, "ipfattach()\n");
#endif

	ASSERT(rw_read_locked(&ipf_global.ipf_lk) == 0);

	bzero((char *)ipf_cache, sizeof(ipf_cache));
	MUTEX_INIT(&ipf_rw, "ipf rw mutex");
	MUTEX_INIT(&ipf_timeoutlock, "ipf timeout lock mutex");
	RWLOCK_INIT(&ipf_ipidfrag, "ipf IP NAT-Frag rwlock");
	RWLOCK_INIT(&ipf_tokens, "ipf token rwlock");
	ipf_locks_done = 1;

	if (ipf_initialise() < 0)
		return -1;

#if SOLARIS2 >= 8
	ip_forwarding = &ip_g_forward;
#endif
	/*
	 * XXX - There is no terminator for this array, so it is not possible
	 * to tell if what we are looking for is missing and go off the end
	 * of the array.
	 */

#if SOLARIS2 <= 8
	for (i = 0; ; i++) {
		if (!strcmp(ip_param_arr[i].ip_param_name, "ip_def_ttl")) {
			ip_ttl_ptr = &ip_param_arr[i].ip_param_value;
		} else if (!strcmp(ip_param_arr[i].ip_param_name,
			    "ip_path_mtu_discovery")) {
			ip_mtudisc = &ip_param_arr[i].ip_param_value;
		}
#if SOLARIS2 < 8
		else if (!strcmp(ip_param_arr[i].ip_param_name,
			    "ip_forwarding")) {
			ip_forwarding = &ip_param_arr[i].ip_param_value;
		}
#else
		else if (!strcmp(ip_param_arr[i].ip_param_name,
			    "ip6_forwarding")) {
			ip6_forwarding = &ip_param_arr[i].ip_param_value;
		}
#endif

		if (ip_mtudisc != NULL && ip_ttl_ptr != NULL &&
#if SOLARIS2 >= 8
		    ip6_forwarding != NULL &&
#endif
		    ip_forwarding != NULL)
			break;
	}
#endif

	if (ipf_control_forwarding & 1) {
		if (ip_forwarding != NULL)
			*ip_forwarding = 1;
#if SOLARIS2 >= 8
		if (ip6_forwarding != NULL)
			*ip6_forwarding = 1;
#endif
	}

	return 0;
}


/*
 * Filter ioctl interface.
 */
/*ARGSUSED*/
int
iplioctl(dev, cmd, data, mode, cp, rp)
	dev_t dev;
	int cmd;
#if SOLARIS2 >= 7
	intptr_t data;
#else
	int *data;
#endif
	int mode;
	cred_t *cp;
	int *rp;
{
	int error = 0;
	minor_t unit;

#ifdef	IPFDEBUG
	cmn_err(CE_CONT, "iplioctl(%x,%x,%x,%d,%x,%d)\n",
		dev, cmd, data, mode, cp, rp);
#endif
	unit = getminor(dev);
	if (IPL_LOGMAX < unit)
		return ENXIO;

	if (ipf_running <= 0) {
		if (unit != IPL_LOGIPF)
			return EIO;
		if (cmd != SIOCIPFGETNEXT && cmd != SIOCIPFGET &&
		    cmd != SIOCIPFSET && cmd != SIOCFRENB &&
		    cmd != SIOCGETFS && cmd != SIOCGETFF)
			return EIO;
	}

	error = ipf_ioctlswitch(unit, (caddr_t)data, cmd, mode,
			       cp->cr_uid, curproc);
	if (error != -1) {
		return error;
	}

	return error;
}


void *
get_unit(char *name, int v)
{
	void *ifp;
	qif_t *qf;
	int sap;

	if (v == 4)
		sap = 0x0800;
	else if (v == 6)
		sap = 0x86dd;
	else
		return NULL;
	rw_enter(&pfil_rw, RW_READER);
	qf = qif_iflookup(name, sap);
	rw_exit(&pfil_rw);
	return qf;
}

/*
 * ipf_send_reset - this could conceivably be a call to tcp_respond(), but that
 * requires a large amount of setting up and isn't any more efficient.
 */
int
ipf_send_reset(fr_info_t *fin)
{
	tcphdr_t *tcp, *tcp2;
	int tlen, hlen;
	mblk_t *m;
#ifdef	USE_INET6
	ip6_t *ip6;
#endif
	ip_t *ip;

	tcp = fin->fin_dp;
	if (tcp->th_flags & TH_RST)
		return -1;

	if (ipf_checkl4sum(fin) == -1)
		return -1;

	tlen = (tcp->th_flags & (TH_SYN|TH_FIN)) ? 1 : 0;
#ifdef	USE_INET6
	if (fin->fin_v == 6)
		hlen = sizeof(ip6_t);
	else
#endif
		hlen = sizeof(ip_t);
	hlen += sizeof(*tcp2);
	if ((m = (mblk_t *)allocb(hlen + 64, BPRI_HI)) == NULL)
		return -1;

	m->b_rptr += 64;
	MTYPE(m) = M_DATA;
	m->b_wptr = m->b_rptr + hlen;
	ip = (ip_t *)m->b_rptr;
	bzero((char *)ip, hlen);
	tcp2 = (struct tcphdr *)(m->b_rptr + hlen - sizeof(*tcp2));
	tcp2->th_dport = tcp->th_sport;
	tcp2->th_sport = tcp->th_dport;
	if (tcp->th_flags & TH_ACK) {
		tcp2->th_seq = tcp->th_ack;
		tcp2->th_flags = TH_RST;
	} else {
		tcp2->th_ack = ntohl(tcp->th_seq);
		tcp2->th_ack += tlen;
		tcp2->th_ack = htonl(tcp2->th_ack);
		tcp2->th_flags = TH_RST|TH_ACK;
	}
	tcp2->th_off = sizeof(struct tcphdr) >> 2;

	ip->ip_v = fin->fin_v;
#ifdef	USE_INET6
	if (fin->fin_v == 6) {
		ip6 = (ip6_t *)m->b_rptr;
		ip6->ip6_flow = ((ip6_t *)fin->fin_ip)->ip6_flow;
		ip6->ip6_src = fin->fin_dst6;
		ip6->ip6_dst = fin->fin_src6;
		ip6->ip6_plen = htons(sizeof(*tcp));
		ip6->ip6_nxt = IPPROTO_TCP;
	} else
#endif
	{
		ip->ip_src.s_addr = fin->fin_daddr;
		ip->ip_dst.s_addr = fin->fin_saddr;
		ip->ip_id = ipf_nextipid(fin);
		ip->ip_hl = sizeof(*ip) >> 2;
		ip->ip_p = IPPROTO_TCP;
		ip->ip_len = htons(sizeof(*ip) + sizeof(*tcp));
		ip->ip_tos = fin->fin_ip->ip_tos;
		tcp2->th_sum = ipf_cksum(m, ip, IPPROTO_TCP, tcp2,
					 ntohs(ip->ip_len));
	}
	return ipf_send_ip(fin, m, &m);
}


/*ARGSUSED*/
static int
ipf_send_ip(fr_info_t *fin, mblk_t *m, mb_t **mpp)
{
	qpktinfo_t qpi, *qpip;
	fr_info_t fnew;
	qif_t *qif;
	ip_t *ip;
	int i, hlen;

	ip = (ip_t *)m->b_rptr;
	bzero((char *)&fnew, sizeof(fnew));

#ifdef	USE_INET6
	if (fin->fin_v == 6) {
		ip6_t *ip6;

		ip6 = (ip6_t *)ip;
		ip6->ip6_vfc = 0x60;
		ip6->ip6_hlim = 127;
		fnew.fin_v = 6;
		hlen = sizeof(*ip6);
	} else
#endif
	{
		fnew.fin_v = 4;
		if (ip_ttl_ptr != NULL)
			ip->ip_ttl = (u_char)(*ip_ttl_ptr);
		else
			ip->ip_ttl = 63;
		if (ip_mtudisc != NULL)
			ip->ip_off = htons(*ip_mtudisc ? IP_DF : 0);
		else
			ip->ip_off = htons(IP_DF);
		ip->ip_sum = ipf_cksum((u_short *)ip, sizeof(*ip));
		hlen = sizeof(*ip);
	}

	qpip = fin->fin_qpi;
	qpi.qpi_q = qpip->qpi_q;
	qpi.qpi_off = 0;
	qpi.qpi_name = qpip->qpi_name;
	qif = qpip->qpi_real;
	qpi.qpi_real = qif;
	qpi.qpi_ill = qif->qf_ill;
	qpi.qpi_hl = qif->qf_hl;
	qpi.qpi_ppa = qif->qf_ppa;
	qpi.qpi_num = qif->qf_num;
	qpi.qpi_flags = qif->qf_flags;
	qpi.qpi_max_frag = qif->qf_max_frag;
	qpi.qpi_m = m;
	qpi.qpi_data = ip;
	fnew.fin_qpi = &qpi;
	fnew.fin_ifp = fin->fin_ifp;
	fnew.fin_flx = FI_NOCKSUM;
	fnew.fin_m = m;
	fnew.fin_ip = ip;
	fnew.fin_mp = mpp;
	fnew.fin_hlen = hlen;
	fnew.fin_dp = (char *)ip + hlen;
	(void) ipf_makefrip(hlen, ip, &fnew);

	i = ipf_fastroute(m, mpp, &fnew, NULL);
	return i;
}


int
ipf_send_icmp_err(int type, fr_info_t *fin, int dst)
{
	struct in_addr dst4;
	struct icmp *icmp;
	qpktinfo_t *qpi;
	int hlen, code;
	i6addr_t dst6;
	u_short sz;
#ifdef	USE_INET6
	mblk_t *mb;
#endif
	mblk_t *m;
#ifdef	USE_INET6
	ip6_t *ip6;
#endif
	ip_t *ip;

	if ((type < 0) || (type > ICMP_MAXTYPE))
		return -1;

	code = fin->fin_icode;
#ifdef USE_INET6
	if ((code < 0) || (code > sizeof(icmptoicmp6unreach)/sizeof(int)))
		return -1;
#endif

	if (ipf_checkl4sum(fin) == -1)
		return -1;

	qpi = fin->fin_qpi;

#ifdef	USE_INET6
	mb = fin->fin_qfm;

	if (fin->fin_v == 6) {
		sz = sizeof(ip6_t);
		sz += MIN(mb->b_wptr - mb->b_rptr, 512);
		hlen = sizeof(ip6_t);
		type = icmptoicmp6types[type];
		if (type == ICMP6_DST_UNREACH)
			code = icmptoicmp6unreach[code];
	} else
#endif
	{
		if ((fin->fin_p == IPPROTO_ICMP) && !(fin->fin_flx & FI_SHORT))
			switch (ntohs(fin->fin_data[0]) >> 8)
			{
			case ICMP_ECHO :
			case ICMP_TSTAMP :
			case ICMP_IREQ :
			case ICMP_MASKREQ :
				break;
			default :
				return 0;
			}

		sz = sizeof(ip_t) * 2;
		sz += 8;		/* 64 bits of data */
		hlen = sizeof(ip_t);
	}

	sz += offsetof(struct icmp, icmp_ip);
	if ((m = (mblk_t *)allocb((size_t)sz + 64, BPRI_HI)) == NULL)
		return -1;
	MTYPE(m) = M_DATA;
	m->b_rptr += 64;
	m->b_wptr = m->b_rptr + sz;
	bzero((char *)m->b_rptr, (size_t)sz);
	ip = (ip_t *)m->b_rptr;
	ip->ip_v = fin->fin_v;
	icmp = (struct icmp *)(m->b_rptr + hlen);
	icmp->icmp_type = type & 0xff;
	icmp->icmp_code = code & 0xff;
#ifdef	icmp_nextmtu
	if (type == ICMP_UNREACH && fin->fin_icode == ICMP_UNREACH_NEEDFRAG) {
		if (fin->fin_mtu != 0) {
			icmp->icmp_nextmtu = htons(fin->fin_mtu);

		} else if (qpi->qpi_max_frag != 0) {
			icmp->icmp_nextmtu = htons(qpi->qpi_max_frag);

		} else {	/* Make up a number */
			icmp->icmp_nextmtu = htons(fin->fin_plen - 20);
		}
	}
#endif

#ifdef	USE_INET6
	if (fin->fin_v == 6) {
		int csz;

		if (dst == 0) {
			if (ipf_ifpaddr(6, FRI_NORMAL, qpi->qpi_real,
					&dst6, NULL) == -1) {
				FREE_MB_T(m);
				return -1;
			}
		} else
			dst6 = fin->fin_dst6;

		csz = sz;
		sz -= sizeof(ip6_t);
		ip6 = (ip6_t *)m->b_rptr;
		ip6->ip6_flow = ((ip6_t *)fin->fin_ip)->ip6_flow;
		ip6->ip6_plen = htons((u_short)sz);
		ip6->ip6_nxt = IPPROTO_ICMPV6;
		ip6->ip6_src = dst6;
		ip6->ip6_dst = fin->fin_src6;
		sz -= offsetof(struct icmp, icmp_ip);
		bcopy((char *)mb->b_rptr, (char *)&icmp->icmp_ip, sz);
		icmp->icmp_cksum = csz - sizeof(ip6_t);
	} else
#endif
	{
		ip->ip_hl = sizeof(*ip) >> 2;
		ip->ip_p = IPPROTO_ICMP;
		ip->ip_id = fin->fin_ip->ip_id;
		ip->ip_tos = fin->fin_ip->ip_tos;
		ip->ip_len = (u_short)sz;
		if (dst == 0) {
			if (ipf_ifpaddr(4, FRI_NORMAL, qpi->qpi_real,
					&dst6, NULL) == -1) {
				FREE_MB_T(m);
				return -1;
			}
			dst4 = dst6.in4;
		} else
			dst4 = fin->fin_dst;
		ip->ip_src = dst4;
		ip->ip_dst = fin->fin_src;
		bcopy((char *)fin->fin_ip, (char *)&icmp->icmp_ip,
		      sizeof(*fin->fin_ip));
		bcopy((char *)fin->fin_ip + fin->fin_hlen,
		      (char *)&icmp->icmp_ip + sizeof(*fin->fin_ip), 8);
		icmp->icmp_cksum = ipf_cksum((u_short *)icmp,
					     sz - sizeof(ip_t));
	}

	/*
	 * Need to exit out of these so we don't recursively call rw_enter
	 * from fr_qout.
	 */
	return ipf_send_ip(fin, m, &m);
}


/*
 * return the first IP Address associated with an interface
 */
/*ARGSUSED*/
int
ipf_ifpaddr(int v, int atype, void *qifptr, i6addr_t *inp, i6addr_t *inpmask)
{
#ifdef	USE_INET6
	struct sockaddr_in6 sin6, mask6;
#endif
	struct sockaddr_in sin, mask;
	qif_t *qif;

	if ((qifptr == NULL) || (qifptr == (void *)-1))
		return -1;

	qif = qifptr;
	if (qif->qf_ill == NULL)
		return -1;

#ifdef	USE_INET6
	if (v == 6) {
		in6_addr_t *inp6;
		ipif_t *ipif;
		ill_t *ill;

		ill = qif->qf_ill;

		/*
		 * First is always link local.
		 */
		for (ipif = ill->ill_ipif; ipif; ipif = ipif->ipif_next) {
			inp6 = &ipif->ipif_v6lcl_addr;
			if (!IN6_IS_ADDR_LINKLOCAL(inp6) &&
			    !IN6_IS_ADDR_LOOPBACK(inp6))
				break;
		}
		if (ipif == NULL)
			return -1;

		mask6.sin6_addr = ipif->ipif_v6net_mask;
		if (atype == FRI_BROADCAST)
			sin6.sin6_addr = ipif->ipif_v6brd_addr;
		else if (atype == FRI_PEERADDR)
			sin6.sin6_addr = ipif->ipif_v6pp_dst_addr;
		else
			sin6.sin6_addr = *inp6;
		return ipf_ifpfillv6addr(atype, &sin6, &mask6, inp, inpmask);
	}
#endif

	if (((ill_t *)qif->qf_ill)->ill_ipif == NULL)
		return -1;

	switch (atype)
	{
	case FRI_BROADCAST :
		sin.sin_addr.s_addr = QF_V4_BROADCAST(qif);
		break;
	case FRI_PEERADDR :
		sin.sin_addr.s_addr = QF_V4_PEERADDR(qif);
		break;
	default :
		sin.sin_addr.s_addr = QF_V4_ADDR(qif);
		break;
	}
	mask.sin_addr.s_addr = QF_V4_NETMASK(qif);

	return ipf_ifpfillv4addr(atype, &sin, &mask, &inp->in4, &inpmask->in4);
}


u_32_t
ipf_newisn(fr_info_t *fin)
{
	static int iss_seq_off = 0;
	u_char hash[16];
	u_32_t newiss;
	MD5_CTX ctx;

	/*
	 * Compute the base value of the ISS.  It is a hash
	 * of (saddr, sport, daddr, dport, secret).
	 */
	MD5Init(&ctx);

	MD5Update(&ctx, (u_char *) &fin->fin_fi.fi_src,
		  sizeof(fin->fin_fi.fi_src));
	MD5Update(&ctx, (u_char *) &fin->fin_fi.fi_dst,
		  sizeof(fin->fin_fi.fi_dst));
	MD5Update(&ctx, (u_char *) &fin->fin_dat, sizeof(fin->fin_dat));

	MD5Update(&ctx, ipf_iss_secret, sizeof(ipf_iss_secret));

	MD5Final(hash, &ctx);

	bcopy(hash, &newiss, sizeof(newiss));

	/*
	 * Now increment our "timer", and add it in to
	 * the computed value.
	 *
	 * XXX Use `addin'?
	 * XXX TCP_ISSINCR too large to use?
	 */
	iss_seq_off += 0x00010000;
	newiss += iss_seq_off;
	return newiss;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nextipid                                                */
/* Returns:     int - 0 == success, -1 == error (packet should be droppped) */
/* Parameters:  fin(I) - pointer to packet information                      */
/*                                                                          */
/* Returns the next IPv4 ID to use for this packet.                         */
/* ------------------------------------------------------------------------ */
u_short
ipf_nextipid(fr_info_t *fin)
{
	static u_short ipid = 0;
	ipstate_t *is;
	nat_t *nat;
	u_short id;

	MUTEX_ENTER(&ipf_rw);
	if (fin->fin_state != NULL) {
		is = fin->fin_state;
		id = (u_short)(is->is_pkts[(fin->fin_rev << 1) + 1] & 0xffff);
	} else if (fin->fin_nat != NULL) {
		nat = fin->fin_nat;
		id = (u_short)(nat->nat_pkts[fin->fin_out] & 0xffff);
	} else
		id = ipid++;
	MUTEX_EXIT(&ipf_rw);

	return id;
}


#ifndef IPFILTER_CKSUM
/* ARGSUSED */
#endif
INLINE void
ipf_checkv4sum(fr_info_t *fin)
{
#ifdef IPFILTER_CKSUM
	if (ipf_checkl4sum(fin) == -1)
		fin->fin_flx |= FI_BAD;
#endif
}


#ifdef USE_INET6
# ifndef IPFILTER_CKSUM
/* ARGSUSED */
# endif
INLINE void
ipf_checkv6sum(fr_info_t *fin)
{
# ifdef IPFILTER_CKSUM
	if (ipf_checkl4sum(fin) == -1)
		fin->fin_flx |= FI_BAD;
# endif
}
#endif /* USE_INET6 */


/*
 * Function:    ipf_verifysrc
 * Returns:     int (really boolean)
 * Parameters:  fin - packet information
 *
 * Check whether the packet has a valid source address for the interface on
 * which the packet arrived, implementing the "ipf_chksrc" feature.
 * Returns true iff the packet's source address is valid.
 * Pre-Solaris 10, we call into the routing code to make the determination.
 * On Solaris 10 and later, we have a valid address set from pfild to check
 * against.
 */
int
ipf_verifysrc(fin)
	fr_info_t *fin;
{
	ire_t *dir;
	int result;

#if SOLARIS2 >= 6
	dir = ire_route_lookup(fin->fin_saddr, 0xffffffff, 0, 0, NULL,
			       NULL, NULL,
# ifdef IP_ULP_OUT_LABELED
			       NULL,
# endif
			       MATCH_IRE_DSTONLY|MATCH_IRE_DEFAULT|
			       MATCH_IRE_RECURSIVE);
#else
	dir = ire_lookup(fin->fin_saddr);
#endif

	if (!dir)
		return 0;
	result = (ire_to_ill(dir) == fin->fin_ifp);
#if SOLARIS2 >= 8
	ire_refrele(dir);
#endif
	return result;
}


void
#if (SOLARIS2 < 7)
ipf_slowtimer()
#else
/*ARGSUSED*/
ipf_slowtimer __P((void *ptr))
#endif
{

	WRITE_ENTER(&ipf_global);
	if (ipf_running <= 0) {
		if (ipf_running >= -1) {
			ipf_timer_id = timeout(ipf_slowtimer, NULL,
					       drv_usectohz(500000));
		} else {
			ipf_timer_id = NULL;
		}
		RWLOCK_EXIT(&ipf_global);
		return;
	}
	MUTEX_DOWNGRADE(&ipf_global);

	ipf_expiretokens();
	ipf_fragexpire();
	ipf_timeoutstate();
	ipf_natexpire();
	ipf_authexpire();
	ipf_ticks++;
	if (ipf_running == -1 || ipf_running == 1)
		ipf_timer_id = timeout(ipf_slowtimer, NULL,
				       drv_usectohz(500000));
	else
		ipf_timer_id = NULL;
	RWLOCK_EXIT(&ipf_global);
}


/*
 * Function:  ipf_fastroute
 * Returns:    0: success;
 *            -1: failed
 * Parameters:
 *    mb: the message block where ip head starts
 *    mpp: the pointer to the pointer of the orignal
 *            packet message
 *    fin: packet information
 *    fdp: destination interface information
 *    if it is NULL, no interface information provided.
 *
 * This function is for fastroute/to/dup-to rules. It calls
 * pfil_make_lay2_packet to search route, make lay-2 header
 * ,and identify output queue for the IP packet.
 * The destination address depends on the following conditions:
 * 1: for fastroute rule, fdp is passed in as NULL, so the
 *    destination address is the IP Packet's destination address
 * 2: for to/dup-to rule, if an ip address is specified after
 *    the interface name, this address is the as destination
 *    address. Otherwise IP Packet's destination address is used
 */
int
ipf_fastroute(mb, mpp, fin, fdp)
	mblk_t *mb, **mpp;
	fr_info_t *fin;
	frdest_t *fdp;
{
	struct in_addr dst;
	qpktinfo_t *qpi;
	frentry_t *fr;
	frdest_t fd;
	qif_t *ifp;
	void *dstp;
	void *sifp;
	ip_t *ip;
#ifndef	sparc
	u_short __iplen, __ipoff;
#endif
#ifdef	USE_INET6
	ip6_t *ip6 = (ip6_t *)fin->fin_ip;
	struct in6_addr dst6;
#endif

	fr = fin->fin_fr;
	ip = fin->fin_ip;
	qpi = fin->fin_qpi;

	/*
	 * If this is a duplicate mblk then we want ip to point at that
	 * data, not the original, if and only if it is already pointing at
	 * the current mblk data.
	 */
	if (ip == (ip_t *)qpi->qpi_m->b_rptr && qpi->qpi_m != mb)
		ip = (ip_t *)mb->b_rptr;

	/*
	 * If there is another M_PROTO, we don't want it
	 */
	if (*mpp != mb) {
		mblk_t *mp;

		mp = unlinkb(*mpp);
		freeb(*mpp);
		*mpp = mp;
	}

	/*
	 * If the fdp is NULL then there is no set route for this packet.
	 */
	if (fdp == NULL) {
		ifp = fin->fin_ifp;

		switch (fin->fin_v)
		{
		case 4 :
			fd.fd_ip = ip->ip_dst;
			ifp = qif_illrouteto(4, &ip->ip_dst);
			break;
#ifdef USE_INET6
		case 6 :
			fd.fd_ip6.in6 = ip6->ip6_dst;
			ifp = qif_illrouteto(6, &ip6->ip6_dst);
			break;
#endif
		}
		fdp = &fd;
	} else {
		ifp = fdp->fd_ifp;

		if (ifp == NULL || ifp == (void *)-1)
			goto bad_fastroute;
	}

	/*
	 * In case we're here due to "to <if>" being used with
	 * "keep state", check that we're going in the correct
	 * direction.
	 */
	if ((fr != NULL) && (fin->fin_rev != 0)) {
		if ((ifp != NULL) && (fdp == &fr->fr_tif))
			return -1;
		dst.s_addr = fin->fin_fi.fi_daddr;
	} else {
		if (fin->fin_v == 4) {
			if (fdp->fd_ip.s_addr != 0)
				dst = fdp->fd_ip;
			else
				dst.s_addr = fin->fin_fi.fi_daddr;
			dstp = &dst;
		}
#ifdef USE_INET6
		else if (fin->fin_v == 6) {
			if (IP6_NOTZERO(&fdp->fd_ip))
				dst6 = fdp->fd_ip6.in6;
			else
				dst6 = fin->fin_dst6;
		}
#endif
	}

	/*
	 * For input packets which are being "fastrouted", they won't
	 * go back through output filtering and miss their chance to get
	 * NAT'd and counted.  Duplicated packets aren't considered to be
	 * part of the normal packet stream, so do not NAT them or pass
	 * them through stateful checking, etc.
	 */
	if ((fdp != &fr->fr_dif) && (fin->fin_out == 0)) {
		sifp = fin->fin_ifp;
		fin->fin_ifp = ifp;
		fin->fin_out = 1;
		(void) ipf_acctpkt(fin, NULL);
		fin->fin_fr = NULL;
		if (!fr || !(fr->fr_flags & FR_RETMASK)) {
			u_32_t pass;

			if (ipf_state_check(fin, &pass) != NULL)
				ipf_state_deref((ipstate_t **)&fin->fin_state);
		}

		switch (ipf_nat_checkout(fin, NULL))
		{
		case 0 :
			break;
		case 1 :
			ipf_nat_deref((nat_t **)&fin->fin_nat);
			ip->ip_sum = 0;
			break;
		case -1 :
			goto bad_fastroute;
			break;
		}

		fin->fin_out = 0;
		fin->fin_ifp = sifp;
	} else if (fin->fin_out == 1) {
#if SOLARIS2 >= 6
		/*
		 * We're taking a packet from an interface and putting it on
		 * another interface.  There's no guarantee that the other
		 * interface will have the same capabilities, so disable
		 * any flags that are set and do things manually for both
		 * IP and TCP/UDP
		 */
		if (mb->b_datap->db_struioflag) {
			mb->b_datap->db_struioflag = 0;

			if (fin->fin_v == 4) {
				ip->ip_sum = 0;
				ip->ip_sum = ipf_cksum((u_short *)ip,
						       sizeof(*ip));
			}
			ipf_fixl4sum(fin);
		}
#endif
	}

  #ifndef sparc
  	if (fin->fin_v == 4) {
  		__iplen = (u_short)ip->ip_len,

	if (pfil_sendbuf(ifp, mb) == 0) {
		ATOMIC_INCL(fr_frouteok[0]);
	} else {
		ATOMIC_INCL(ipf_frouteok[1]);
	}
	return 0;

bad_fastroute:
	ATOMIC_INCL(ipf_frouteok[1]);
	freemsg(mb);
	return -1;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_pullup                                                  */
/* Returns:     NULL == pullup failed, else pointer to protocol header      */
/* Parameters:  xmin(I)- pointer to buffer where data packet starts         */
/*              fin(I) - pointer to packet information                      */
/*              len(I) - number of bytes to pullup                          */
/*                                                                          */
/* Attempt to move at least len bytes (from the start of the buffer) into a */
/* single buffer for ease of access.  Operating system native functions are */
/* used to manage buffers - if necessary.  If the entire packet ends up in  */
/* a single buffer, set the FI_COALESCE flag even though ipf_coalesce() has */
/* not been called.  Both fin_ip and fin_dp are updated before exiting _IF_ */
/* and ONLY if the pullup succeeds.                                         */
/*                                                                          */
/* We assume that 'xmin' is a pointer to a buffer that is part of the chain */
/* of buffers that starts at *fin->fin_mp.                                  */
/* ------------------------------------------------------------------------ */
void *
ipf_pullup(mb_t *xmin, fr_info_t *fin, int len)
{
	qpktinfo_t *qpi = fin->fin_qpi;
	int out = fin->fin_out, dpoff, ipoff;
	mb_t *m = xmin;
	char *ip;

	if (m == NULL)
		return NULL;

	ip = (char *)fin->fin_ip;
	if ((fin->fin_flx & FI_COALESCE) != 0)
		return ip;

	ipoff = fin->fin_ipoff;
	if (fin->fin_dp != NULL)
		dpoff = (char *)fin->fin_dp - (char *)ip;
	else
		dpoff = 0;

	if (M_LEN(m) < len) {

		/*
		 * pfil_precheck ensures the IP header is on a 32bit
		 * aligned address so simply fail if that isn't currently
		 * the case (should never happen).
		 */
		if (((ipoff & 3) != 0) || (pullupmsg(m, len + ipoff) == 0)) {
			ATOMIC_INCL(ipf_stats[out].fr_pull[1]);
			FREE_MB_T(*fin->fin_mp);
			*fin->fin_mp = NULL;
			fin->fin_m = NULL;
			fin->fin_ip = NULL;
			fin->fin_dp = NULL;
			qpi->qpi_data = NULL;
			return NULL;
		}

		fin->fin_m = m;
		ip = MTOD(m, char *) + ipoff;
		qpi->qpi_data = ip;
	}

	ATOMIC_INCL(ipf_stats[out].fr_pull[0]);
	fin->fin_ip = (ip_t *)ip;
	if (fin->fin_dp != NULL)
		fin->fin_dp = (char *)fin->fin_ip + dpoff;

	if (len == fin->fin_plen)
		fin->fin_flx |= FI_COALESCE;
	return ip;
}


int
ipf_inject(fr_info_t *fin, mb_t *m)
{
	qifpkt_t *qp;

	qp = kmem_alloc(sizeof(*qp), KM_NOSLEEP);
	if (qp == NULL) {
		freemsg(*fin->fin_mp);
		return ENOMEM;
	}

	qp->qp_mb = *fin->fin_mp;
	if (fin->fin_v == 4)
		qp->qp_sap = 0x800;
	else if (fin->fin_v == 6)
		qp->qp_sap = 0x86dd;
	qp->qp_inout = fin->fin_out;
	strncpy(qp->qp_ifname, fin->fin_ifname, LIFNAMSIZ);
	qif_addinject(qp);
	return 0;
}


static void
ipf_fixl4sum(fr_info_t *fin)
{
	u_short *csump;
	udphdr_t *udp;

	csump = NULL;

	switch (fin->fin_p)
	{
	case IPPROTO_TCP :
		csump = &((tcphdr_t *)fin->fin_dp)->th_sum;
		break;

	case IPPROTO_UDP :
		udp = fin->fin_dp;
		if (udp->uh_sum != 0)
			csump = &udp->uh_sum;
		break;

	default :
		break;
	}

	if (csump != NULL) {
		*csump = 0;
		*csump = ipf_cksum(fin->fin_m, fin->fin_ip, fin->fin_p,
				   fin->fin_dp, fin->fin_plen);
	}
}


mblk_t *
ipf_allocmbt(size_t len)
{
	mblk_t *m;

	/*
	 * +64 is to reverse some token amount of space so that we
	 * might have a good chance of copying over data from the
	 * front of the existing IP packet to this one.
	 */
	m = allocb(len + 128, BPRI_HI);
	if (m == NULL)
		return NULL;

	m->b_rptr += 128;
	m->b_wptr += 128 + len;
	return m;
}


void
ipf_prependmbt(fr_info_t *fin, mblk_t *m)
{
	mblk_t *o = NULL;
	mblk_t *n = *fin->fin_mp;

	if (MTYPE(n) == M_DATA) {
		/*
		 * The aim here is to copy x bytes of data from immediately
		 * preceding the IP packet in the original mblk to the new
		 * mblk that now precedes it.  In doing this, b_rptr in the
		 * original packet is moved so that we don't transmit data
		 * that has been moved.
		 */
		int x;

		x = min(fin->fin_ipoff, m->b_rptr - m->b_datap->db_base);

		if (x > 0) {
			m->b_rptr -= x;
			bcopy(n->b_rptr, m->b_rptr, x);
			n->b_rptr += fin->fin_ipoff;
		}
		linkb(m, n);
		fin->fin_m = m;
		*fin->fin_mp = m;
		return;
	}

	/*
	 * If there are special mblk's at the ststart of the current message,
	 * pull them off the front and move them...good or bad?
	 */
	while ((n != NULL) && (MTYPE(n) != M_DATA)) {
		if (o == NULL)
			o = n;
		else
			linkb(o, n);
		n = unlinkb(n);
	}

	if (n != NULL)
		linkb(m, n);

	/*
	 * We know that o != NULL because to get here, the first mblk of n
	 * _must_ have not been an M_DATA..
	 */
	*fin->fin_mp = o;
	linkb(o, m);

	fin->fin_m = m;
}


/*
 * In the face of no kernel random function, this is implemented...it is
 * not meant to be random, just a fill in.
 */
int
ipf_random(int range)
{
	static int last = 0;
	static int calls = 0;
	struct timeval tv;
	int number;

	GETKTIME(&tv);
	last *= tv.tv_usec + calls++;
	last += (int)&range * ipf_ticks;
	number = last + tv.tv_sec;
	number %= range;
	return number;
}
