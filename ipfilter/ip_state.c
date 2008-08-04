/*
 * Copyright (C) 1995-2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2008 Sun Microsystems.
 *
 * $Id$
 */
#if defined(KERNEL) || defined(_KERNEL)
# undef KERNEL
# undef _KERNEL
# define        KERNEL	1
# define        _KERNEL	1
#endif
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/file.h>
#if defined(_KERNEL) && defined(__FreeBSD_version) && \
    (__FreeBSD_version >= 400000) && !defined(KLD_MODULE)
#include "opt_inet6.h"
#endif
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
#endif
#if defined(_KERNEL) && (__FreeBSD_version >= 220000)
# include <sys/filio.h>
# include <sys/fcntl.h>
#else
# include <sys/ioctl.h>
#endif
#include <sys/time.h>
#if !defined(linux)
# include <sys/protosw.h>
#endif
#include <sys/socket.h>
#if defined(_KERNEL)
# include <sys/systm.h>
# if !defined(__SVR4) && !defined(__svr4__)
#  include <sys/mbuf.h>
# endif
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

#include <net/if.h>
#ifdef sun
# include <net/af.h>
#endif
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#if !defined(linux)
# include <netinet/ip_var.h>
#endif
#if !defined(__hpux) && !defined(linux)
# include <netinet/tcp_fsm.h>
#endif
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "netinet/ip_compat.h"
#include <netinet/tcpip.h>
#include "netinet/ip_fil.h"
#include "netinet/ip_nat.h"
#include "netinet/ip_frag.h"
#include "netinet/ip_state.h"
#include "netinet/ip_proxy.h"
#include "netinet/ip_lookup.h"
#ifdef	IPFILTER_SYNC
#include "netinet/ip_sync.h"
#endif
#ifdef	IPFILTER_SCAN
#include "netinet/ip_scan.h"
#endif
#ifdef	USE_INET6
#include <netinet/icmp6.h>
#endif
#if (__FreeBSD_version >= 300000)
# include <sys/malloc.h>
# if defined(_KERNEL) && !defined(IPFILTER_LKM)
#  include <sys/libkern.h>
#  include <sys/systm.h>
# endif
#endif
/* END OF INCLUDES */


#if !defined(lint)
static const char sccsid[] = "@(#)ip_state.c	1.8 6/5/96 (C) 1993-2000 Darren Reed";
static const char rcsid[] = "@(#)$Id$";
#endif

static	ipstate_t **ipf_state_table = NULL;
static	u_long	*ipf_state_seed = NULL;
ips_stat_t ipf_state_stats;
static ipftq_t ipf_state_pending;
static ipftq_t ipf_state_deletetq;

#ifdef	USE_INET6
static ipstate_t *ipf_checkicmp6matchingstate __P((fr_info_t *));
#endif
static int ipf_allowstateicmp __P((fr_info_t *, ipstate_t *, i6addr_t *));
static ipstate_t *ipf_matchsrcdst __P((fr_info_t *, ipstate_t *, i6addr_t *,
				      i6addr_t *, tcphdr_t *, u_32_t));
static ipstate_t *ipf_checkicmpmatchingstate __P((fr_info_t *));
static int ipf_state_flush __P((int, int));
static int ipf_state_flush_entry __P((void *));
static ips_stat_t *ipf_statetstats __P((void));
static int ipf_state_del __P((ipstate_t *, int));
static int ipf_state_remove __P((caddr_t));
static int ipf_state_match __P((ipstate_t *is1, ipstate_t *is2));
static int ipf_state_matchaddresses __P((ipstate_t *is1, ipstate_t *is2));
static int ipf_state_matchipv4addrs __P((ipstate_t *is1, ipstate_t *is2));
static int ipf_state_matchipv6addrs __P((ipstate_t *is1, ipstate_t *is2));
static int ipf_state_matchisps __P((ipstate_t *is1, ipstate_t *is2));
static int ipf_state_matchports __P((udpinfo_t *is1, udpinfo_t *is2));
static int ipf_state_matcharray __P((ipstate_t *, int *));
static void ipf_ipsmove __P((ipstate_t *, u_int));
static int ipf_state_tcp __P((fr_info_t *, tcphdr_t *, ipstate_t *));
static int ipf_tcpoptions __P((fr_info_t *, tcphdr_t *, tcpdata_t *));
static ipstate_t *ipf_state_clone __P((fr_info_t *, tcphdr_t *, ipstate_t *));
static void ipf_fixinisn __P((fr_info_t *, ipstate_t *));
static void ipf_fixoutisn __P((fr_info_t *, ipstate_t *));
static void ipf_checknewisn __P((fr_info_t *, ipstate_t *));
static int ipf_stateiter __P((ipftoken_t *, ipfgeniter_t *));
static int ipf_stgettable __P((char *));

int ipf_stputent __P((caddr_t));
int ipf_stgetent __P((caddr_t));

#define	ONE_DAY		IPF_TTLVAL(1 * 86400)	/* 1 day */
#define	FIVE_DAYS	(5 * ONE_DAY)
#define	DOUBLE_HASH(x)	(((x) + ipf_state_seed[(x) % ipf_state_size]) % \
			 ipf_state_size)

u_int	ipf_tcpidletimeout = FIVE_DAYS,
	ipf_tcpclosewait = IPF_TTLVAL(2 * TCP_MSL),
	ipf_tcplastack = IPF_TTLVAL(30),
	ipf_tcptimewait = IPF_TTLVAL(2 * TCP_MSL),
	ipf_tcptimeout = IPF_TTLVAL(2 * TCP_MSL),
	ipf_tcpsynsent = IPF_TTLVAL(2 * TCP_MSL),
	ipf_tcpsynrecv = IPF_TTLVAL(2 * TCP_MSL),
	ipf_tcpclosed = IPF_TTLVAL(30),
	ipf_tcphalfclosed = IPF_TTLVAL(2 * 3600),	/* 2 hours */
	ipf_udptimeout = IPF_TTLVAL(120),
	ipf_udpacktimeout = IPF_TTLVAL(12),
	ipf_icmptimeout = IPF_TTLVAL(60),
	ipf_icmpacktimeout = IPF_TTLVAL(6),
	ipf_iptimeout = IPF_TTLVAL(60),
	ipf_state_wm_freq = IPF_TTLVAL(10),
	ipf_state_max = IPSTATE_MAX,
	ipf_state_size = IPSTATE_SIZE,
	ipf_state_maxbucket = 0,
	ipf_state_wm_last = 0,
	ipf_state_wm_high = 99,
	ipf_state_wm_low = 90,
	ipf_state_inited = 0;
int	ipf_state_lock = 0,
	ipf_state_doflush = 0;
ipftq_t	ipf_state_tcptq[IPF_TCP_NSTATES],
	ipf_state_udptq,
	ipf_state_udpacktq,
	ipf_state_iptq,
	ipf_state_icmptq,
	ipf_state_icmpacktq,
	*ipf_state_usertq = NULL;
#ifdef	IPFILTER_LOG
int	ipf_state_logging = 1;
#else
int	ipf_state_logging = 0;
#endif
ipstate_t *ipf_state_list = NULL;


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_init                                              */
/* Returns:     int - 0 == success, -1 == failure                           */
/* Parameters:  Nil                                                         */
/*                                                                          */
/* Initialise all the global variables used within the state code.          */
/* This action also includes initiailising locks.                           */
/* ------------------------------------------------------------------------ */
int
ipf_state_init()
{
	int i;

	KMALLOCS(ipf_state_table,
		 ipstate_t **, ipf_state_size * sizeof(ipstate_t *));
	if (ipf_state_table == NULL)
		return -1;

	bzero((char *)ipf_state_table, ipf_state_size * sizeof(ipstate_t *));

	KMALLOCS(ipf_state_seed, u_long *,
		 ipf_state_size * sizeof(*ipf_state_seed));
	if (ipf_state_seed == NULL)
		return -2;

	for (i = 0; i < ipf_state_size; i++) {
		/*
		 * XXX - ipf_state_seed[X] should be a random number of sorts.
		 */
#if  (__FreeBSD_version >= 400000)
		ipf_state_seed[i] = arc4random();
#else
		ipf_state_seed[i] = ((u_long)ipf_state_seed + i) *
				    ipf_state_size;
		ipf_state_seed[i] ^= 0xa5a55a5a;
		ipf_state_seed[i] *= (u_long)ipf_state_seed;
		ipf_state_seed[i] ^= 0x5a5aa5a5;
		ipf_state_seed[i] *= ipf_state_max;
#endif
	}

	/* fill icmp reply type table */
	for (i = 0; i <= ICMP_MAXTYPE; i++)
		icmpreplytype4[i] = -1;
	icmpreplytype4[ICMP_ECHO] = ICMP_ECHOREPLY;
	icmpreplytype4[ICMP_TSTAMP] = ICMP_TSTAMPREPLY;
	icmpreplytype4[ICMP_IREQ] = ICMP_IREQREPLY;
	icmpreplytype4[ICMP_MASKREQ] = ICMP_MASKREPLY;
#ifdef	USE_INET6
	/* fill icmp reply type table */
	for (i = 0; i <= ICMP6_MAXTYPE; i++)
		icmpreplytype6[i] = -1;
	icmpreplytype6[ICMP6_ECHO_REQUEST] = ICMP6_ECHO_REPLY;
	icmpreplytype6[ICMP6_MEMBERSHIP_QUERY] = ICMP6_MEMBERSHIP_REPORT;
	icmpreplytype6[ICMP6_NI_QUERY] = ICMP6_NI_REPLY;
	icmpreplytype6[ND_ROUTER_SOLICIT] = ND_ROUTER_ADVERT;
	icmpreplytype6[ND_NEIGHBOR_SOLICIT] = ND_NEIGHBOR_ADVERT;
#endif

	KMALLOCS(ipf_state_stats.iss_bucketlen, u_int *,
		 ipf_state_size * sizeof(u_int));
	if (ipf_state_stats.iss_bucketlen == NULL)
		return -1;
	bzero((char *)ipf_state_stats.iss_bucketlen,
	      ipf_state_size * sizeof(u_int));

	if (ipf_state_maxbucket == 0) {
		for (i = ipf_state_size; i > 0; i >>= 1)
			ipf_state_maxbucket++;
		ipf_state_maxbucket *= 2;
	}

	ipf_state_stats.iss_tcptab = ipf_state_tcptq;
	ipf_sttab_init(ipf_state_tcptq);
	ipf_state_tcptq[IPF_TCP_NSTATES - 1].ifq_next = &ipf_state_udptq;

	IPFTQ_INIT(&ipf_state_udptq, ipf_udptimeout, "ipftq udp tab");
	ipf_state_udptq.ifq_next = &ipf_state_udpacktq;

	IPFTQ_INIT(&ipf_state_udpacktq, ipf_udpacktimeout, "ipftq udpack tab");
	ipf_state_udpacktq.ifq_next = &ipf_state_icmptq;

	IPFTQ_INIT(&ipf_state_icmptq, ipf_icmptimeout, "ipftq icmp tab");
	ipf_state_icmptq.ifq_next = &ipf_state_icmpacktq;

	IPFTQ_INIT(&ipf_state_icmpacktq, ipf_icmpacktimeout,
		  "ipftq icmpack tab");
	ipf_state_icmpacktq.ifq_next = &ipf_state_iptq;

	IPFTQ_INIT(&ipf_state_iptq, ipf_iptimeout, "ipftq iptimeout tab");
	ipf_state_iptq.ifq_next = &ipf_state_pending;

	IPFTQ_INIT(&ipf_state_pending, 1, "ipftq pending");
	ipf_state_pending.ifq_next = &ipf_state_deletetq;

	IPFTQ_INIT(&ipf_state_deletetq, 1, "ipftq delete");
	ipf_state_deletetq.ifq_next = NULL;

	RWLOCK_INIT(&ipf_state, "ipf IP state rwlock");
	MUTEX_INIT(&ipf_stinsert, "ipf state insert mutex");

	ipf_state_inited = 1;

	ipf_state_wm_last = ipf_ticks;
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_unload                                            */
/* Returns:     Nil                                                         */
/* Parameters:  Nil                                                         */
/*                                                                          */
/* Release and destroy any resources acquired or initialised so that        */
/* IPFilter can be unloaded or re-initialised.                              */
/* ------------------------------------------------------------------------ */
void
ipf_state_unload()
{
	ipftq_t *ifq, *ifqnext;
	ipstate_t *is;

	while ((is = ipf_state_list) != NULL)
		ipf_state_del(is, ISL_UNLOAD);

	/*
	 * Proxy timeout queues are not cleaned here because although they
	 * exist on the state list, appr_unload is called after
	 * ipf_state_unload and the proxies actually are responsible for them
	 * being created. Should the proxy timeouts have their own list?
	 * There's no real justification as this is the only complication.
	 */
	for (ifq = ipf_state_usertq; ifq != NULL; ifq = ifqnext) {
		ifqnext = ifq->ifq_next;
		if (((ifq->ifq_flags & IFQF_PROXY) == 0) &&
		    (ipf_deletetimeoutqueue(ifq) == 0))
			ipf_freetimeoutqueue(ifq);
	}

	ipf_state_stats.iss_inuse = 0;
	ipf_state_stats.iss_active = 0;

	if (ipf_state_inited == 1) {
		ipf_sttab_destroy(ipf_state_tcptq);
		MUTEX_DESTROY(&ipf_state_udptq.ifq_lock);
		MUTEX_DESTROY(&ipf_state_icmptq.ifq_lock);
		MUTEX_DESTROY(&ipf_state_udpacktq.ifq_lock);
		MUTEX_DESTROY(&ipf_state_icmpacktq.ifq_lock);
		MUTEX_DESTROY(&ipf_state_iptq.ifq_lock);
		MUTEX_DESTROY(&ipf_state_deletetq.ifq_lock);
	}

	if (ipf_state_table != NULL) {
		KFREES(ipf_state_table,
		       ipf_state_size * sizeof(*ipf_state_table));
		ipf_state_table = NULL;
	}

	if (ipf_state_seed != NULL) {
		KFREES(ipf_state_seed,
		       ipf_state_size * sizeof(*ipf_state_seed));
		ipf_state_seed = NULL;
	}

	if (ipf_state_stats.iss_bucketlen != NULL) {
		KFREES(ipf_state_stats.iss_bucketlen,
		       ipf_state_size * sizeof(u_int));
		ipf_state_stats.iss_bucketlen = NULL;
	}

	if (ipf_state_inited == 1) {
		ipf_state_inited = 0;
		RW_DESTROY(&ipf_state);
		MUTEX_DESTROY(&ipf_stinsert);
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_statetstats                                             */
/* Returns:     ips_state_t* - pointer to state stats structure             */
/* Parameters:  Nil                                                         */
/*                                                                          */
/* Put all the current numbers and pointers into a single struct and return */
/* a pointer to it.                                                         */
/* ------------------------------------------------------------------------ */
static ips_stat_t *
ipf_statetstats()
{
	ipf_state_stats.iss_state_size = ipf_state_size;
	ipf_state_stats.iss_state_max = ipf_state_max;
	ipf_state_stats.iss_table = ipf_state_table;
	ipf_state_stats.iss_list = ipf_state_list;
	ipf_state_stats.iss_ticks = ipf_ticks;
	return &ipf_state_stats;
}

/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_remove                                            */
/* Returns:     int - 0 == success, != 0 == failure                         */
/* Parameters:  data(I) - pointer to state structure to delete from table   */
/*                                                                          */
/* Search for a state structure that matches the one passed, according to   */
/* the IP addresses and other protocol specific information.                */
/* ------------------------------------------------------------------------ */
static int
ipf_state_remove(data)
	caddr_t data;
{
	ipstate_t *sp, st;
	int error;

	sp = &st;
	error = ipf_inobj(data, &st, IPFOBJ_IPSTATE);
	if (error)
		return EFAULT;

	WRITE_ENTER(&ipf_state);
	for (sp = ipf_state_list; sp; sp = sp->is_next)
		if ((sp->is_p == st.is_p) && (sp->is_v == st.is_v) &&
		    !bcmp((caddr_t)&sp->is_src, (caddr_t)&st.is_src,
			  sizeof(st.is_src)) &&
		    !bcmp((caddr_t)&sp->is_dst, (caddr_t)&st.is_dst,
			  sizeof(st.is_dst)) &&
		    !bcmp((caddr_t)&sp->is_ps, (caddr_t)&st.is_ps,
			  sizeof(st.is_ps))) {
			ipf_state_del(sp, ISL_REMOVE);
			RWLOCK_EXIT(&ipf_state);
			return 0;
		}
	RWLOCK_EXIT(&ipf_state);

	ipf_interror = 100001;
	return ESRCH;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_ioctl                                             */
/* Returns:     int - 0 == success, != 0 == failure                         */
/* Parameters:  data(I) - pointer to ioctl data                             */
/*              cmd(I)  - ioctl command integer                             */
/*              mode(I) - file mode bits used with open                     */
/*                                                                          */
/* Processes an ioctl call made to operate on the IP Filter state device.   */
/* ------------------------------------------------------------------------ */
int
ipf_state_ioctl(data, cmd, mode, uid, ctx)
	caddr_t data;
	ioctlcmd_t cmd;
	int mode, uid;
	void *ctx;
{
	int arg, ret, error = 0;
	SPL_INT(s);

	switch (cmd)
	{
	/*
	 * Delete an entry from the state table.
	 */
	case SIOCDELST :
		error = ipf_state_remove(data);
		break;

	/*
	 * Flush the state table
	 */
	case SIOCIPFFL :
		error = BCOPYIN(data, &arg, sizeof(arg));
		if (error != 0) {
			ipf_interror = 100002;
			error = EFAULT;

		} else {
			WRITE_ENTER(&ipf_state);
			ret = ipf_state_flush(arg, 4);
			RWLOCK_EXIT(&ipf_state);

			error = BCOPYOUT(&ret, data, sizeof(ret));
			if (error != 0) {
				ipf_interror = 100003;
				error = EFAULT;
			}
		}
		break;

#ifdef	USE_INET6
	case SIOCIPFL6 :
		error = BCOPYIN(data, &arg, sizeof(arg));
		if (error != 0) {
			ipf_interror = 100004;
			error = EFAULT;

		} else {
			WRITE_ENTER(&ipf_state);
			ret = ipf_state_flush(arg, 6);
			RWLOCK_EXIT(&ipf_state);

			error = BCOPYOUT(&ret, data, sizeof(ret));
			if (error != 0) {
				ipf_interror = 100005;
				error = EFAULT;
			}
		}
		break;
#endif

	case SIOCMATCHFLUSH :
		WRITE_ENTER(&ipf_state);
		error = ipf_state_matchflush(data);
		RWLOCK_EXIT(&ipf_state);
		break;

#ifdef	IPFILTER_LOG
	/*
	 * Flush the state log.
	 */
	case SIOCIPFFB :
		if (!(mode & FWRITE)) {
			ipf_interror = 100008;
			error = EPERM;
		} else {
			int tmp;

			tmp = ipf_log_clear(IPL_LOGSTATE);
			error = BCOPYOUT(&tmp, data, sizeof(tmp));
			if (error != 0) {
				ipf_interror = 100009;
				error = EFAULT;
			}
		}
		break;

	/*
	 * Turn logging of state information on/off.
	 */
	case SIOCSETLG :
		if (!(mode & FWRITE)) {
			ipf_interror = 100010;
			error = EPERM;
		} else {
			error = BCOPYIN(data, &ipf_state_logging,
					sizeof(ipf_state_logging));
			if (error != 0) {
				ipf_interror = 100011;
				error = EFAULT;
			}
		}
		break;

	/*
	 * Return the current state of logging.
	 */
	case SIOCGETLG :
		error = BCOPYOUT(&ipf_state_logging, data,
				 sizeof(ipf_state_logging));
		if (error != 0) {
			ipf_interror = 100012;
			error = EFAULT;
		}
		break;

	/*
	 * Return the number of bytes currently waiting to be read.
	 */
	case FIONREAD :
		arg = iplused[IPL_LOGSTATE];	/* returned in an int */
		error = BCOPYOUT(&arg, data, sizeof(arg));
		if (error != 0) {
			ipf_interror = 100013;
			error = EFAULT;
		}
		break;
#endif

	/*
	 * Get the current state statistics.
	 */
	case SIOCGETFS :
		error = ipf_outobj(data, ipf_statetstats(), IPFOBJ_STATESTAT);
		break;

	/*
	 * Lock/Unlock the state table.  (Locking prevents any changes, which
	 * means no packets match).
	 */
	case SIOCSTLCK :
		if (!(mode & FWRITE)) {
			ipf_interror = 100014;
			error = EPERM;
		} else {
			error = ipf_lock(data, &ipf_state_lock);
		}
		break;

	/*
	 * Add an entry to the current state table.
	 */
	case SIOCSTPUT :
		if (!ipf_state_lock || !(mode &FWRITE)) {
			ipf_interror = 100015;
			error = EACCES;
			break;
		}
		error = ipf_stputent(data);
		break;

	/*
	 * Get a state table entry.
	 */
	case SIOCSTGET :
		if (!ipf_state_lock) {
			ipf_interror = 100016;
			error = EACCES;
			break;
		}
		error = ipf_stgetent(data);
		break;

	/*
	 * Return a copy of the hash table bucket lengths
	 */
	case SIOCSTAT1 :
		error = BCOPYOUT(ipf_state_stats.iss_bucketlen, data,
				 ipf_state_size * sizeof(u_int));
		if (error != 0) {
			ipf_interror = 100017;
			error = EFAULT;
		}
		break;

	case SIOCGENITER :
	    {
		ipftoken_t *token;
		ipfgeniter_t iter;

		error = ipf_inobj(data, &iter, IPFOBJ_GENITER);
		if (error != 0)
			break;

		SPL_SCHED(s);
		token = ipf_findtoken(IPFGENITER_STATE, uid, ctx);
		if (token != NULL) {
			error = ipf_stateiter(token, &iter);
		} else {
			ipf_interror = 100018;
			error = ESRCH;
		}
		RWLOCK_EXIT(&ipf_tokens);
		SPL_X(s);
		break;
	    }

	case SIOCGTABL :
		error = ipf_stgettable(data);
		break;

	case SIOCIPFDELTOK :
		error = BCOPYIN(data, &arg, sizeof(arg));
		if (error != 0) {
			ipf_interror = 100019;
			error = EFAULT;
		} else {
			SPL_SCHED(s);
			error = ipf_deltoken(arg, uid, ctx);
			SPL_X(s);
		}
		break;

	case SIOCGTQTAB :
		error = ipf_outobj(data, ipf_state_tcptq, IPFOBJ_STATETQTAB);
		break;

	default :
		ipf_interror = 100020;
		error = EINVAL;
		break;
	}
	return error;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_stgetent                                                */
/* Returns:     int - 0 == success, != 0 == failure                         */
/* Parameters:  data(I) - pointer to state structure to retrieve from table */
/*                                                                          */
/* Copy out state information from the kernel to a user space process.  If  */
/* there is a filter rule associated with the state entry, copy that out    */
/* as well.  The entry to copy out is taken from the value of "ips_next" in */
/* the struct passed in and if not null and not found in the list of current*/
/* state entries, the retrieval fails.                                      */
/* ------------------------------------------------------------------------ */
int
ipf_stgetent(data)
	caddr_t data;
{
	ipstate_t *is, *isn;
	ipstate_save_t ips;
	int error;

	error = ipf_inobj(data, &ips, IPFOBJ_STATESAVE);
	if (error)
		return EFAULT;

	READ_ENTER(&ipf_state);
	isn = ips.ips_next;
	if (isn == NULL) {
		isn = ipf_state_list;
		if (isn == NULL) {
			if (ips.ips_next == NULL) {
				RWLOCK_EXIT(&ipf_state);
				ipf_interror = 100021;
				return ENOENT;
			}
			return 0;
		}
	} else {
		/*
		 * Make sure the pointer we're copying from exists in the
		 * current list of entries.  Security precaution to prevent
		 * copying of random kernel data.
		 */
		for (is = ipf_state_list; is; is = is->is_next)
			if (is == isn)
				break;
		if (!is) {
			RWLOCK_EXIT(&ipf_state);
			ipf_interror = 100022;
			return ESRCH;
		}
	}
	ips.ips_next = isn->is_next;
	bcopy((char *)isn, (char *)&ips.ips_is, sizeof(ips.ips_is));
	ips.ips_rule = isn->is_rule;
	if (isn->is_rule != NULL)
		bcopy((char *)isn->is_rule, (char *)&ips.ips_fr,
		      sizeof(ips.ips_fr));
	RWLOCK_EXIT(&ipf_state);
	error = ipf_outobj(data, &ips, IPFOBJ_STATESAVE);
	return error;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_stputent                                                */
/* Returns:     int - 0 == success, != 0 == failure                         */
/* Parameters:  data(I) - pointer to state information struct               */
/*                                                                          */
/* This function implements the SIOCSTPUT ioctl: insert a state entry into  */
/* the state table.  If the state info. includes a pointer to a filter rule */
/* then also add in an orphaned rule (will not show up in any "ipfstat -io" */
/* output.                                                                  */
/* ------------------------------------------------------------------------ */
int
ipf_stputent(data)
	caddr_t data;
{
	ipstate_t *is, *isn;
	ipstate_save_t ips;
	int error, out, i;
	frentry_t *fr;
	char *name;

	error = ipf_inobj(data, &ips, IPFOBJ_STATESAVE);
	if (error != 0)
		return error;

	KMALLOC(isn, ipstate_t *);
	if (isn == NULL) {
		ipf_interror = 100023;
		return ENOMEM;
	}

	bcopy((char *)&ips.ips_is, (char *)isn, sizeof(*isn));
	bzero((char *)isn, offsetof(struct ipstate, is_pkts));
	isn->is_sti.tqe_pnext = NULL;
	isn->is_sti.tqe_next = NULL;
	isn->is_sti.tqe_ifq = NULL;
	isn->is_sti.tqe_parent = isn;
	isn->is_ifp[0] = NULL;
	isn->is_ifp[1] = NULL;
	isn->is_ifp[2] = NULL;
	isn->is_ifp[3] = NULL;
	isn->is_sync = NULL;
	fr = ips.ips_rule;

	if (fr == NULL) {
		READ_ENTER(&ipf_state);
		ipf_state_insert(isn, 0);
		MUTEX_EXIT(&isn->is_lock);
		RWLOCK_EXIT(&ipf_state);
		return 0;
	}

	if (isn->is_flags & SI_NEWFR) {
		KMALLOC(fr, frentry_t *);
		if (fr == NULL) {
			KFREE(isn);
			ipf_interror = 100024;
			return ENOMEM;
		}
		bcopy((char *)&ips.ips_fr, (char *)fr, sizeof(*fr));
		out = fr->fr_flags & FR_OUTQUE ? 1 : 0;
		isn->is_rule = fr;
		ips.ips_is.is_rule = fr;
		MUTEX_NUKE(&fr->fr_lock);
		MUTEX_INIT(&fr->fr_lock, "state filter rule lock");

		/*
		 * Look up all the interface names in the rule.
		 */
		for (i = 0; i < 4; i++) {
			name = fr->fr_ifnames[i];
			fr->fr_ifas[i] = ipf_resolvenic(name, fr->fr_family);
			name = isn->is_ifname[i];
			isn->is_ifp[i] = ipf_resolvenic(name, isn->is_v);
		}

		fr->fr_ref = 0;
		fr->fr_dsize = 0;
		fr->fr_data = NULL;
		fr->fr_type = FR_T_NONE;

		ipf_resolvedest(&fr->fr_tifs[0], fr->fr_family);
		ipf_resolvedest(&fr->fr_tifs[1], fr->fr_family);
		ipf_resolvedest(&fr->fr_dif, fr->fr_family);

		/*
		 * send a copy back to userland of what we ended up
		 * to allow for verification.
		 */
		error = ipf_outobj(data, &ips, IPFOBJ_STATESAVE);
		if (error != 0) {
			KFREE(isn);
			MUTEX_DESTROY(&fr->fr_lock);
			KFREE(fr);
			ipf_interror = 100025;
			return EFAULT;
		}
		READ_ENTER(&ipf_state);
		ipf_state_insert(isn, 0);
		MUTEX_EXIT(&isn->is_lock);
		RWLOCK_EXIT(&ipf_state);

	} else {
		READ_ENTER(&ipf_state);
		for (is = ipf_state_list; is; is = is->is_next)
			if (is->is_rule == fr) {
				ipf_state_insert(isn, 0);
				MUTEX_EXIT(&isn->is_lock);
				break;
			}

		if (is == NULL) {
			KFREE(isn);
			isn = NULL;
		}
		RWLOCK_EXIT(&ipf_state);

		if (isn == NULL) {
			ipf_interror = 100033;
			return ESRCH;
		}
	}

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:   ipf_state_insert                                             */
/* Returns:    Nil                                                          */
/* Parameters: is(I)  - pointer to state structure                          */
/*             rev(I) - flag indicating forward/reverse direction of packet */
/*                                                                          */
/* Inserts a state structure into the hash table (for lookups) and the list */
/* of state entries (for enumeration).  Resolves all of the interface names */
/* to pointers and adjusts running stats for the hash table as appropriate. */
/*                                                                          */
/* Locking: it is assumed that some kind of lock on ipf_state is held.      */
/*          Exits with is_lock initialised and held.                        */
/* ------------------------------------------------------------------------ */
void
ipf_state_insert(is, rev)
	ipstate_t *is;
	int rev;
{
	frentry_t *fr;
	u_int hv;
	int i;

	MUTEX_INIT(&is->is_lock, "ipf state entry");

	fr = is->is_rule;
	if (fr != NULL) {
		MUTEX_ENTER(&fr->fr_lock);
		fr->fr_ref++;
		fr->fr_statecnt++;
		MUTEX_EXIT(&fr->fr_lock);
	}

	/*
	 * Look up all the interface names in the state entry.
	 */
	for (i = 0; i < 4; i++) {
		if (is->is_ifp[i] != NULL)
			continue;
		is->is_ifp[i] = ipf_resolvenic(is->is_ifname[i], is->is_v);
	}

	/*
	 * If we could trust is_hv, then the modulous would not be needed,
	 * but when running with IPFILTER_SYNC, this stops bad values.
	 */
	hv = is->is_hv % ipf_state_size;
	/* TRACE is, hv */
	is->is_hv = hv;

	/*
	 * We need to get both of these locks...the first because it is
	 * possible that once the insert is complete another packet might
	 * come along, match the entry and want to update it.
	 */
	MUTEX_ENTER(&is->is_lock);
	MUTEX_ENTER(&ipf_stinsert);

	/*
	 * add into list table.
	 */
	if (ipf_state_list != NULL)
		ipf_state_list->is_pnext = &is->is_next;
	is->is_pnext = &ipf_state_list;
	is->is_next = ipf_state_list;
	ipf_state_list = is;

	if (ipf_state_table[hv] != NULL)
		ipf_state_table[hv]->is_phnext = &is->is_hnext;
	else
		ipf_state_stats.iss_inuse++;
	is->is_phnext = ipf_state_table + hv;
	is->is_hnext = ipf_state_table[hv];
	ipf_state_table[hv] = is;
	ipf_state_stats.iss_bucketlen[hv]++;
	ipf_state_stats.iss_active++;
	MUTEX_EXIT(&ipf_stinsert);

	ipf_state_setqueue(is, rev);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_matchipv4addrs                                          */
/* Returns:     int - 2 addresses match (strong match), 1 reverse match,    */
/*                    0 no match                                            */
/* Parameters:  is1, is2 pointers to states we are checking                 */
/*                                                                          */
/* Function matches IPv4 addresses it returns strong match for ICMP proto   */
/* even there is only reverse match                                         */
/* ------------------------------------------------------------------------ */
static int
ipf_state_matchipv4addrs(is1, is2)
	ipstate_t *is1, *is2;
{
	int	rv;

	if (is1->is_saddr == is2->is_saddr && is1->is_daddr == is2->is_daddr)
		rv = 2;
	else if (is1->is_saddr == is2->is_daddr && 
	    is1->is_daddr == is2->is_saddr) {
		/* force strong match for ICMP protocol */
		rv = (is1->is_p == IPPROTO_ICMP) ? 2 : 1;
	}
	else
		rv = 0;

	return (rv);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_matchipv6addrs                                          */
/* Returns:     int - 2 addresses match (strong match), 1 reverse match,    */
/*                    0 no match                                            */
/* Parameters:  is1, is2 pointers to states we are checking                 */
/*                                                                          */
/* Function matches IPv6 addresses it returns strong match for ICMP proto   */
/* even there is only reverse match                                         */
/* ------------------------------------------------------------------------ */
static int
ipf_state_matchipv6addrs(is1, is2)
	ipstate_t *is1, *is2;
{
	int	rv;

	if (IP6_EQ(&is1->is_src, &is2->is_src) && 
	    IP6_EQ(&is1->is_dst, &is2->is_dst))  
		rv = 2;
	else if (IP6_EQ(&is1->is_src, &is2->is_dst) &&
	    IP6_EQ(&is1->is_dst, &is2->is_src)) {
		/* force strong match for ICMPv6 protocol */
		rv = (is1->is_p == IPPROTO_ICMPV6) ? 2 : 1;
	}
	else
		rv = 0;

	return (rv);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_matchaddresses                                          */
/* Returns:     int - 2 addresses match, 1 reverse match, zero no match     */
/* Parameters:  is1, is2 pointers to states we are checking                 */
/*                                                                          */
/* function retruns true if two pairs of addresses belong to single         */
/* connection. suppose there are two endpoints:                             */
/*      endpoint1 1.1.1.1                                                   */
/*      endpoint2 1.1.1.2                                                   */
/*                                                                          */
/* the state is established by packet flying from .1 to .2 so we see:       */
/*      is1->src = 1.1.1.1                                                  */
/*      is1->dst = 1.1.1.2                                                  */
/* now endpoint 1.1.1.2 sends answer                                        */
/* retreives is1 record created by first packat and compares it with is2    */
/* temporal record, is2 is initialized as follows:                          */
/*      is2->src = 1.1.1.2                                                  */
/*      is2->dst = 1.1.1.1                                                  */
/* in this case 1 will be returned                                          */
/*                                                                          */
/* the ipf_matchaddresses() assumes those two records to be same. of course */
/* the ipf_matchaddresses() also assume records are same in case you pass   */
/* identical arguments (i.e. ipf_matchaddress(is1, is1) would return 2      */
/* ------------------------------------------------------------------------ */
static int
ipf_state_matchaddresses(is1, is2)
	ipstate_t *is1, *is2;
{
	int	rv;

	if (is1->is_v == 4) {
		rv = ipf_state_matchipv4addrs(is1, is2);
	}
	else {
		rv = ipf_state_matchipv6addrs(is1, is2);
	}

	return (rv);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_matchports                                              */
/* Returns:     int - 2 match, 1 rverse match, 0 no match                   */
/* Parameters:  ppairs1, ppairs - src, dst ports we want to match           */
/*                                                                          */
/* performs the same match for isps members as for addresses                */
/* ------------------------------------------------------------------------ */
static int
ipf_state_matchports(ppairs1, ppairs2)
	udpinfo_t *ppairs1, *ppairs2;
{
	int	rv;

	if (ppairs1->us_sport == ppairs2->us_sport && 
	    ppairs1->us_dport == ppairs2->us_dport)
		rv = 2;
	else if (ppairs1->us_sport == ppairs2->us_dport && 
		    ppairs1->us_dport == ppairs2->us_sport)
		rv = 1;
	else
		rv = 0;

	return (rv);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_matchisps                                               */
/* Returns:     int - nonzero if isps members match, 0 nomatch              */
/* Parameters:  is1, is2 - states we want to match                          */
/*                                                                          */
/* performs the same match for isps members as for addresses                */
/* ------------------------------------------------------------------------ */
static int
ipf_state_matchisps(is1, is2)
	ipstate_t *is1, *is2;
{
	int	rv;

	if (is1->is_p == is2->is_p) {
		switch (is1->is_p)
		{
		case IPPROTO_TCP :
		case IPPROTO_UDP :
		case IPPROTO_GRE :
			/* greinfo_t can be also interprted as port pair */
			rv = ipf_state_matchports(&is1->is_ps.is_us,
						  &is2->is_ps.is_us);
			break;

		case IPPROTO_ICMP :
		case IPPROTO_ICMPV6 :
			/* force strong match for ICMP datagram. */
			if (bcmp(&is1->is_ps, &is2->is_ps,
				 sizeof(icmpinfo_t)) == 0)  {
				rv = 2;
			} else {
				rv = 0;
			}
			break;

		default:
			rv = 0;
		}
	} else {
		rv = 0;
	}

	return (rv);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_match                                             */
/* Returns:     int - nonzero match, zero no match                          */
/* Parameters:  is1, is2 - states we want to match                          */
/*                                                                          */
/* ------------------------------------------------------------------------ */
static int
ipf_state_match(is1, is2)
	ipstate_t *is1, *is2;
{
	int	rv;
	int	amatch;
	int	pmatch;

	if (bcmp(&is1->is_pass, &is2->is_pass,
		 offsetof(struct ipstate, is_authmsk) -
		 offsetof(struct ipstate, is_pass)) == 0) {

		pmatch = ipf_state_matchisps(is1, is2);
		amatch = ipf_state_matchaddresses(is1, is2);
		rv = (amatch != 0) && (amatch == pmatch);
	} else {
		rv = 0;
	}

	return (rv);
}

/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_add                                               */
/* Returns:     ipstate_t - 0 = success                                     */
/* Parameters:  fin(I)    - pointer to packet information                   */
/*              stsave(O) - pointer to place to save pointer to created     */
/*                          state structure.                                */
/*              flags(I)  - flags to use when creating the structure        */
/*                                                                          */
/* Creates a new IP state structure from the packet information collected.  */
/* Inserts it into the state table and appends to the bottom of the active  */
/* list.  If the capacity of the table has reached the maximum allowed then */
/* the call will fail and a flush is scheduled for the next timeout call.   */
/*                                                                          */
/* NOTE: The use of stsave to point to nat_state will result in memory      */
/*       corruption.  It should only be used to point to objects that will  */
/*       either outlive this (not expired) or will deref the ip_state_t     */
/*       when they are deleted.                                             */
/* ------------------------------------------------------------------------ */
int
ipf_state_add(fin, stsave, flags)
	fr_info_t *fin;
	void **stsave;
	u_int flags;
{
	ipstate_t *is, ips;
	struct icmp *ic;
	u_int pass, hv;
	frentry_t *fr;
	tcphdr_t *tcp;
	frdest_t *fdp;
#if 0
	grehdr_t *gre;
#endif
	int out;

	if (ipf_state_lock ||
	    (fin->fin_flx & (FI_SHORT|FI_STATE|FI_FRAGBODY|FI_BAD)) ||
	    ((fin->fin_flx & FI_OOW) && !(fin->fin_tcpf & TH_SYN))) {
		ATOMIC_INCL(ipf_state_stats.iss_add_bad);
		return -1;
	}

	if ((ipf_state_stats.iss_active * 100 / ipf_state_max) >
	    ipf_state_wm_high) {
		ipf_state_doflush = 1;
	}

	/*
	 * If a "keep state" rule has reached the maximum number of references
	 * to it, then schedule an automatic flush in case we can clear out
	 * some "dead old wood".  Note that because the lock isn't held on
	 * fr it is possible that we could overflow.  The cost of overflowing
	 * is being ignored here as the number by which it can overflow is
	 * a product of the number of simultaneous threads that could be
	 * executing in here, so a limit of 100 won't result in 200, but could
	 * result in 101 or 102.
	 */
	fr = fin->fin_fr;
	if (fr != NULL) {
		if ((ipf_state_stats.iss_active >= ipf_state_max) &&
		    (fr->fr_statemax == 0)) {
			ATOMIC_INCL(ipf_state_stats.iss_max);
			return 1;
		}
		if ((fr->fr_statemax != 0) &&
		    (fr->fr_statecnt >= fr->fr_statemax)) {
			ATOMIC_INCL(ipf_state_stats.iss_max_ref);
			return 2;
		}
	}

	is = &ips;
	if (fr == NULL) {
		pass = ipf_flags;
		is->is_tag = FR_NOLOGTAG;
	} else {
		pass = fr->fr_flags;
	}

	ic = NULL;
	tcp = NULL;
	out = fin->fin_out;
	bzero((char *)is, sizeof(*is));
	is->is_die = 1 + ipf_ticks;
	/*
	 * We want to check everything that is a property of this packet,
	 * but we don't (automatically) care about it's fragment status as
	 * this may change.
	 */
	is->is_pass = pass;
	is->is_v = fin->fin_v;
	is->is_opt[0] = fin->fin_optmsk;
	is->is_optmsk[0] = 0xffffffff;
	is->is_optmsk[1] = 0xffffffff;
	if (is->is_v == 6) {
		is->is_opt[0] &= ~0x8;
		is->is_optmsk[0] &= ~0x8;
		is->is_optmsk[1] &= ~0x8;
	}
	is->is_sec = fin->fin_secmsk;
	is->is_secmsk = 0xffff;
	is->is_auth = fin->fin_auth;
	is->is_authmsk = 0xffff;

	/*
	 * Copy and calculate...
	 */
	hv = (is->is_p = fin->fin_fi.fi_p);
	is->is_src = fin->fin_fi.fi_src;
	hv += is->is_saddr;
	is->is_dst = fin->fin_fi.fi_dst;
	hv += is->is_daddr;
#ifdef	USE_INET6
	if (fin->fin_v == 6) {
		/*
		 * For ICMPv6, we check to see if the destination address is
		 * a multicast address.  If it is, do not include it in the
		 * calculation of the hash because the correct reply will come
		 * back from a real address, not a multicast address.
		 */
		if ((is->is_p == IPPROTO_ICMPV6) &&
		    IN6_IS_ADDR_MULTICAST(&is->is_dst.in6)) {
			/*
			 * So you can do keep state with neighbour discovery.
			 *
			 * Here we could use the address from the neighbour
			 * solicit message to put in the state structure and
			 * we could use that without a wildcard flag too...
			 */
			flags |= SI_W_DADDR;
			hv -= is->is_daddr;
		} else {
			hv += is->is_dst.i6[1];
			hv += is->is_dst.i6[2];
			hv += is->is_dst.i6[3];
		}
		hv += is->is_src.i6[1];
		hv += is->is_src.i6[2];
		hv += is->is_src.i6[3];
	}
#endif
	if ((fin->fin_v == 4) &&
	    (fin->fin_flx & (FI_MULTICAST|FI_BROADCAST|FI_MBCAST))) {
		flags |= SI_W_DADDR;
		hv -= is->is_daddr;
	}

	switch (is->is_p)
	{
#ifdef	USE_INET6
	case IPPROTO_ICMPV6 :
		ic = fin->fin_dp;

		switch (ic->icmp_type)
		{
		case ICMP6_ECHO_REQUEST :
			hv += (is->is_icmp.ici_id = ic->icmp_id);
			/*FALLTHROUGH*/
		case ICMP6_MEMBERSHIP_QUERY :
		case ND_ROUTER_SOLICIT :
		case ND_NEIGHBOR_SOLICIT :
		case ICMP6_NI_QUERY :
			is->is_icmp.ici_type = ic->icmp_type;
			break;
		default :
			ATOMIC_INCL(ipf_state_stats.iss_icmp6_notquery);
			return -2;
		}
		break;
#endif
	case IPPROTO_ICMP :
		ic = fin->fin_dp;

		switch (ic->icmp_type)
		{
		case ICMP_ECHO :
		case ICMP_TSTAMP :
		case ICMP_IREQ :
		case ICMP_MASKREQ :
			is->is_icmp.ici_type = ic->icmp_type;
			hv += (is->is_icmp.ici_id = ic->icmp_id);
			break;
		default :
			ATOMIC_INCL(ipf_state_stats.iss_icmp_notquery);
			return -3;
		}
		break;

#if 0
	case IPPROTO_GRE :
		gre = fin->fin_dp;

		is->is_gre.gs_flags = gre->gr_flags;
		is->is_gre.gs_ptype = gre->gr_ptype;
		if (GRE_REV(is->is_gre.gs_flags) == 1) {
			is->is_call[0] = fin->fin_data[0];
			is->is_call[1] = fin->fin_data[1];
		}
		break;
#endif
	if ((fin->fin_v == 4) &&
	    (fin->fin_flx & (FI_MULTICAST|FI_BROADCAST|FI_MBCAST))) {
		if (fin->fin_out == 0) {
			flags |= SI_W_DADDR|SI_CLONE;
			hv -= is->is_daddr;
		} else {
			flags |= SI_W_SADDR|SI_CLONE;
			hv -= is->is_saddr;
		}
	}

	case IPPROTO_TCP :
		tcp = fin->fin_dp;

		if (tcp->th_flags & TH_RST) {
			ATOMIC_INCL(ipf_state_stats.iss_tcp_rstadd);
			return -4;
		}

		/* TRACE is, flags, hv */

		/*
		 * The endian of the ports doesn't matter, but the ack and
		 * sequence numbers do as we do mathematics on them later.
		 */
		is->is_sport = htons(fin->fin_data[0]);
		is->is_dport = htons(fin->fin_data[1]);
		if ((flags & (SI_W_DPORT|SI_W_SPORT)) == 0) {
			hv += is->is_sport;
			hv += is->is_dport;
		}

		/* TRACE is, flags, hv */

		/*
		 * If this is a real packet then initialise fields in the
		 * state information structure from the TCP header information.
		 */

		is->is_maxdwin = 1;
		is->is_maxswin = ntohs(tcp->th_win);
		if (is->is_maxswin == 0)
			is->is_maxswin = 1;

		if ((fin->fin_flx & FI_IGNORE) == 0) {
			is->is_send = ntohl(tcp->th_seq) + fin->fin_dlen -
				      (TCP_OFF(tcp) << 2) +
				      ((tcp->th_flags & TH_SYN) ? 1 : 0) +
				      ((tcp->th_flags & TH_FIN) ? 1 : 0);
			is->is_maxsend = is->is_send;

			/*
			 * Window scale option is only present in
			 * SYN/SYN-ACK packet.
			 */
			if ((tcp->th_flags & ~(TH_FIN|TH_ACK|TH_ECNALL)) ==
			    TH_SYN &&
			    (TCP_OFF(tcp) > (sizeof(tcphdr_t) >> 2))) {
				if (ipf_tcpoptions(fin, tcp,
					      &is->is_tcp.ts_data[0]) == -1) {
					fin->fin_flx |= FI_BAD;
				}
			}

			if ((fin->fin_out != 0) && (pass & FR_NEWISN) != 0) {
				ipf_checknewisn(fin, is);
				ipf_fixoutisn(fin, is);
			}

			if ((tcp->th_flags & TH_OPENING) == TH_SYN)
				flags |= IS_TCPFSM;
			else {
				is->is_maxdwin = is->is_maxswin * 2;
				is->is_dend = ntohl(tcp->th_ack);
				is->is_maxdend = ntohl(tcp->th_ack);
				is->is_maxdwin *= 2;
			}
		}

		/*
		 * If we're creating state for a starting connection, start
		 * the timer on it as we'll never see an error if it fails
		 * to connect.
		 */
		break;

	case IPPROTO_UDP :
		tcp = fin->fin_dp;

		is->is_sport = htons(fin->fin_data[0]);
		is->is_dport = htons(fin->fin_data[1]);
		if ((flags & (SI_W_DPORT|SI_W_SPORT)) == 0) {
			hv += tcp->th_dport;
			hv += tcp->th_sport;
		}
		break;

	default :
		break;
	}
	hv = DOUBLE_HASH(hv);
	is->is_hv = hv;
	is->is_rule = fr;
	is->is_flags = flags & IS_INHERITED;

	/*
	 * Look for identical state.
	 */
	for (is = ipf_state_table[is->is_hv % ipf_state_size]; is != NULL;
	     is = is->is_hnext) {
		if (ipf_state_match(&ips, is) == 1)
			break;
	}
	if (is != NULL) {
		ATOMIC_INCL(ipf_state_stats.iss_add_dup);
		return 3;
	}

	if (ipf_state_stats.iss_bucketlen[hv] >= ipf_state_maxbucket) {
		ATOMIC_INCL(ipf_state_stats.iss_bucket_full);
		return 4;
	}
	KMALLOC(is, ipstate_t *);
	if (is == NULL) {
		ATOMIC_INCL(ipf_state_stats.iss_nomem);
		return 5;
	}
	bcopy((char *)&ips, (char *)is, sizeof(*is));
	/*
	 * Do not do the modulous here, it is done in ipf_state_insert().
	 */
	if (fr != NULL) {
		ipftq_t *tq;

		(void) strncpy(is->is_group, fr->fr_group, FR_GROUPLEN);
		if (fr->fr_age[0] != 0) {
			tq = ipf_addtimeoutqueue(&ipf_state_usertq,
						 fr->fr_age[0]);
			is->is_tqehead[0] = tq;
			is->is_sti.tqe_flags |= TQE_RULEBASED;
		}
		if (fr->fr_age[1] != 0) {
			tq = ipf_addtimeoutqueue(&ipf_state_usertq,
						 fr->fr_age[1]);
			is->is_tqehead[1] = tq;
			is->is_sti.tqe_flags |= TQE_RULEBASED;
		}

		is->is_tag = fr->fr_logtag;

		/*
		 * The name '-' is special for network interfaces and causes
		 * a NULL name to be present, always, allowing packets to
		 * match it, regardless of their interface.
		 */
		if ((fin->fin_ifp == NULL) ||
		    (fr->fr_ifnames[out << 1][0] == '-' &&
		     fr->fr_ifnames[out << 1][1] == '\0')) {
			is->is_ifp[out << 1] = fr->fr_ifas[0];
			strncpy(is->is_ifname[out << 1], fr->fr_ifnames[0],
				sizeof(fr->fr_ifnames[0]));
		} else {
			is->is_ifp[out << 1] = fin->fin_ifp;
			COPYIFNAME(fin->fin_ifp, is->is_ifname[out << 1]);
		}

		is->is_ifp[(out << 1) + 1] = fr->fr_ifas[1];
		strncpy(is->is_ifname[(out << 1) + 1], fr->fr_ifnames[1],
			sizeof(fr->fr_ifnames[1]));

		is->is_ifp[(1 - out) << 1] = fr->fr_ifas[2];
		strncpy(is->is_ifname[((1 - out) << 1)], fr->fr_ifnames[2],
			sizeof(fr->fr_ifnames[2]));

		is->is_ifp[((1 - out) << 1) + 1] = fr->fr_ifas[3];
		strncpy(is->is_ifname[((1 - out) << 1) + 1], fr->fr_ifnames[3],
			sizeof(fr->fr_ifnames[3]));
	} else {
		if (fin->fin_ifp != NULL) {
			is->is_ifp[out << 1] = fin->fin_ifp;
			COPYIFNAME(fin->fin_ifp, is->is_ifname[out << 1]);
		}
	}

	/*
	 * It may seem strange to set is_ref to 2, but ipf_check() will call
	 * ipf_state_deref() after calling ipf_state_add() and the idea is to
	 * have it exist at the end of ipf_check() with is_ref == 1.
	 */
	is->is_ref = 2;
	is->is_pkts[0] = 0, is->is_bytes[0] = 0;
	is->is_pkts[1] = 0, is->is_bytes[1] = 0;
	is->is_pkts[2] = 0, is->is_bytes[2] = 0;
	is->is_pkts[3] = 0, is->is_bytes[3] = 0;
	if ((fin->fin_flx & FI_IGNORE) == 0) {
		is->is_pkts[out] = 1;
		is->is_bytes[out] = fin->fin_plen;
		is->is_flx[out][0] = fin->fin_flx & FI_CMP;
		is->is_flx[out][0] &= ~FI_OOW;
	}

	if (pass & FR_STSTRICT)
		is->is_flags |= IS_STRICT;

	if (pass & FR_STATESYNC)
		is->is_flags |= IS_STATESYNC;

	if (flags & (SI_WILDP|SI_WILDA)) {
		ATOMIC_INCL(ipf_state_stats.iss_wild);
	}
	is->is_rulen = fin->fin_rule;


	if (pass & FR_LOGFIRST)
		is->is_pass &= ~(FR_LOGFIRST|FR_LOG);

	READ_ENTER(&ipf_state);

	ipf_state_insert(is, fin->fin_rev);

	if (fin->fin_p == IPPROTO_TCP) {
		/*
		* If we're creating state for a starting connection, start the
		* timer on it as we'll never see an error if it fails to
		* connect.
		*/
		(void) ipf_tcp_age(&is->is_sti, fin, ipf_state_tcptq,
				   is->is_flags, 2);
		MUTEX_EXIT(&is->is_lock);
#ifdef	IPFILTER_SCAN
		if ((is->is_flags & SI_CLONE) == 0)
			(void) ipf_scan_attachis(is);
#endif
	} else {
		MUTEX_EXIT(&is->is_lock);
	}
#ifdef	IPFILTER_SYNC
	if ((is->is_flags & IS_STATESYNC) && ((is->is_flags & SI_CLONE) == 0))
		is->is_sync = ipf_sync_new(SMC_STATE, fin, is);
#endif
	if (ipf_state_logging)
		ipf_state_log(is, ISL_NEW);

	RWLOCK_EXIT(&ipf_state);
	*stsave = is;
	fin->fin_state = is;
	fin->fin_rev = IP6_NEQ(&is->is_dst, &fin->fin_daddr);
	fin->fin_flx |= FI_STATE;
	if (fin->fin_flx & FI_FRAG)
		(void) ipf_frag_new(fin, pass);
	fdp = &fr->fr_tifs[0];
	if (fdp->fd_type == FRD_POOL)
		fdp->fd_ptr = ipf_lookup_res_name(IPLT_DSTLIST, IPL_LOGIPF,
						  fdp->fd_name, NULL);
	fdp = &fr->fr_tifs[1];
	if (fdp->fd_type == FRD_POOL)
		fdp->fd_ptr = ipf_lookup_res_name(IPLT_DSTLIST, IPL_LOGIPF,
						  fdp->fd_name, NULL);
	fdp = &fr->fr_dif;
	if (fdp->fd_type == FRD_POOL)
		fdp->fd_ptr = ipf_lookup_res_name(IPLT_DSTLIST, IPL_LOGIPF,
						  fdp->fd_name, NULL);

	ATOMIC_INCL(ipf_state_stats.iss_proto[is->is_p]);
	ATOMIC_INC32(ipf_state_stats.iss_active_proto[is->is_p]);

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_tcpoptions                                              */
/* Returns:     int - 1 == packet matches state entry, 0 == it does not,    */
/*                   -1 == packet has bad TCP options data                  */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              tcp(I) - pointer to TCP packet header                       */
/*              td(I)  - pointer to TCP data held as part of the state      */
/*                                                                          */
/* Look after the TCP header for any options and deal with those that are   */
/* present.  Record details about those that we recogise.                   */
/* ------------------------------------------------------------------------ */
static int
ipf_tcpoptions(fin, tcp, td)
	fr_info_t *fin;
	tcphdr_t *tcp;
	tcpdata_t *td;
{
	int off, mlen, ol, i, len, retval;
	char buf[64], *s, opt;
	mb_t *m = NULL;

	len = (TCP_OFF(tcp) << 2);
	if (fin->fin_dlen < len) {
		ATOMIC_INCL(ipf_state_stats.iss_tcp_toosmall);
		return 0;
	}
	len -= sizeof(*tcp);

	off = fin->fin_plen - fin->fin_dlen + sizeof(*tcp) + fin->fin_ipoff;

	m = fin->fin_m;
	mlen = MSGDSIZE(m) - off;
	if (len > mlen) {
		len = mlen;
		retval = 0;
	} else {
		retval = 1;
	}

	COPYDATA(m, off, len, buf);

	for (s = buf; len > 0; ) {
		opt = *s;
		if (opt == TCPOPT_EOL)
			break;
		else if (opt == TCPOPT_NOP)
			ol = 1;
		else {
			if (len < 2)
				break;
			ol = (int)*(s + 1);
			if (ol < 2 || ol > len)
				break;

			/*
			 * Extract the TCP options we are interested in out of
			 * the header and store them in the the tcpdata struct.
			 */
			switch (opt)
			{
			case TCPOPT_WINDOW :
				if (ol == TCPOLEN_WINDOW) {
					i = (int)*(s + 2);
					if (i > TCP_WSCALE_MAX)
						i = TCP_WSCALE_MAX;
					else if (i < 0)
						i = 0;
					td->td_winscale = i;
					td->td_winflags |= TCP_WSCALE_SEEN|
							   TCP_WSCALE_FIRST;
				} else
					retval = -1;
				break;
			case TCPOPT_MAXSEG :
				/*
				 * So, if we wanted to set the TCP MAXSEG,
				 * it should be done here...
				 */
				if (ol == TCPOLEN_MAXSEG) {
					i = (int)*(s + 2);
					i <<= 8;
					i += (int)*(s + 3);
					td->td_maxseg = i;
				} else
					retval = -1;
				break;
			case TCPOPT_SACK_PERMITTED :
				if (ol == TCPOLEN_SACK_PERMITTED)
					td->td_winflags |= TCP_SACK_PERMIT;
				else
					retval = -1;
				break;
			}
		}
		len -= ol;
		s += ol;
	}
	if (retval == -1) {
		ATOMIC_INCL(ipf_state_stats.iss_tcp_badopt);
	}
	return retval;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_tcp                                               */
/* Returns:     int - 1 == packet matches state entry, 0 == it does not     */
/* Parameters:  fin(I)   - pointer to packet information                    */
/*              tcp(I)   - pointer to TCP packet header                     */
/*              is(I)  - pointer to master state structure                  */
/*                                                                          */
/* Check to see if a packet with TCP headers fits within the TCP window.    */
/* Change timeout depending on whether new packet is a SYN-ACK returning    */
/* for a SYN or a RST or FIN which indicate time to close up shop.          */
/* ------------------------------------------------------------------------ */
static int
ipf_state_tcp(fin, tcp, is)
	fr_info_t *fin;
	tcphdr_t *tcp;
	ipstate_t *is;
{
	tcpdata_t  *fdata, *tdata;
	int source, ret, flags;

	source = !fin->fin_rev;
	if (((is->is_flags & IS_TCPFSM) != 0) && (source == 1) &&
	    (ntohs(is->is_sport) != fin->fin_data[0]))
		source = 0;
	fdata = &is->is_tcp.ts_data[!source];
	tdata = &is->is_tcp.ts_data[source];

	MUTEX_ENTER(&is->is_lock);

	/*
	 * If a SYN packet is received for a connection that is on the way out
	 * but hasn't yet departed then advance this session along the way.
	 */
	if ((tcp->th_flags & TH_OPENING) == TH_SYN) {
		if ((is->is_state[0] > IPF_TCPS_ESTABLISHED) &&
		    (is->is_state[1] > IPF_TCPS_ESTABLISHED)) {
			is->is_state[!source] = IPF_TCPS_CLOSED;
			ipf_movequeue(&is->is_sti, is->is_sti.tqe_ifq,
				      &ipf_state_deletetq);
			MUTEX_EXIT(&is->is_lock);
			ATOMIC_INCL(ipf_state_stats.iss_tcp_closing);
			return 0;
		}
	}

	ret = ipf_tcpinwindow(fin, fdata, tdata, tcp, is->is_flags);
	if (ret > 0) {
#ifdef	IPFILTER_SCAN
		if (is->is_flags & (IS_SC_CLIENT|IS_SC_SERVER)) {
			ipf_scan_packet(fin, is);
			if (FR_ISBLOCK(is->is_pass)) {
				MUTEX_EXIT(&is->is_lock);
				ATOMIC_INCL(ipf_state_stats.iss_scan_block);
				return 1;
			}
		}
#endif

		/*
		 * Nearing end of connection, start timeout.
		 */
		ret = ipf_tcp_age(&is->is_sti, fin, ipf_state_tcptq,
				  is->is_flags, ret);
		if (ret == 0) {
			MUTEX_EXIT(&is->is_lock);
			ATOMIC_INCL(ipf_state_stats.iss_tcp_fsm);
			return 0;
		}

		if (ipf_state_logging > 4)
			ipf_state_log(is, ISL_STATECHANGE);

		/*
		 * set s0's as appropriate.  Use syn-ack packet as it
		 * contains both pieces of required information.
		 */
		/*
		 * Window scale option is only present in SYN/SYN-ACK packet.
		 * Compare with ~TH_FIN to mask out T/TCP setups.
		 */
		flags = tcp->th_flags & ~(TH_FIN|TH_ECNALL);
		if (flags == (TH_SYN|TH_ACK)) {
			is->is_s0[source] = ntohl(tcp->th_ack);
			is->is_s0[!source] = ntohl(tcp->th_seq) + 1;
			if ((TCP_OFF(tcp) > (sizeof(tcphdr_t) >> 2))) {
				if (ipf_tcpoptions(fin, tcp, fdata) == -1)
					fin->fin_flx |= FI_BAD;
			}
			if ((fin->fin_out != 0) && (is->is_pass & FR_NEWISN))
				ipf_checknewisn(fin, is);
		} else if (flags == TH_SYN) {
			is->is_s0[source] = ntohl(tcp->th_seq) + 1;
			if ((TCP_OFF(tcp) > (sizeof(tcphdr_t) >> 2))) {
				if (ipf_tcpoptions(fin, tcp, fdata) == -1)
					fin->fin_flx |= FI_BAD;
			}

			if ((fin->fin_out != 0) && (is->is_pass & FR_NEWISN))
				ipf_checknewisn(fin, is);

		}
		ret = 1;
	} else {
		ATOMIC_INCL(ipf_state_stats.iss_tcp_oow);
		fin->fin_flx |= FI_OOW;
		ret = 0;
	}
	MUTEX_EXIT(&is->is_lock);
	return ret;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_checknewisn                                             */
/* Returns:     Nil                                                         */
/* Parameters:  fin(I)   - pointer to packet information                    */
/*              is(I)  - pointer to master state structure                  */
/*                                                                          */
/* Check to see if this TCP connection is expecting and needs a new         */
/* sequence number for a particular direction of the connection.            */
/*                                                                          */
/* NOTE: This does not actually change the sequence numbers, only gets new  */
/* one ready.                                                               */
/* ------------------------------------------------------------------------ */
static void
ipf_checknewisn(fin, is)
	fr_info_t *fin;
	ipstate_t *is;
{
	u_32_t sumd, old, new;
	tcphdr_t *tcp;
	int i;

	i = fin->fin_rev;
	tcp = fin->fin_dp;

	if (((i == 0) && !(is->is_flags & IS_ISNSYN)) ||
	    ((i == 1) && !(is->is_flags & IS_ISNACK))) {
		old = ntohl(tcp->th_seq);
		new = ipf_newisn(fin);
		is->is_isninc[i] = new - old;
		CALC_SUMD(old, new, sumd);
		is->is_sumd[i] = (sumd & 0xffff) + (sumd >> 16);

		is->is_flags |= ((i == 0) ? IS_ISNSYN : IS_ISNACK);
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_tcpinwindow                                             */
/* Returns:     int - 1 == packet inside TCP "window", 0 == not inside.     */
/* Parameters:  fin(I)   - pointer to packet information                    */
/*              fdata(I) - pointer to tcp state informatio (forward)        */
/*              tdata(I) - pointer to tcp state informatio (reverse)        */
/*              tcp(I)   - pointer to TCP packet header                     */
/*                                                                          */
/* Given a packet has matched addresses and ports, check to see if it is    */
/* within the TCP data window.  In a show of generosity, allow packets that */
/* are within the window space behind the current sequence # as well.       */
/* ------------------------------------------------------------------------ */
int
ipf_tcpinwindow(fin, fdata, tdata, tcp, flags)
	fr_info_t *fin;
	tcpdata_t  *fdata, *tdata;
	tcphdr_t *tcp;
	int flags;
{
	tcp_seq seq, ack, end;
	int ackskew, tcpflags;
	u_32_t win, maxwin;
	int dsize, inseq;

	/*
	 * Find difference between last checked packet and this packet.
	 */
	tcpflags = tcp->th_flags;
	seq = ntohl(tcp->th_seq);
	ack = ntohl(tcp->th_ack);
	if (tcpflags & TH_SYN)
		win = ntohs(tcp->th_win);
	else
		win = ntohs(tcp->th_win) << fdata->td_winscale;

	/*
	 * A window of 0 produces undesirable behaviour from this function.
	 */
	if (win == 0)
		win = 1;

	dsize = fin->fin_dlen - (TCP_OFF(tcp) << 2) +
	        ((tcpflags & TH_SYN) ? 1 : 0) + ((tcpflags & TH_FIN) ? 1 : 0);

	/*
	 * if window scaling is present, the scaling is only allowed
	 * for windows not in the first SYN packet. In that packet the
	 * window is 65535 to specify the largest window possible
	 * for receivers not implementing the window scale option.
	 * Currently, we do not assume TTCP here. That means that
	 * if we see a second packet from a host (after the initial
	 * SYN), we can assume that the receiver of the SYN did
	 * already send back the SYN/ACK (and thus that we know if
	 * the receiver also does window scaling)
	 */
	if (!(tcpflags & TH_SYN) && (fdata->td_winflags & TCP_WSCALE_FIRST)) {
		fdata->td_winflags &= ~TCP_WSCALE_FIRST;
		fdata->td_maxwin = win;
	}

	end = seq + dsize;

	if ((fdata->td_end == 0) &&
	    (!(flags & IS_TCPFSM) ||
	     ((tcpflags & TH_OPENING) == TH_OPENING))) {
		/*
		 * Must be a (outgoing) SYN-ACK in reply to a SYN.
		 */
		fdata->td_end = end - 1;
		fdata->td_maxwin = 1;
		fdata->td_maxend = end + win;
	}

	if (!(tcpflags & TH_ACK)) {  /* Pretend an ack was sent */
		ack = tdata->td_end;
	} else if (((tcpflags & (TH_ACK|TH_RST)) == (TH_ACK|TH_RST)) &&
		   (ack == 0)) {
		/* gross hack to get around certain broken tcp stacks */
		ack = tdata->td_end;
	}

	maxwin = tdata->td_maxwin;
	ackskew = tdata->td_end - ack;

	/*
	 * Strict sequencing only allows in-order delivery.
	 */
	if ((flags & IS_STRICT) != 0) {
		if (seq != fdata->td_end) {
			ATOMIC_INCL(ipf_state_stats.iss_tcp_strict);
			return 0;
		}
	}

#define	SEQ_GE(a,b)	((int)((a) - (b)) >= 0)
#define	SEQ_GT(a,b)	((int)((a) - (b)) > 0)
	inseq = 0;
	if ((SEQ_GE(fdata->td_maxend, end)) &&
	    (SEQ_GE(seq, fdata->td_end - maxwin)) &&
/* XXX what about big packets */
#define MAXACKWINDOW 66000
	    (-ackskew <= (MAXACKWINDOW)) &&
	    ( ackskew <= (MAXACKWINDOW << fdata->td_winscale))) {
		inseq = 1;
	/*
	 * Microsoft Windows will send the next packet to the right of the
	 * window if SACK is in use.
	 */
	} else if ((seq == fdata->td_maxend) && (ackskew == 0) &&
	    (fdata->td_winflags & TCP_SACK_PERMIT) &&
	    (tdata->td_winflags & TCP_SACK_PERMIT)) {
		ATOMIC_INCL(ipf_state_stats.iss_winsack);
		inseq = 1;
	/*
	 * Sometimes a TCP RST will be generated with only the ACK field
	 * set to non-zero.
	 */
	} else if ((seq == 0) && (tcpflags == (TH_RST|TH_ACK)) &&
		   (ackskew >= -1) && (ackskew <= 1)) {
		inseq = 1;
	} else if (!(flags & IS_TCPFSM)) {
		int i;

		i = (fin->fin_rev << 1) + fin->fin_out;

#if 0
		if (is_pkts[i]0 == 0) {
			/*
			 * Picking up a connection in the middle, the "next"
			 * packet seen from a direction that is new should be
			 * accepted, even if it appears out of sequence.
			 */
			inseq = 1;
		} else
#endif
		if (!(fdata->td_winflags &
			    (TCP_WSCALE_SEEN|TCP_WSCALE_FIRST))) {
			/*
			 * No TCPFSM and no window scaling, so make some
			 * extra guesses.
			 */
			if ((seq == fdata->td_maxend) && (ackskew == 0))
				inseq = 1;
			else if (SEQ_GE(seq + maxwin, fdata->td_end - maxwin))
				inseq = 1;
		}
	}

	/* TRACE(inseq, fdata, tdata, seq, end, ack, ackskew, win, maxwin) */

	if (inseq) {
		/* if ackskew < 0 then this should be due to fragmented
		 * packets. There is no way to know the length of the
		 * total packet in advance.
		 * We do know the total length from the fragment cache though.
		 * Note however that there might be more sessions with
		 * exactly the same source and destination parameters in the
		 * state cache (and source and destination is the only stuff
		 * that is saved in the fragment cache). Note further that
		 * some TCP connections in the state cache are hashed with
		 * sport and dport as well which makes it not worthwhile to
		 * look for them.
		 * Thus, when ackskew is negative but still seems to belong
		 * to this session, we bump up the destinations end value.
		 */
		if (ackskew < 0)
			tdata->td_end = ack;

		/* update max window seen */
		if (fdata->td_maxwin < win)
			fdata->td_maxwin = win;
		if (SEQ_GT(end, fdata->td_end))
			fdata->td_end = end;
		if (SEQ_GE(ack + win, tdata->td_maxend))
			tdata->td_maxend = ack + win;
		return 1;
	}
	ATOMIC_INCL(ipf_state_stats.iss_oow);
	fin->fin_flx |= FI_OOW;
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_clone                                             */
/* Returns:     ipstate_t* - NULL == cloning failed,                        */
/*                           else pointer to new state structure            */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              tcp(I) - pointer to TCP/UDP header                          */
/*              is(I)  - pointer to master state structure                  */
/*                                                                          */
/* Create a "duplcate" state table entry from the master.                   */
/* ------------------------------------------------------------------------ */
static ipstate_t *
ipf_state_clone(fin, tcp, is)
	fr_info_t *fin;
	tcphdr_t *tcp;
	ipstate_t *is;
{
	ipstate_t *clone;
	u_32_t send;

	if (ipf_state_stats.iss_active == ipf_state_max) {
		ATOMIC_INCL(ipf_state_stats.iss_max);
		ipf_state_doflush = 1;
		return NULL;
	}
	KMALLOC(clone, ipstate_t *);
	if (clone == NULL) {
		ATOMIC_INCL(ipf_state_stats.iss_clone_nomem);
		return NULL;
	}
	bcopy((char *)is, (char *)clone, sizeof(*clone));

	MUTEX_NUKE(&clone->is_lock);

	clone->is_die = ONE_DAY + ipf_ticks;
	clone->is_state[0] = 0;
	clone->is_state[1] = 0;
	send = ntohl(tcp->th_seq) + fin->fin_dlen - (TCP_OFF(tcp) << 2) +
		((tcp->th_flags & TH_SYN) ? 1 : 0) +
		((tcp->th_flags & TH_FIN) ? 1 : 0);

	if (fin->fin_rev == 1) {
		clone->is_dend = send;
		clone->is_maxdend = send;
		clone->is_send = 0;
		clone->is_maxswin = 1;
		clone->is_maxdwin = ntohs(tcp->th_win);
		if (clone->is_maxdwin == 0)
			clone->is_maxdwin = 1;
	} else {
		clone->is_send = send;
		clone->is_maxsend = send;
		clone->is_dend = 0;
		clone->is_maxdwin = 1;
		clone->is_maxswin = ntohs(tcp->th_win);
		if (clone->is_maxswin == 0)
			clone->is_maxswin = 1;
	}

	clone->is_flags &= ~SI_CLONE;
	clone->is_flags |= SI_CLONED;
	ipf_state_insert(clone, fin->fin_rev);
	clone->is_ref = 2;
	if (clone->is_p == IPPROTO_TCP) {
		(void) ipf_tcp_age(&clone->is_sti, fin, ipf_state_tcptq,
				  clone->is_flags, 2);
	}
	MUTEX_EXIT(&clone->is_lock);
#ifdef	IPFILTER_SCAN
	(void) ipf_scan_attachis(is);
#endif
#ifdef	IPFILTER_SYNC
	if (is->is_flags & IS_STATESYNC)
		clone->is_sync = ipf_sync_new(SMC_STATE, fin, clone);
#endif
	ATOMIC_INCL(ipf_state_stats.iss_cloned);
	return clone;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_matchsrcdst                                             */
/* Returns:     Nil                                                         */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              is(I)  - pointer to state structure                         */
/*              src(I) - pointer to source address                          */
/*              dst(I) - pointer to destination address                     */
/*              tcp(I) - pointer to TCP/UDP header                          */
/*                                                                          */
/* Match a state table entry against an IP packet.  The logic below is that */
/* ret gets set to one if the match succeeds, else remains 0.  If it is     */
/* still 0 after the test. no match.                                        */
/* ------------------------------------------------------------------------ */
static ipstate_t *
ipf_matchsrcdst(fin, is, src, dst, tcp, cmask)
	fr_info_t *fin;
	ipstate_t *is;
	i6addr_t *src, *dst;
	tcphdr_t *tcp;
	u_32_t cmask;
{
	int ret = 0, rev, out, flags, flx = 0, idx;
	u_short sp, dp;
	u_32_t cflx;
	void *ifp;

	rev = IP6_NEQ(&is->is_dst, dst);
	ifp = fin->fin_ifp;
	out = fin->fin_out;
	flags = is->is_flags;
	sp = 0;
	dp = 0;

	if (tcp != NULL) {
		sp = htons(fin->fin_sport);
		dp = ntohs(fin->fin_dport);
	}
	if (!rev) {
		if (tcp != NULL) {
			if (!(flags & SI_W_SPORT) && (sp != is->is_sport))
				rev = 1;
			else if (!(flags & SI_W_DPORT) && (dp != is->is_dport))
				rev = 1;
		}
	}

	idx = (out << 1) + rev;

	/*
	 * If the interface for this 'direction' is set, make sure it matches.
	 * An interface name that is not set matches any, as does a name of *.
	 */
	if ((is->is_ifp[idx] == ifp) || (is->is_ifp[idx] == NULL &&
	    (*is->is_ifname[idx] == '\0' || *is->is_ifname[idx] == '-' ||
	     *is->is_ifname[idx] == '*')))
		ret = 1;

	if (ret == 0) {
		ATOMIC_INCL(ipf_state_stats.iss_lookup_badifp);
		/* TRACE is, out, rev, idx */
		return NULL;
	}
	ret = 0;

	/*
	 * Match addresses and ports.
	 */
	if (rev == 0) {
		if ((IP6_EQ(&is->is_dst, dst) || (flags & SI_W_DADDR)) &&
		    (IP6_EQ(&is->is_src, src) || (flags & SI_W_SADDR))) {
			if (tcp) {
				if ((sp == is->is_sport || flags & SI_W_SPORT)&&
				    (dp == is->is_dport || flags & SI_W_DPORT))
					ret = 1;
			} else {
				ret = 1;
			}
		}
	} else {
		if ((IP6_EQ(&is->is_dst, src) || (flags & SI_W_DADDR)) &&
		    (IP6_EQ(&is->is_src, dst) || (flags & SI_W_SADDR))) {
			if (tcp) {
				if ((dp == is->is_sport || flags & SI_W_SPORT)&&
				    (sp == is->is_dport || flags & SI_W_DPORT))
					ret = 1;
			} else {
				ret = 1;
			}
		}
	}

	if (ret == 0) {
		ATOMIC_INCL(ipf_state_stats.iss_lookup_badport);
		/* TRACE rev, is, sp, dp, src, dst */
		return NULL;
	}

	/*
	 * Whether or not this should be here, is questionable, but the aim
	 * is to get this out of the main line.
	 */
	if (tcp == NULL)
		flags = is->is_flags & ~(SI_WILDP|SI_NEWFR|SI_CLONE|SI_CLONED);

	/*
	 * Only one of the source or destination address can be flaged as a
	 * wildcard.  Fill in the missing address, if set.
	 * For IPv6, if the address being copied in is multicast, then
	 * don't reset the wild flag - multicast causes it to be set in the
	 * first place!
	 */
	if ((flags & (SI_W_SADDR|SI_W_DADDR))) {
		fr_ip_t *fi = &fin->fin_fi;

		if ((flags & SI_W_SADDR) != 0) {
			if (rev == 0) {
#ifdef USE_INET6
				if (is->is_v == 6 &&
				    IN6_IS_ADDR_MULTICAST(&fi->fi_src.in6))
					/*EMPTY*/;
				else
#endif
				{
					is->is_src = fi->fi_src;
					is->is_flags &= ~SI_W_SADDR;
				}
			} else {
#ifdef USE_INET6
				if (is->is_v == 6 &&
				    IN6_IS_ADDR_MULTICAST(&fi->fi_dst.in6))
					/*EMPTY*/;
				else
#endif
				{
					is->is_src = fi->fi_dst;
					is->is_flags &= ~SI_W_SADDR;
				}
			}
		} else if ((flags & SI_W_DADDR) != 0) {
			if (rev == 0) {
#ifdef USE_INET6
				if (is->is_v == 6 &&
				    IN6_IS_ADDR_MULTICAST(&fi->fi_dst.in6))
					/*EMPTY*/;
				else
#endif
				{
					is->is_dst = fi->fi_dst;
					is->is_flags &= ~SI_W_DADDR;
				}
			} else {
#ifdef USE_INET6
				if (is->is_v == 6 &&
				    IN6_IS_ADDR_MULTICAST(&fi->fi_src.in6))
					/*EMPTY*/;
				else
#endif
				{
					is->is_dst = fi->fi_src;
					is->is_flags &= ~SI_W_DADDR;
				}
			}
		}
		if ((is->is_flags & (SI_WILDA|SI_WILDP)) == 0) {
			ATOMIC_DECL(ipf_state_stats.iss_wild);
		}
	}

	flx = fin->fin_flx & cmask;
	cflx = is->is_flx[out][rev];

	/*
	 * Match up any flags set from IP options.
	 */
	if ((cflx && (flx != (cflx & cmask))) ||
	    ((fin->fin_optmsk & is->is_optmsk[rev]) != is->is_opt[rev]) ||
	    ((fin->fin_secmsk & is->is_secmsk) != is->is_sec) ||
	    ((fin->fin_auth & is->is_authmsk) != is->is_auth)) {
		ATOMIC_INCL(ipf_state_stats.iss_miss_mask);
		return NULL;
	}

	if ((fin->fin_flx & FI_IGNORE) != 0) {
		fin->fin_rev = rev;
		return is;
	}

	/*
	 * Only one of the source or destination port can be flagged as a
	 * wildcard.  When filling it in, fill in a copy of the matched entry
	 * if it has the cloning flag set.
	 */
	if ((flags & (SI_W_SPORT|SI_W_DPORT))) {
		if ((flags & SI_CLONE) != 0) {
			ipstate_t *clone;

			clone = ipf_state_clone(fin, tcp, is);
			if (clone == NULL)
				return NULL;
			is = clone;
		} else {
			ATOMIC_DECL(ipf_state_stats.iss_wild);
		}

		if ((flags & SI_W_SPORT) != 0) {
			if (rev == 0) {
				is->is_sport = sp;
				is->is_send = ntohl(tcp->th_seq);
			} else {
				is->is_sport = dp;
				is->is_send = ntohl(tcp->th_ack);
			}
			is->is_maxsend = is->is_send + 1;
		} else if ((flags & SI_W_DPORT) != 0) {
			if (rev == 0) {
				is->is_dport = dp;
				is->is_dend = ntohl(tcp->th_ack);
			} else {
				is->is_dport = sp;
				is->is_dend = ntohl(tcp->th_seq);
			}
			is->is_maxdend = is->is_dend + 1;
		}
		is->is_flags &= ~(SI_W_SPORT|SI_W_DPORT);
		if ((flags & SI_CLONED) && ipf_state_logging)
			ipf_state_log(is, ISL_CLONE);
	}

	ret = -1;

	if (is->is_flx[out][rev] == 0) {
		is->is_flx[out][rev] = flx;
		is->is_opt[rev] = fin->fin_optmsk;
		if (is->is_v == 6)
			is->is_opt[rev] &= ~0x8;
	}

	/*
	 * Check if the interface name for this "direction" is set and if not,
	 * fill it in.
	 */
	if (is->is_ifp[idx] == NULL &&
	    (*is->is_ifname[idx] == '\0' || *is->is_ifname[idx] == '*')) {
		is->is_ifp[idx] = ifp;
		COPYIFNAME(ifp, is->is_ifname[idx]);
	}
	fin->fin_rev = rev;
	return is;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_checkicmpmatchingstate                                  */
/* Returns:     Nil                                                         */
/* Parameters:  fin(I) - pointer to packet information                      */
/*                                                                          */
/* If we've got an ICMP error message, using the information stored in the  */
/* ICMP packet, look for a matching state table entry.                      */
/*                                                                          */
/* If we return NULL then no lock on ipf_state is held.                     */
/* If we return non-null then a read-lock on ipf_state is held.             */
/* ------------------------------------------------------------------------ */
static ipstate_t *
ipf_checkicmpmatchingstate(fin)
	fr_info_t *fin;
{
	ipstate_t *is, **isp;
	u_short sport, dport;
	i6addr_t dst, src;
	struct icmp *ic;
	u_short savelen;
	icmphdr_t *icmp;
	fr_info_t ofin;
	tcphdr_t *tcp;
	int type, len;
	u_char	pr;
	ip_t *oip;
	u_int hv;

	/*
	 * Does it at least have the return (basic) IP header ?
	 * Is it an actual recognised ICMP error type?
	 * Only a basic IP header (no options) should be with
	 * an ICMP error header.
	 */
	if ((fin->fin_v != 4) || (fin->fin_hlen != sizeof(ip_t)) ||
	    (fin->fin_plen < ICMPERR_MINPKTLEN) ||
	    !(fin->fin_flx & FI_ICMPERR)) {
		ATOMIC_INCL(ipf_state_stats.iss_icmp_bad);
		return NULL;
	}
	ic = fin->fin_dp;
	type = ic->icmp_type;

	oip = (ip_t *)((char *)ic + ICMPERR_ICMPHLEN);
	/*
	 * Check if the at least the old IP header (with options) and
	 * 8 bytes of payload is present.
	 */
	if (fin->fin_plen < ICMPERR_MAXPKTLEN + ((IP_HL(oip) - 5) << 2)) {
		ATOMIC_INCL(ipf_state_stats.iss_icmp_short);
		return NULL;
	}

	/*
	 * Sanity Checks.
	 */
	len = fin->fin_dlen - ICMPERR_ICMPHLEN;
	if ((len <= 0) || ((IP_HL(oip) << 2) > len)) {
		ATOMIC_INCL(ipf_state_stats.iss_icmp_short);
		return NULL;
	}

	/*
	 * Is the buffer big enough for all of it ?  It's the size of the IP
	 * header claimed in the encapsulated part which is of concern.  It
	 * may be too big to be in this buffer but not so big that it's
	 * outside the ICMP packet, leading to TCP deref's causing problems.
	 * This is possible because we don't know how big oip_hl is when we
	 * do the pullup early in ipf_check() and thus can't guarantee it is
	 * all here now.
	 */
#ifdef  _KERNEL
	{
	mb_t *m;

	m = fin->fin_m;
# if defined(MENTAT)
	if ((char *)oip + len > (char *)m->b_wptr) {
		ATOMIC_INCL(ipf_state_stats.iss_icmp_short);
		return NULL;
	}
# else
	if ((char *)oip + len > (char *)fin->fin_ip + m->m_len) {
		ATOMIC_INCL(ipf_state_stats.iss_icmp_short);
		return NULL;
	}
# endif
	}
#endif

	bcopy((char *)fin, (char *)&ofin, sizeof(*fin));

	/*
	 * in the IPv4 case we must zero the i6addr union otherwise
	 * the IP6_EQ and IP6_NEQ macros produce the wrong results because
	 * of the 'junk' in the unused part of the union
	 */
	bzero((char *)&src, sizeof(src));
	bzero((char *)&dst, sizeof(dst));

	/*
	 * we make an fin entry to be able to feed it to
	 * matchsrcdst note that not all fields are encessary
	 * but this is the cleanest way. Note further we fill
	 * in fin_mp such that if someone uses it we'll get
	 * a kernel panic. ipf_matchsrcdst does not use this.
	 *
	 * watch out here, as ip is in host order and oip in network
	 * order. Any change we make must be undone afterwards, like
	 * oip->ip_len.
	 */
	savelen = oip->ip_len;
	oip->ip_len = htons(len);

	ofin.fin_flx = FI_NOCKSUM;
	ofin.fin_v = 4;
	ofin.fin_ip = oip;
	ofin.fin_m = NULL;	/* if dereferenced, panic XXX */
	ofin.fin_mp = NULL;	/* if dereferenced, panic XXX */
	(void) ipf_makefrip(IP_HL(oip) << 2, oip, &ofin);
	ofin.fin_ifp = fin->fin_ifp;
	ofin.fin_out = !fin->fin_out;

	hv = (pr = oip->ip_p);
	src.in4 = oip->ip_src;
	hv += src.in4.s_addr;
	dst.in4 = oip->ip_dst;
	hv += dst.in4.s_addr;

	/*
	 * Reset the short and bad flag here because in ipf_matchsrcdst()
	 * the flags for the current packet (fin_flx) are compared against
	 * those for the existing session.
	 */
	ofin.fin_flx &= ~(FI_BAD|FI_SHORT);

	/*
	 * Put old values of ip_len back as we don't know
	 * if we have to forward the packet or process it again.
	 */
	oip->ip_len = savelen;

	switch (oip->ip_p)
	{
	case IPPROTO_ICMP :
		/*
		 * an ICMP error can only be generated as a result of an
		 * ICMP query, not as the response on an ICMP error
		 *
		 * XXX theoretically ICMP_ECHOREP and the other reply's are
		 * ICMP query's as well, but adding them here seems strange XXX
		 */
		if ((ofin.fin_flx & FI_ICMPERR) != 0) {
			ATOMIC_INCL(ipf_state_stats.iss_icmp_icmperr);
		    	return NULL;
		}

		/*
		 * perform a lookup of the ICMP packet in the state table
		 */
		icmp = (icmphdr_t *)((char *)oip + (IP_HL(oip) << 2));
		hv += icmp->icmp_id;
		hv = DOUBLE_HASH(hv);

		READ_ENTER(&ipf_state);
		for (isp = &ipf_state_table[hv]; ((is = *isp) != NULL); ) {
			isp = &is->is_hnext;
			if ((is->is_p != pr) || (is->is_v != 4))
				continue;
			if (is->is_pass & FR_NOICMPERR)
				continue;

			is = ipf_matchsrcdst(&ofin, is, &src, &dst,
					    NULL, FI_ICMPCMP);
			if ((is != NULL) && !ipf_allowstateicmp(fin, is, &src))
				return is;
		}
		RWLOCK_EXIT(&ipf_state);
		ATOMIC_INCL(ipf_state_stats.iss_icmp_miss);
		return NULL;
	case IPPROTO_TCP :
	case IPPROTO_UDP :
		break;
	default :
		ATOMIC_INCL(ipf_state_stats.iss_icmp_miss);
		return NULL;
	}

	tcp = (tcphdr_t *)((char *)oip + (IP_HL(oip) << 2));
	dport = tcp->th_dport;
	sport = tcp->th_sport;

	hv += dport;
	hv += sport;
	hv = DOUBLE_HASH(hv);

	READ_ENTER(&ipf_state);
	for (isp = &ipf_state_table[hv]; ((is = *isp) != NULL); ) {
		isp = &is->is_hnext;
		/*
		 * Only allow this icmp though if the
		 * encapsulated packet was allowed through the
		 * other way around. Note that the minimal amount
		 * of info present does not allow for checking against
		 * tcp internals such as seq and ack numbers.   Only the
		 * ports are known to be present and can be even if the
		 * short flag is set.
		 */
		if ((is->is_p == pr) && (is->is_v == 4) &&
		    (is = ipf_matchsrcdst(&ofin, is, &src, &dst,
					 tcp, FI_ICMPCMP))) {
			if (ipf_allowstateicmp(fin, is, &src) == 0)
				return is;
		}
	}
	RWLOCK_EXIT(&ipf_state);
	ATOMIC_INCL(ipf_state_stats.iss_icmp_miss);
	return NULL;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_allowstateicmp                                          */
/* Returns:     int - 1 = packet denied, 0 = packet allowed                 */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              is(I)  - pointer to state table entry                       */
/*                                                                          */
/* For an ICMP packet that has so far matched a state table entry, check if */
/* there are any further refinements that might mean we want to block this  */
/* packet.  This code isn't specific to either IPv4 or IPv6.                */
/* ------------------------------------------------------------------------ */
static int
ipf_allowstateicmp(fin, is, src)
	fr_info_t *fin;
	ipstate_t *is;
	i6addr_t *src;
{
	frentry_t *savefr;
	frentry_t *fr;
	u_32_t ipass;
	int backward;
	int oi;
	int i;

	fr = is->is_rule;
	if (fr != NULL && fr->fr_icmpgrp != NULL) {
		savefr = fin->fin_fr;
		fin->fin_fr = *fr->fr_icmpgrp;

		ipass = ipf_scanlist(fin, ipf_pass);
		fin->fin_fr = savefr;
		if (FR_ISBLOCK(ipass)) {
			ATOMIC_INCL(ipf_state_stats.iss_icmp_headblock);
			return 1;
		}
	}

	/*
	 * i  : the index of this packet (the icmp unreachable)
	 * oi : the index of the original packet found in the
	 *      icmp header (i.e. the packet causing this icmp)
	 * backward : original packet was backward compared to
	 *            the state
	 */
	backward = IP6_NEQ(&is->is_src, src);
	fin->fin_rev = !backward;
	i = (!backward << 1) + fin->fin_out;
	oi = (backward << 1) + !fin->fin_out;

	if (is->is_pass & FR_NOICMPERR) {
		ATOMIC_INCL(ipf_state_stats.iss_icmp_banned);
		return 1;
	}
	if (is->is_icmppkts[i] > is->is_pkts[oi]) {
		ATOMIC_INCL(ipf_state_stats.iss_icmp_toomany);
		return 1;
	}

	ATOMIC_INCL(ipf_state_stats.iss_icmp_hits);
	is->is_icmppkts[i]++;

	/*
	 * we deliberately do not touch the timeouts
	 * for the accompanying state table entry.
	 * It remains to be seen if that is correct. XXX
	 */
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_ipsmove                                                 */
/* Returns:     Nil                                                         */
/* Parameters:  is(I) - pointer to state table entry                        */
/*              hv(I) - new hash value for state table entry                */
/* Write Locks: ipf_state                                                   */
/*                                                                          */
/* Move a state entry from one position in the hash table to another.       */
/* ------------------------------------------------------------------------ */
static void
ipf_ipsmove(is, hv)
	ipstate_t *is;
	u_int hv;
{
	ipstate_t **isp;
	u_int hvm;

	hvm = is->is_hv;

	/* TRACE is, is_hv, hvm */

	/*
	 * Remove the hash from the old location...
	 */
	isp = is->is_phnext;
	if (is->is_hnext)
		is->is_hnext->is_phnext = isp;
	*isp = is->is_hnext;
	if (ipf_state_table[hvm] == NULL)
		ipf_state_stats.iss_inuse--;
	ipf_state_stats.iss_bucketlen[hvm]--;

	/*
	 * ...and put the hash in the new one.
	 */
	hvm = DOUBLE_HASH(hv);
	is->is_hv = hvm;

	/* TRACE is, hv, is_hv, hvm */

	isp = &ipf_state_table[hvm];
	if (*isp)
		(*isp)->is_phnext = &is->is_hnext;
	else
		ipf_state_stats.iss_inuse++;
	ipf_state_stats.iss_bucketlen[hvm]++;
	is->is_phnext = isp;
	is->is_hnext = *isp;
	*isp = is;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_lookup                                            */
/* Returns:     ipstate_t* - NULL == no matching state found,               */
/*                           else pointer to state information is returned  */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              tcp(I) - pointer to TCP/UDP header.                         */
/*                                                                          */
/* Search the state table for a matching entry to the packet described by   */
/* the contents of *fin.                                                    */
/*                                                                          */
/* If we return NULL then no lock on ipf_state is held.                     */
/* If we return non-null then a read-lock on ipf_state is held.             */
/* ------------------------------------------------------------------------ */
ipstate_t *
ipf_state_lookup(fin, tcp, ifqp)
	fr_info_t *fin;
	tcphdr_t *tcp;
	ipftq_t **ifqp;
{
	u_int hv, hvm, pr, v, tryagain;
	ipstate_t *is, **isp;
	u_short dport, sport;
	i6addr_t src, dst;
	struct icmp *ic;
	ipftq_t *ifq;
	int oow;

	is = NULL;
	ifq = NULL;
	tcp = fin->fin_dp;
	ic = (struct icmp *)tcp;
	hv = (pr = fin->fin_fi.fi_p);
	src = fin->fin_fi.fi_src;
	dst = fin->fin_fi.fi_dst;
	hv += src.in4.s_addr;
	hv += dst.in4.s_addr;

	v = fin->fin_fi.fi_v;
#ifdef	USE_INET6
	if (v == 6) {
		hv  += fin->fin_fi.fi_src.i6[1];
		hv  += fin->fin_fi.fi_src.i6[2];
		hv  += fin->fin_fi.fi_src.i6[3];

		if ((fin->fin_p == IPPROTO_ICMPV6) &&
		    IN6_IS_ADDR_MULTICAST(&fin->fin_fi.fi_dst.in6)) {
			hv -= dst.in4.s_addr;
		} else {
			hv += fin->fin_fi.fi_dst.i6[1];
			hv += fin->fin_fi.fi_dst.i6[2];
			hv += fin->fin_fi.fi_dst.i6[3];
		}
	}
#endif
	if ((v == 4) &&
	    (fin->fin_flx & (FI_MULTICAST|FI_BROADCAST|FI_MBCAST))) {
		if (fin->fin_out == 0) {
			hv -= src.in4.s_addr;
		} else {
			hv -= dst.in4.s_addr;
		}
	}

	/* TRACE fin_saddr, fin_daddr, hv */

	/*
	 * Search the hash table for matching packet header info.
	 */
	switch (pr)
	{
#ifdef	USE_INET6
	case IPPROTO_ICMPV6 :
		tryagain = 0;
		if (v == 6) {
			if ((ic->icmp_type == ICMP6_ECHO_REQUEST) ||
			    (ic->icmp_type == ICMP6_ECHO_REPLY)) {
				hv += ic->icmp_id;
			}
		}
		READ_ENTER(&ipf_state);
icmp6again:
		hvm = DOUBLE_HASH(hv);
		for (isp = &ipf_state_table[hvm]; ((is = *isp) != NULL); ) {
			isp = &is->is_hnext;
			/*
			 * If a connection is about to be deleted, no packets
			 * are allowed to match it.
			 */
			if (is->is_sti.tqe_ifq == &ipf_state_deletetq)
				continue;

			if ((is->is_p != pr) || (is->is_v != v))
				continue;
			is = ipf_matchsrcdst(fin, is, &src, &dst, NULL, FI_CMP);
			if (is != NULL &&
			    ipf_matchicmpqueryreply(v, &is->is_icmp,
						   ic, fin->fin_rev)) {
				if (fin->fin_rev)
					ifq = &ipf_state_icmpacktq;
				else
					ifq = &ipf_state_icmptq;
				break;
			}
		}

		if (is != NULL) {
			if ((tryagain != 0) && !(is->is_flags & SI_W_DADDR)) {
				hv += fin->fin_fi.fi_src.i6[0];
				hv += fin->fin_fi.fi_src.i6[1];
				hv += fin->fin_fi.fi_src.i6[2];
				hv += fin->fin_fi.fi_src.i6[3];
				ipf_ipsmove(is, hv);
				MUTEX_DOWNGRADE(&ipf_state);
			}
			break;
		}
		RWLOCK_EXIT(&ipf_state);

		/*
		 * No matching icmp state entry. Perhaps this is a
		 * response to another state entry.
		 *
		 * XXX With some ICMP6 packets, the "other" address is already
		 * in the packet, after the ICMP6 header, and this could be
		 * used in place of the multicast address.  However, taking
		 * advantage of this requires some significant code changes
		 * to handle the specific types where that is the case.
		 */
		if ((ipf_state_stats.iss_wild != 0) &&
		    (v == 6) && (tryagain == 0) &&
		    !IN6_IS_ADDR_MULTICAST(&fin->fin_fi.fi_src.in6)) {
			hv -= fin->fin_fi.fi_src.i6[0];
			hv -= fin->fin_fi.fi_src.i6[1];
			hv -= fin->fin_fi.fi_src.i6[2];
			hv -= fin->fin_fi.fi_src.i6[3];
			tryagain = 1;
			WRITE_ENTER(&ipf_state);
			goto icmp6again;
		}

		is = ipf_checkicmp6matchingstate(fin);
		if (is != NULL)
			return is;
		break;
#endif

	case IPPROTO_ICMP :
		if (v == 4) {
			hv += ic->icmp_id;
		}
		hv = DOUBLE_HASH(hv);
		READ_ENTER(&ipf_state);
		for (isp = &ipf_state_table[hv]; ((is = *isp) != NULL); ) {
			isp = &is->is_hnext;
			if ((is->is_p != pr) || (is->is_v != v))
				continue;
			is = ipf_matchsrcdst(fin, is, &src, &dst, NULL, FI_CMP);
			if ((is != NULL) &&
			    (ic->icmp_id == is->is_icmp.ici_id) &&
			    ipf_matchicmpqueryreply(v, &is->is_icmp,
						   ic, fin->fin_rev)) {
				if (fin->fin_rev)
					ifq = &ipf_state_icmpacktq;
				else
					ifq = &ipf_state_icmptq;
				break;
			}
		}
		if (is == NULL) {
			RWLOCK_EXIT(&ipf_state);
		}
		break;

	case IPPROTO_TCP :
	case IPPROTO_UDP :
		ifqp = NULL;
		sport = htons(fin->fin_data[0]);
		hv += sport;
		dport = htons(fin->fin_data[1]);
		hv += dport;
		oow = 0;
		tryagain = 0;
		READ_ENTER(&ipf_state);
retry_tcpudp:
		hvm = DOUBLE_HASH(hv);

		/* TRACE hv, hvm */

		for (isp = &ipf_state_table[hvm]; ((is = *isp) != NULL); ) {
			isp = &is->is_hnext;
			if ((is->is_p != pr) || (is->is_v != v))
				continue;
			fin->fin_flx &= ~FI_OOW;
			is = ipf_matchsrcdst(fin, is, &src, &dst, tcp, FI_CMP);
			if (is != NULL) {
				if (pr == IPPROTO_TCP) {
					if (!ipf_state_tcp(fin, tcp, is)) {
						oow |= fin->fin_flx & FI_OOW;
						continue;
					}
				}
				break;
			}
		}
		if (is != NULL) {
			if (tryagain &&
			    !(is->is_flags & (SI_CLONE|SI_WILDP|SI_WILDA))) {
				hv += dport;
				hv += sport;
				ipf_ipsmove(is, hv);
				MUTEX_DOWNGRADE(&ipf_state);
			}
			break;
		}
		RWLOCK_EXIT(&ipf_state);

		if (ipf_state_stats.iss_wild) {
			if (tryagain == 0) {
				hv -= dport;
				hv -= sport;
			} else if (tryagain == 1) {
				hv = fin->fin_fi.fi_p;
				/*
				 * If we try to pretend this is a reply to a
				 * multicast/broadcast packet then we need to
				 * exclude part of the address from the hash
				 * calculation.
				 */
				if (fin->fin_out == 0) {
					hv += src.in4.s_addr;
				} else {
					hv += dst.in4.s_addr;
				}
				hv += dport;
				hv += sport;
			}
			tryagain++;
			if (tryagain <= 2) {
				WRITE_ENTER(&ipf_state);
				goto retry_tcpudp;
			}
		}
		fin->fin_flx |= oow;
		break;

#if 0
	case IPPROTO_GRE :
		gre = fin->fin_dp;
		if (GRE_REV(gre->gr_flags) == 1) {
			hv += gre->gr_call;
		}
		/* FALLTHROUGH */
#endif
	default :
		ifqp = NULL;
		hvm = DOUBLE_HASH(hv);
		READ_ENTER(&ipf_state);
		for (isp = &ipf_state_table[hvm]; ((is = *isp) != NULL); ) {
			isp = &is->is_hnext;
			if ((is->is_p != pr) || (is->is_v != v))
				continue;
			is = ipf_matchsrcdst(fin, is, &src, &dst, NULL, FI_CMP);
			if (is != NULL) {
				ifq = &ipf_state_iptq;
				break;
			}
		}
		if (is == NULL) {
			RWLOCK_EXIT(&ipf_state);
		}
		break;
	}

	if (is != NULL) {
		if (((is->is_sti.tqe_flags & TQE_RULEBASED) != 0) &&
		    (is->is_tqehead[fin->fin_rev] != NULL))
			ifq = is->is_tqehead[fin->fin_rev];
		if (ifq != NULL && ifqp != NULL)
			*ifqp = ifq;
	} else {
		ATOMIC_INCL(ipf_state_stats.iss_lookup_miss);
	}
	return is;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_check                                             */
/* Returns:     frentry_t* - NULL == search failed,                         */
/*                           else pointer to rule for matching state        */
/* Parameters:  ifp(I)   - pointer to interface                             */
/*              passp(I) - pointer to filtering result flags                */
/*                                                                          */
/* Check if a packet is associated with an entry in the state table.        */
/* ------------------------------------------------------------------------ */
frentry_t *
ipf_state_check(fin, passp)
	fr_info_t *fin;
	u_32_t *passp;
{
	ipftqent_t *tqe;
	ipstate_t *is;
	frentry_t *fr;
	tcphdr_t *tcp;
	ipftq_t *ifq;
	u_int pass;
	int inout;

	if (ipf_state_lock || (ipf_state_list == NULL))
		return NULL;

	if (fin->fin_flx & (FI_SHORT|FI_FRAGBODY|FI_BAD)) {
		ATOMIC_INCL(ipf_state_stats.iss_check_bad);
		return NULL;
	}

	is = fin->fin_state;
	if (is != NULL) {
		READ_ENTER(&ipf_state);
		fr = is->is_rule;
		MUTEX_ENTER(&is->is_lock);
		goto stateheld;
	}

	if ((fin->fin_flx & FI_TCPUDP) ||
	    (fin->fin_fi.fi_p == IPPROTO_ICMP)
#ifdef	USE_INET6
	    || (fin->fin_fi.fi_p == IPPROTO_ICMPV6)
#endif
	    )
		tcp = fin->fin_dp;
	else
		tcp = NULL;

	ifq = NULL;
	/*
	 * Search the hash table for matching packet header info.
	 */
	is = ipf_state_lookup(fin, tcp, &ifq);

	switch (fin->fin_p)
	{
#ifdef	USE_INET6
	case IPPROTO_ICMPV6 :
		if (is != NULL)
			break;
		if (fin->fin_v == 6) {
			is = ipf_checkicmp6matchingstate(fin);
		}
		break;
#endif
	case IPPROTO_ICMP :
		if (is != NULL)
			break;
		/*
		 * No matching icmp state entry. Perhaps this is a
		 * response to another state entry.
		 */
		is = ipf_checkicmpmatchingstate(fin);
		break;

	case IPPROTO_TCP :
		if (is == NULL)
			break;

		if (is->is_pass & FR_NEWISN) {
			if (fin->fin_out == 0)
				ipf_fixinisn(fin, is);
			else if (fin->fin_out == 1)
				ipf_fixoutisn(fin, is);
		}
		break;
	default :
		if (fin->fin_rev)
			ifq = &ipf_state_udpacktq;
		else
			ifq = &ipf_state_udptq;
		break;
	}
	if (is == NULL) {
		ATOMIC_INCL(ipf_state_stats.iss_check_miss);
		return NULL;
	}

	fr = is->is_rule;
	if (fr != NULL) {
		if ((fin->fin_out == 0) && (fr->fr_nattag.ipt_num[0] != 0)) {
			if (fin->fin_nattag == NULL) {
				RWLOCK_EXIT(&ipf_state);
				ATOMIC_INCL(ipf_state_stats.iss_check_notag);
				return NULL;
			}
			if (ipf_matchtag(&fr->fr_nattag, fin->fin_nattag)!=0) {
				RWLOCK_EXIT(&ipf_state);
				ATOMIC_INCL(ipf_state_stats.iss_check_nattag);
				return NULL;
			}
		}
		(void) strncpy(fin->fin_group, fr->fr_group, FR_GROUPLEN);
		fin->fin_icode = fr->fr_icode;
	}

	fin->fin_rule = is->is_rulen;
	fin->fin_fr = is->is_rule;
	fin->fin_state = is;

	/*
	 * If this packet is a fragment and the rule says to track fragments,
	 * then create a new fragment cache entry.
	 */
	if ((fin->fin_flx & FI_FRAG) && FR_ISPASS(is->is_pass))
		(void) ipf_frag_new(fin, is->is_pass);

	/*
	 * For TCP packets, ifq == NULL.  For all others, check if this new
	 * queue is different to the last one it was on and move it if so.
	 */
	tqe = &is->is_sti;
	if ((tqe->tqe_flags & TQE_RULEBASED) != 0)
		ifq = is->is_tqehead[fin->fin_rev];

	MUTEX_ENTER(&is->is_lock);
	is->is_ref++;

	if (ifq != NULL)
		ipf_movequeue(tqe, tqe->tqe_ifq, ifq);

stateheld:
	inout = (fin->fin_rev << 1) + fin->fin_out;
	is->is_pkts[inout]++;
	is->is_bytes[inout] += fin->fin_plen;

	MUTEX_EXIT(&is->is_lock);

	pass = is->is_pass;

#ifdef	IPFILTER_SYNC
	if (is->is_flags & IS_STATESYNC)
		ipf_sync_update(SMC_STATE, fin, is->is_sync);
#endif

	RWLOCK_EXIT(&ipf_state);

	ATOMIC_INCL(ipf_state_stats.iss_hits);

	fin->fin_flx |= FI_STATE;
	if ((pass & FR_LOGFIRST) != 0)
		pass &= ~(FR_LOGFIRST|FR_LOG);
	*passp = pass;
	return fr;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_fixoutisn                                               */
/* Returns:     Nil                                                         */
/* Parameters:  fin(I)   - pointer to packet information                    */
/*              is(I)  - pointer to master state structure                  */
/*                                                                          */
/* Called only for outbound packets, adjusts the sequence number and the    */
/* TCP checksum to match that change.                                       */
/* ------------------------------------------------------------------------ */
static void
ipf_fixoutisn(fin, is)
	fr_info_t *fin;
	ipstate_t *is;
{
	tcphdr_t *tcp;
	int rev;
	u_32_t seq;

	tcp = fin->fin_dp;
	rev = fin->fin_rev;
	if ((is->is_flags & IS_ISNSYN) != 0) {
		if (rev == 0) {
			seq = ntohl(tcp->th_seq);
			seq += is->is_isninc[0];
			tcp->th_seq = htonl(seq);
			ipf_fix_outcksum(fin, &tcp->th_sum, is->is_sumd[0]);
		}
	}
	if ((is->is_flags & IS_ISNACK) != 0) {
		if (rev == 1) {
			seq = ntohl(tcp->th_seq);
			seq += is->is_isninc[1];
			tcp->th_seq = htonl(seq);
			ipf_fix_outcksum(fin, &tcp->th_sum, is->is_sumd[1]);
		}
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_fixinisn                                                */
/* Returns:     Nil                                                         */
/* Parameters:  fin(I)   - pointer to packet information                    */
/*              is(I)  - pointer to master state structure                  */
/*                                                                          */
/* Called only for inbound packets, adjusts the acknowledge number and the  */
/* TCP checksum to match that change.                                       */
/* ------------------------------------------------------------------------ */
static void
ipf_fixinisn(fin, is)
	fr_info_t *fin;
	ipstate_t *is;
{
	tcphdr_t *tcp;
	int rev;
	u_32_t ack;

	tcp = fin->fin_dp;
	rev = fin->fin_rev;
	if ((is->is_flags & IS_ISNSYN) != 0) {
		if (rev == 1) {
			ack = ntohl(tcp->th_ack);
			ack -= is->is_isninc[0];
			tcp->th_ack = htonl(ack);
			ipf_fix_incksum(fin, &tcp->th_sum, is->is_sumd[0]);
		}
	}
	if ((is->is_flags & IS_ISNACK) != 0) {
		if (rev == 0) {
			ack = ntohl(tcp->th_ack);
			ack -= is->is_isninc[1];
			tcp->th_ack = htonl(ack);
			ipf_fix_incksum(fin, &tcp->th_sum, is->is_sumd[1]);
		}
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_sync                                              */
/* Returns:     Nil                                                         */
/* Parameters:  ifp(I) - pointer to interface                               */
/*                                                                          */
/* Walk through all state entries and if an interface pointer match is      */
/* found then look it up again, based on its name in case the pointer has   */
/* changed since last time.                                                 */
/*                                                                          */
/* If ifp is passed in as being non-null then we are only doing updates for */
/* existing, matching, uses of it.                                          */
/* ------------------------------------------------------------------------ */
void
ipf_state_sync(ifp)
	void *ifp;
{
	ipstate_t *is;
	int i;

	if (ipf_running <= 0)
		return;

	WRITE_ENTER(&ipf_state);

	if (ipf_running <= 0) {
		RWLOCK_EXIT(&ipf_state);
		return;
	}

	for (is = ipf_state_list; is; is = is->is_next) {
		/*
		 * Look up all the interface names in the state entry.
		 */
		for (i = 0; i < 4; i++) {
			if (ifp == NULL || ifp == is->is_ifp[i])
				is->is_ifp[i] = ipf_resolvenic(is->is_ifname[i],
							      is->is_v);
		}
	}
	RWLOCK_EXIT(&ipf_state);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_del                                               */
/* Returns:     int    - 0 = deleted, else refernce count on active struct  */
/* Parameters:  is(I)  - pointer to state structure to delete               */
/*              why(I) - if not 0, log reason why it was deleted            */
/* Write Locks: ipf_state                                                   */
/*                                                                          */
/* Deletes a state entry from the enumerated list as well as the hash table */
/* and timeout queue lists.  Make adjustments to hash table statistics and  */
/* global counters as required.                                             */
/* ------------------------------------------------------------------------ */
static int
ipf_state_del(is, why)
	ipstate_t *is;
	int why;
{
	int orphan = 1;
	frentry_t *fr;
	frdest_t *fdp;

	/*
	 * Since we want to delete this, remove it from the state table,
	 * where it can be found & used, first.
	 */
	if (is->is_phnext != NULL) {
		*is->is_phnext = is->is_hnext;
		if (is->is_hnext != NULL)
			is->is_hnext->is_phnext = is->is_phnext;
		if (ipf_state_table[is->is_hv] == NULL)
			ipf_state_stats.iss_inuse--;
		ipf_state_stats.iss_bucketlen[is->is_hv]--;

		is->is_phnext = NULL;
		is->is_hnext = NULL;
		orphan = 0;
	}

	if (is->is_me != NULL) {
		*is->is_me = NULL;
		is->is_me = NULL;
	}

	/*
	 * Because ipf_state_stats.iss_wild is a count of entries in the state
	 * table that have wildcard flags set, only decerement it once
	 * and do it here.
	 */
	if (is->is_flags & (SI_WILDP|SI_WILDA)) {
		if (!(is->is_flags & SI_CLONED)) {
			ATOMIC_DECL(ipf_state_stats.iss_wild);
		}
		is->is_flags &= ~(SI_WILDP|SI_WILDA);
	}

	/*
	 * Next, remove it from the timeout queue it is in.
	 */
	if (is->is_sti.tqe_ifq != NULL)
		ipf_deletequeueentry(&is->is_sti);

	if (is->is_me != NULL) {
		*is->is_me = NULL;
		is->is_me = NULL;
	}

	/*
	 * If it is still in use by something else, do not go any further,
	 * but note that at this point it is now an orphan.  How can this
	 * be?  ipf_state_flush() calls ipf_delete() directly because it wants
	 * to empty the table out and if something has a hold on a state
	 * entry (such as ipfstat), it'll do the deref path that'll bring
	 * us back here to do the real delete & free.
	 */
	MUTEX_ENTER(&is->is_lock);
	if (is->is_ref > 1) {
		is->is_ref--;
		MUTEX_EXIT(&is->is_lock);
		if (!orphan)
			ipf_state_stats.iss_orphan++;
		return is->is_ref;
	}
	MUTEX_EXIT(&is->is_lock);

	fr = is->is_rule;
	if (fr != NULL) {
		fdp = &fr->fr_tifs[0];
		if (fdp->fd_type == FRD_POOL)
			ipf_lookup_deref(IPLT_DSTLIST, fdp->fd_ptr);
		fdp = &fr->fr_tifs[1];
		if (fdp->fd_type == FRD_POOL)
			ipf_lookup_deref(IPLT_DSTLIST, fdp->fd_ptr);
		fdp = &fr->fr_dif;
		if (fdp->fd_type == FRD_POOL)
			ipf_lookup_deref(IPLT_DSTLIST, fdp->fd_ptr);
	}

	is->is_ref = 0;

	if (is->is_tqehead[0] != NULL) {
		(void) ipf_deletetimeoutqueue(is->is_tqehead[0]);
	}
	if (is->is_tqehead[1] != NULL) {
		(void) ipf_deletetimeoutqueue(is->is_tqehead[1]);
	}

#ifdef	IPFILTER_SYNC
	if (is->is_sync)
		ipf_sync_del_state(is->is_sync);
#endif
#ifdef	IPFILTER_SCAN
	(void) ipf_scan_detachis(is);
#endif

	/*
	 * Now remove it from the linked list of known states
	 */
	if (is->is_pnext != NULL) {
		*is->is_pnext = is->is_next;

		if (is->is_next != NULL)
			is->is_next->is_pnext = is->is_pnext;

		is->is_pnext = NULL;
		is->is_next = NULL;
	}

	if (ipf_state_logging != 0 && why != 0)
		ipf_state_log(is, why);

	if (is->is_p == IPPROTO_TCP)
		ipf_state_stats.iss_fin++;
	else
		ipf_state_stats.iss_expire++;
	if (orphan)
		ipf_state_stats.iss_orphan--;

	if (is->is_rule != NULL) {
		is->is_rule->fr_statecnt--;
		(void) ipf_derefrule(&is->is_rule);
	}

	ipf_state_stats.iss_active_proto[is->is_p]--;

	MUTEX_DESTROY(&is->is_lock);
	KFREE(is);
	ipf_state_stats.iss_active--;

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_expire                                            */
/* Returns:     Nil                                                         */
/* Parameters:  Nil                                                         */
/*                                                                          */
/* Slowly expire held state for thingslike UDP and ICMP.  The algorithm     */
/* used here is to keep the queue sorted with the oldest things at the top  */
/* and the youngest at the bottom.  So if the top one doesn't need to be    */
/* expired then neither will any under it.                                  */
/* ------------------------------------------------------------------------ */
void
ipf_state_expire()
{
	ipftq_t *ifq, *ifqnext;
	ipftqent_t *tqe, *tqn;
	ipstate_t *is;
	SPL_INT(s);

	SPL_NET(s);
	WRITE_ENTER(&ipf_state);
	for (ifq = ipf_state_tcptq; ifq != NULL; ifq = ifq->ifq_next)
		for (tqn = ifq->ifq_head; ((tqe = tqn) != NULL); ) {
			if (tqe->tqe_die > ipf_ticks)
				break;
			tqn = tqe->tqe_next;
			is = tqe->tqe_parent;
			ipf_state_del(is, ISL_EXPIRE);
		}

	for (ifq = ipf_state_usertq; ifq != NULL; ifq = ifqnext) {
		ifqnext = ifq->ifq_next;

		for (tqn = ifq->ifq_head; ((tqe = tqn) != NULL); ) {
			if (tqe->tqe_die > ipf_ticks)
				break;
			tqn = tqe->tqe_next;
			is = tqe->tqe_parent;
			ipf_state_del(is, ISL_EXPIRE);
		}
	}

	for (ifq = ipf_state_usertq; ifq != NULL; ifq = ifqnext) {
		ifqnext = ifq->ifq_next;

		if (((ifq->ifq_flags & IFQF_DELETE) != 0) &&
		    (ifq->ifq_ref == 0)) {
			ipf_freetimeoutqueue(ifq);
		}
	}

	if (ipf_state_doflush) {
		(void) ipf_state_flush(2, 0);
		ipf_state_doflush = 0;
		ipf_state_wm_last = ipf_ticks;
	}

	RWLOCK_EXIT(&ipf_state);
	SPL_X(s);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_flush                                             */
/* Returns:     int - 0 == success, -1 == failure                           */
/* Parameters:  Nil                                                         */
/* Write Locks: ipf_state                                                   */
/*                                                                          */
/* Flush state tables.  Three actions currently defined:                    */
/* which == 0 : flush all state table entries                               */
/* which == 1 : flush TCP connections which have started to close but are   */
/*	      stuck for some reason.                                        */
/* which == 2 : flush TCP connections which have been idle for a long time, */
/*	      starting at > 4 days idle and working back in successive half-*/
/*	      days to at most 12 hours old.  If this fails to free enough   */
/*            slots then work backwards in half hour slots to 30 minutes.   */
/*            If that too fails, then work backwards in 30 second intervals */
/*            for the last 30 minutes to at worst 30 seconds idle.          */
/* ------------------------------------------------------------------------ */
static int
ipf_state_flush(which, proto)
	int which, proto;
{
	ipftqent_t *tqe, *tqn;
	ipstate_t *is, **isp;
	ipftq_t *ifq;
	int removed;
	SPL_INT(s);

	removed = 0;

	SPL_NET(s);

	switch (which)
	{
	case 0 :
		ATOMIC_INCL(ipf_state_stats.iss_flush_all);
		/*
		 * Style 0 flush removes everything...
		 */
		for (isp = &ipf_state_list; ((is = *isp) != NULL); ) {
			if ((proto != 0) && (is->is_v != proto)) {
				isp = &is->is_next;
				continue;
			}
			if (ipf_state_del(is, ISL_FLUSH) == 0)
				removed++;
			else
				isp = &is->is_next;
		}
		break;

	case 1 :
		ATOMIC_INCL(ipf_state_stats.iss_flush_closing);
		/*
		 * Since we're only interested in things that are closing,
		 * we can start with the appropriate timeout queue.
		 */
		for (ifq = ipf_state_tcptq + IPF_TCPS_CLOSE_WAIT; ifq != NULL;
		     ifq = ifq->ifq_next) {

			for (tqn = ifq->ifq_head; ((tqe = tqn) != NULL); ) {
				tqn = tqe->tqe_next;
				is = tqe->tqe_parent;
				if (is->is_p != IPPROTO_TCP)
					break;
				if (ipf_state_del(is, ISL_FLUSH) == 0)
					removed++;
			}
		}

		/*
		 * Also need to look through the user defined queues.
		 */
		for (ifq = ipf_state_usertq; ifq != NULL; ifq = ifq->ifq_next) {
			for (tqn = ifq->ifq_head; ((tqe = tqn) != NULL); ) {
				tqn = tqe->tqe_next;
				is = tqe->tqe_parent;
				if (is->is_p != IPPROTO_TCP)
					continue;

				if ((is->is_state[0] > IPF_TCPS_ESTABLISHED) &&
				    (is->is_state[1] > IPF_TCPS_ESTABLISHED)) {
					if (ipf_state_del(is, ISL_FLUSH) == 0)
						removed++;
				}
			}
		}
		break;

	case 2 :
		break;

		/*
		 * Args 5-11 correspond to flushing those particular states
		 * for TCP connections.
		 */
	case IPF_TCPS_CLOSE_WAIT :
	case IPF_TCPS_FIN_WAIT_1 :
	case IPF_TCPS_CLOSING :
	case IPF_TCPS_LAST_ACK :
	case IPF_TCPS_FIN_WAIT_2 :
	case IPF_TCPS_TIME_WAIT :
	case IPF_TCPS_CLOSED :
		ATOMIC_INCL(ipf_state_stats.iss_flush_queue);
		tqn = ipf_state_tcptq[which].ifq_head;
		while (tqn != NULL) {
			tqe = tqn;
			tqn = tqe->tqe_next;
			is = tqe->tqe_parent;
			if (ipf_state_del(is, ISL_FLUSH) == 0)
				removed++;
		}
		break;

	default :
		if (which < 30)
			break;

		ATOMIC_INCL(ipf_state_stats.iss_flush_state);
		/*
		 * Take a large arbitrary number to mean the number of seconds
		 * for which which consider to be the maximum value we'll allow
		 * the expiration to be.
		 */
		which = IPF_TTLVAL(which);
		for (isp = &ipf_state_list; ((is = *isp) != NULL); ) {
			if ((proto == 0) || (is->is_v == proto)) {
				if (ipf_ticks - is->is_touched > which) {
					if (ipf_state_del(is, ISL_FLUSH) == 0) {
						removed++;
						continue;
					}
				}
			}
			isp = &is->is_next;
		}
		break;
	}

	if (which != 2) {
		SPL_X(s);
		return removed;
	}

	ATOMIC_INCL(ipf_state_stats.iss_flush_timeout);
	/*
	 * Asked to remove inactive entries because the table is full, try
	 * again, 3 times, if first attempt failed with a different criteria
	 * each time.  The order tried in must be in decreasing age.
	 * Another alternative is to implement random drop and drop N entries
	 * at random until N have been freed up.
	 */
	if (ipf_ticks - ipf_state_wm_last > ipf_state_wm_freq) {
		removed = ipf_queueflush(ipf_state_flush_entry, ipf_state_tcptq,
					 ipf_state_usertq,
					 &ipf_state_stats.iss_active,
					 ipf_state_size, ipf_state_wm_low);
		ipf_state_wm_last = ipf_ticks;
	}

	SPL_X(s);
	return removed;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_flush_entry                                       */
/* Returns:     int - 0 = entry deleted, else not deleted                   */
/* Parameters:  entry(I)  - pointer to state structure to delete            */
/* Write Locks: ipf_state                                                   */
/*                                                                          */
/* This function is a stepping stone between ipf_queueflush() and           */
/* ipf_state_del().  It is used so we can provide a uniform interface via   */
/* the ipf_queueflush() function.                                           */
/* ------------------------------------------------------------------------ */
static int
ipf_state_flush_entry(entry)
	void *entry;
{
	return ipf_state_del(entry, ISL_FLUSH);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_tcp_age                                                 */
/* Returns:     int - 1 == state transition made, 0 == no change (rejected) */
/* Parameters:  tq(I)    - pointer to timeout queue information             */
/*              fin(I)   - pointer to packet information                    */
/*              tqtab(I) - TCP timeout queue table this is in               */
/*              flags(I) - flags from state/NAT entry                       */
/*              ok(I)    - can we advance state                             */
/*                                                                          */
/* Rewritten by Arjan de Vet <Arjan.deVet@adv.iae.nl>, 2000-07-29:          */
/*                                                                          */
/* - (try to) base state transitions on real evidence only,                 */
/*   i.e. packets that are sent and have been received by ipfilter;         */
/*   diagram 18.12 of TCP/IP volume 1 by W. Richard Stevens was used.       */
/*                                                                          */
/* - deal with half-closed connections correctly;                           */
/*                                                                          */
/* - store the state of the source in state[0] such that ipfstat            */
/*   displays the state as source/dest instead of dest/source; the calls    */
/*   to ipf_tcp_age have been changed accordingly.                          */
/*                                                                          */
/* Internal Parameters:                                                     */
/*                                                                          */
/*    state[0] = state of source (host that initiated connection)           */
/*    state[1] = state of dest   (host that accepted the connection)        */
/*                                                                          */
/*    dir == 0 : a packet from source to dest                               */
/*    dir == 1 : a packet from dest to source                               */
/*                                                                          */
/* A typical procession for a connection is as follows:                     */
/*                                                                          */
/* +--------------+-------------------+                                     */
/* | Side '0'     | Side '1'          |                                     */
/* +--------------+-------------------+                                     */
/* | 0 -> 1 (SYN) |                   |                                     */
/* |              | 0 -> 2 (SYN-ACK)  |                                     */
/* | 1 -> 3 (ACK) |                   |                                     */
/* |              | 2 -> 4 (ACK-PUSH) |                                     */
/* | 3 -> 4 (ACK) |                   |                                     */
/* |   ...        |   ...             |                                     */
/* |              | 4 -> 6 (FIN-ACK)  |                                     */
/* | 4 -> 5 (ACK) |                   |                                     */
/* |              | 6 -> 6 (ACK-PUSH) |                                     */
/* | 5 -> 5 (ACK) |                   |                                     */
/* | 5 -> 8 (FIN) |                   |                                     */
/* |              | 6 -> 10 (ACK)     |                                     */
/* +--------------+-------------------+                                     */
/*                                                                          */
/* Locking: it is assumed that the parent of the tqe structure is locked.   */
/* ------------------------------------------------------------------------ */
int
ipf_tcp_age(tqe, fin, tqtab, flags, ok)
	ipftqent_t *tqe;
	fr_info_t *fin;
	ipftq_t *tqtab;
	int flags, ok;
{
	int dlen, ostate, nstate, rval, dir;
	u_char tcpflags;
	tcphdr_t *tcp;

	tcp = fin->fin_dp;

	rval = 0;
	dir = fin->fin_rev;
	tcpflags = tcp->th_flags;
	dlen = fin->fin_dlen - (TCP_OFF(tcp) << 2);

	if (tcpflags & TH_RST) {
		if (!(tcpflags & TH_PUSH) && !dlen)
			nstate = IPF_TCPS_CLOSED;
		else
			nstate = IPF_TCPS_CLOSE_WAIT;
		rval = 1;
	} else {
		ostate = tqe->tqe_state[1 - dir];
		nstate = tqe->tqe_state[dir];

		switch (nstate)
		{
		case IPF_TCPS_LISTEN: /* 0 */
			if ((tcpflags & TH_OPENING) == TH_OPENING) {
				/*
				 * 'dir' received an S and sends SA in
				 * response, LISTEN -> SYN_RECEIVED
				 */
				nstate = IPF_TCPS_SYN_RECEIVED;
				rval = 1;
			} else if ((tcpflags & TH_OPENING) == TH_SYN) {
				/* 'dir' sent S, LISTEN -> SYN_SENT */
				nstate = IPF_TCPS_SYN_SENT;
				rval = 1;
			}
			/*
			 * the next piece of code makes it possible to get
			 * already established connections into the state table
			 * after a restart or reload of the filter rules; this
			 * does not work when a strict 'flags S keep state' is
			 * used for tcp connections of course
			 */
			if (((flags & IS_TCPFSM) == 0) &&
			    ((tcpflags & TH_ACKMASK) == TH_ACK)) {
				/*
				 * we saw an A, guess 'dir' is in ESTABLISHED
				 * mode
				 */
				switch (ostate)
				{
				case IPF_TCPS_LISTEN :
				case IPF_TCPS_SYN_RECEIVED :
					nstate = IPF_TCPS_HALF_ESTAB;
					rval = 1;
					break;
				case IPF_TCPS_HALF_ESTAB :
				case IPF_TCPS_ESTABLISHED :
					nstate = IPF_TCPS_ESTABLISHED;
					rval = 1;
					break;
				default :
					break;
				}
			}
			/*
			 * TODO: besides regular ACK packets we can have other
			 * packets as well; it is yet to be determined how we
			 * should initialize the states in those cases
			 */
			break;

		case IPF_TCPS_SYN_SENT: /* 1 */
			if ((tcpflags & ~(TH_ECN|TH_CWR)) == TH_SYN) {
				/*
				 * A retransmitted SYN packet.  We do not reset
				 * the timeout here to ipf_tcptimeout because a
				 * connection connect timeout does not renew
				 * after every packet that is sent.  We need to
				 * set rval so as to indicate the packet has
				 * passed the check for its flags being valid
				 * in the TCP FSM.  Setting rval to 2 has the
				 * result of not resetting the timeout.
				 */
				rval = 2;
			} else if ((tcpflags & (TH_SYN|TH_FIN|TH_ACK)) ==
				   TH_ACK) {
				/*
				 * we see an A from 'dir' which is in SYN_SENT
				 * state: 'dir' sent an A in response to an SA
				 * which it received, SYN_SENT -> ESTABLISHED
				 */
				nstate = IPF_TCPS_ESTABLISHED;
				rval = 1;
			} else if (tcpflags & TH_FIN) {
				/*
				 * we see an F from 'dir' which is in SYN_SENT
				 * state and wants to close its side of the
				 * connection; SYN_SENT -> FIN_WAIT_1
				 */
				nstate = IPF_TCPS_FIN_WAIT_1;
				rval = 1;
			} else if ((tcpflags & TH_OPENING) == TH_OPENING) {
				/*
				 * we see an SA from 'dir' which is already in
				 * SYN_SENT state, this means we have a
				 * simultaneous open; SYN_SENT -> SYN_RECEIVED
				 */
				nstate = IPF_TCPS_SYN_RECEIVED;
				rval = 1;
			}
			break;

		case IPF_TCPS_SYN_RECEIVED: /* 2 */
			if ((tcpflags & (TH_SYN|TH_FIN|TH_ACK)) == TH_ACK) {
				/*
				 * we see an A from 'dir' which was in
				 * SYN_RECEIVED state so it must now be in
				 * established state, SYN_RECEIVED ->
				 * ESTABLISHED
				 */
				nstate = IPF_TCPS_ESTABLISHED;
				rval = 1;
			} else if ((tcpflags & ~(TH_ECN|TH_CWR)) ==
				   TH_OPENING) {
				/*
				 * We see an SA from 'dir' which is already in
				 * SYN_RECEIVED state.
				 */
				rval = 2;
			} else if (tcpflags & TH_FIN) {
				/*
				 * we see an F from 'dir' which is in
				 * SYN_RECEIVED state and wants to close its
				 * side of the connection; SYN_RECEIVED ->
				 * FIN_WAIT_1
				 */
				nstate = IPF_TCPS_FIN_WAIT_1;
				rval = 1;
			}
			break;

		case IPF_TCPS_HALF_ESTAB: /* 3 */
			if (tcpflags & TH_FIN) {
				nstate = IPF_TCPS_FIN_WAIT_1;
				rval = 1;
			} else if ((tcpflags & TH_ACKMASK) == TH_ACK) {
				/*
				 * If we've picked up a connection in mid
				 * flight, we could be looking at a follow on
				 * packet from the same direction as the one
				 * that created this state.  Recognise it but
				 * do not advance the entire connection's
				 * state.
				 */
				switch (ostate)
				{
				case IPF_TCPS_LISTEN :
				case IPF_TCPS_SYN_SENT :
				case IPF_TCPS_SYN_RECEIVED :
					rval = 1;
					break;
				case IPF_TCPS_HALF_ESTAB :
				case IPF_TCPS_ESTABLISHED :
					nstate = IPF_TCPS_ESTABLISHED;
					rval = 1;
					break;
				default :
					break;
				}
			}
			break;

		case IPF_TCPS_ESTABLISHED: /* 4 */
			rval = 1;
			if (tcpflags & TH_FIN) {
				/*
				 * 'dir' closed its side of the connection;
				 * this gives us a half-closed connection;
				 * ESTABLISHED -> FIN_WAIT_1
				 */
				if (ostate == IPF_TCPS_FIN_WAIT_1) {
					nstate = IPF_TCPS_CLOSING;
				} else {
					nstate = IPF_TCPS_FIN_WAIT_1;
				}
			} else if (tcpflags & TH_ACK) {
				/*
				 * an ACK, should we exclude other flags here?
				 */
				if (ostate == IPF_TCPS_FIN_WAIT_1) {
					/*
					 * We know the other side did an active
					 * close, so we are ACKing the recvd
					 * FIN packet (does the window matching
					 * code guarantee this?) and go into
					 * CLOSE_WAIT state; this gives us a
					 * half-closed connection
					 */
					nstate = IPF_TCPS_CLOSE_WAIT;
				} else if (ostate < IPF_TCPS_CLOSE_WAIT) {
					/*
					 * still a fully established
					 * connection reset timeout
					 */
					nstate = IPF_TCPS_ESTABLISHED;
				}
			}
			break;

		case IPF_TCPS_CLOSE_WAIT: /* 5 */
			rval = 1;
			if (tcpflags & TH_FIN) {
				/*
				 * application closed and 'dir' sent a FIN,
				 * we're now going into LAST_ACK state
				 */
				nstate = IPF_TCPS_LAST_ACK;
			} else {
				/*
				 * we remain in CLOSE_WAIT because the other
				 * side has closed already and we did not
				 * close our side yet; reset timeout
				 */
				nstate = IPF_TCPS_CLOSE_WAIT;
			}
			break;

		case IPF_TCPS_FIN_WAIT_1: /* 6 */
			rval = 1;
			if ((tcpflags & TH_ACK) &&
			    ostate > IPF_TCPS_CLOSE_WAIT) {
				/*
				 * if the other side is not active anymore
				 * it has sent us a FIN packet that we are
				 * ack'ing now with an ACK; this means both
				 * sides have now closed the connection and
				 * we go into TIME_WAIT
				 */
				/*
				 * XXX: how do we know we really are ACKing
				 * the FIN packet here? does the window code
				 * guarantee that?
				 */
				nstate = IPF_TCPS_LAST_ACK;
			} else {
				/*
				 * we closed our side of the connection
				 * already but the other side is still active
				 * (ESTABLISHED/CLOSE_WAIT); continue with
				 * this half-closed connection
				 */
				nstate = IPF_TCPS_FIN_WAIT_1;
			}
			break;

		case IPF_TCPS_CLOSING: /* 7 */
			if ((tcpflags & (TH_FIN|TH_ACK)) == TH_ACK) {
				nstate = IPF_TCPS_TIME_WAIT;
			}
			rval = 1;
			break;

		case IPF_TCPS_LAST_ACK: /* 8 */
			if (tcpflags & TH_ACK) {
				rval = 1;
			}
			/*
			 * we cannot detect when we go out of LAST_ACK state
			 * to CLOSED because that is based on the reception
			 * of ACK packets; ipfilter can only detect that a
			 * packet has been sent by a host
			 */
			break;

		case IPF_TCPS_FIN_WAIT_2: /* 9 */
			/* NOT USED */
			break;

		case IPF_TCPS_TIME_WAIT: /* 10 */
			/* we're in 2MSL timeout now */
			if (ostate == IPF_TCPS_LAST_ACK) {
				nstate = IPF_TCPS_CLOSED;
				rval = 1;
			} else {
				rval = 2;
			}
			break;

		case IPF_TCPS_CLOSED: /* 11 */
			rval = 2;
			break;

		default :
#if defined(_KERNEL)
# if SOLARIS
			cmn_err(CE_NOTE,
				"tcp %lx flags %x si %lx nstate %d ostate %d\n",
				(u_long)tcp, tcpflags, (u_long)tqe,
				nstate, ostate);
# else
			printf("tcp %lx flags %x si %lx nstate %d ostate %d\n",
				(u_long)tcp, tcpflags, (u_long)tqe,
				nstate, ostate);
# endif
#else
			abort();
#endif
			break;
		}
	}

	/*
	 * If rval == 2 then do not update the queue position, but treat the
	 * packet as being ok.
	 */
	if (rval == 2)
		rval = 1;
	else if (rval == 1) {
		if (ok)
			tqe->tqe_state[dir] = nstate;
		if ((tqe->tqe_flags & TQE_RULEBASED) == 0)
			ipf_movequeue(tqe, tqe->tqe_ifq, tqtab + nstate);
	}

	return rval;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_log                                               */
/* Returns:     Nil                                                         */
/* Parameters:  is(I)   - pointer to state structure                        */
/*              type(I) - type of log entry to create                       */
/*                                                                          */
/* Creates a state table log entry using the state structure and type info. */
/* passed in.  Log packet/byte counts, source/destination address and other */
/* protocol specific information.                                           */
/* ------------------------------------------------------------------------ */
void
ipf_state_log(is, type)
	struct ipstate *is;
	u_int type;
{
#ifdef	IPFILTER_LOG
	struct	ipslog	ipsl;
	size_t sizes[1];
	void *items[1];
	int types[1];

	/*
	 * Copy information out of the ipstate_t structure and into the
	 * structure used for logging.
	 */
	ipsl.isl_type = type;
	ipsl.isl_pkts[0] = is->is_pkts[0] + is->is_icmppkts[0];
	ipsl.isl_bytes[0] = is->is_bytes[0];
	ipsl.isl_pkts[1] = is->is_pkts[1] + is->is_icmppkts[1];
	ipsl.isl_bytes[1] = is->is_bytes[1];
	ipsl.isl_pkts[2] = is->is_pkts[2] + is->is_icmppkts[2];
	ipsl.isl_bytes[2] = is->is_bytes[2];
	ipsl.isl_pkts[3] = is->is_pkts[3] + is->is_icmppkts[3];
	ipsl.isl_bytes[3] = is->is_bytes[3];
	ipsl.isl_src = is->is_src;
	ipsl.isl_dst = is->is_dst;
	ipsl.isl_p = is->is_p;
	ipsl.isl_v = is->is_v;
	ipsl.isl_flags = is->is_flags;
	ipsl.isl_tag = is->is_tag;
	ipsl.isl_rulen = is->is_rulen;
	(void) strncpy(ipsl.isl_group, is->is_group, FR_GROUPLEN);

	if (ipsl.isl_p == IPPROTO_TCP || ipsl.isl_p == IPPROTO_UDP) {
		ipsl.isl_sport = is->is_sport;
		ipsl.isl_dport = is->is_dport;
		if (ipsl.isl_p == IPPROTO_TCP) {
			ipsl.isl_state[0] = is->is_state[0];
			ipsl.isl_state[1] = is->is_state[1];
		}
	} else if (ipsl.isl_p == IPPROTO_ICMP) {
		ipsl.isl_itype = is->is_icmp.ici_type;
	} else if (ipsl.isl_p == IPPROTO_ICMPV6) {
		ipsl.isl_itype = is->is_icmp.ici_type;
	} else {
		ipsl.isl_ps.isl_filler[0] = 0;
		ipsl.isl_ps.isl_filler[1] = 0;
	}

	items[0] = &ipsl;
	sizes[0] = sizeof(ipsl);
	types[0] = 0;

	if (ipf_log_items(IPL_LOGSTATE, NULL, items, sizes, types, 1)) {
		ATOMIC_INCL(ipf_state_stats.iss_log_ok);
	} else {
		ATOMIC_INCL(ipf_state_stats.iss_log_fail);
	}
#endif
}


#ifdef	USE_INET6
/* ------------------------------------------------------------------------ */
/* Function:    ipf_checkicmp6matchingstate                                 */
/* Returns:     ipstate_t* - NULL == no match found,                        */
/*                           else  pointer to matching state entry          */
/* Parameters:  fin(I) - pointer to packet information                      */
/* Locks:       NULL == no locks, else Read Lock on ipf_state               */
/*                                                                          */
/* If we've got an ICMPv6 error message, using the information stored in    */
/* the ICMPv6 packet, look for a matching state table entry.                */
/* ------------------------------------------------------------------------ */
static ipstate_t *
ipf_checkicmp6matchingstate(fin)
	fr_info_t *fin;
{
	struct icmp6_hdr *ic6, *oic;
	ipstate_t *is, **isp;
	u_short sport, dport;
	i6addr_t dst, src;
	u_short savelen;
	icmpinfo_t *ic;
	fr_info_t ofin;
	tcphdr_t *tcp;
	ip6_t *oip6;
	u_char pr;
	u_int hv;
	int type;

	/*
	 * Does it at least have the return (basic) IP header ?
	 * Is it an actual recognised ICMP error type?
	 * Only a basic IP header (no options) should be with
	 * an ICMP error header.
	 */
	if ((fin->fin_v != 6) || (fin->fin_plen < ICMP6ERR_MINPKTLEN) ||
	    !(fin->fin_flx & FI_ICMPERR)) {
		ATOMIC_INCL(ipf_state_stats.iss_icmp_bad);
		return NULL;
	}

	ic6 = fin->fin_dp;
	type = ic6->icmp6_type;

	oip6 = (ip6_t *)((char *)ic6 + ICMPERR_ICMPHLEN);
	if (fin->fin_plen < sizeof(*oip6)) {
		ATOMIC_INCL(ipf_state_stats.iss_icmp_short);
		return NULL;
	}

	bcopy((char *)fin, (char *)&ofin, sizeof(*fin));
	ofin.fin_v = 6;
	ofin.fin_ifp = fin->fin_ifp;
	ofin.fin_out = !fin->fin_out;
	ofin.fin_m = NULL;	/* if dereferenced, panic XXX */
	ofin.fin_mp = NULL;	/* if dereferenced, panic XXX */

	/*
	 * We make a fin entry to be able to feed it to
	 * matchsrcdst. Note that not all fields are necessary
	 * but this is the cleanest way. Note further we fill
	 * in fin_mp such that if someone uses it we'll get
	 * a kernel panic. ipf_matchsrcdst does not use this.
	 *
	 * watch out here, as ip is in host order and oip6 in network
	 * order. Any change we make must be undone afterwards.
	 */
	savelen = oip6->ip6_plen;
	oip6->ip6_plen = fin->fin_dlen - ICMPERR_ICMPHLEN;
	ofin.fin_flx = FI_NOCKSUM;
	ofin.fin_ip = (ip_t *)oip6;
	(void) ipf_makefrip(sizeof(*oip6), (ip_t *)oip6, &ofin);
	ofin.fin_flx &= ~(FI_BAD|FI_SHORT);
	oip6->ip6_plen = savelen;
	pr = ofin.fin_p;

	/*
	 * an ICMP error can never generate an ICMP error in response.
	 */
	if (ofin.fin_flx & FI_ICMPERR) {
		ATOMIC_INCL(ipf_state_stats.iss_icmp6_icmperr);
		return NULL;
	}

	if (oip6->ip6_nxt == IPPROTO_ICMPV6) {
		oic = ofin.fin_dp;
		/*
		 * an ICMP error can only be generated as a result of an
		 * ICMP query, not as the response on an ICMP error
		 *
		 * XXX theoretically ICMP_ECHOREP and the other reply's are
		 * ICMP query's as well, but adding them here seems strange XXX
		 */
		 if (!(oic->icmp6_type & ICMP6_INFOMSG_MASK)) {
			ATOMIC_INCL(ipf_state_stats.iss_icmp6_notinfo);
			return NULL;
		}

		/*
		 * perform a lookup of the ICMP packet in the state table
		 */
		hv = (pr = oip6->ip6_nxt);
		src.in6 = oip6->ip6_src;
		hv += src.in4.s_addr;
		dst.in6 = oip6->ip6_dst;
		hv += dst.in4.s_addr;
		hv += oic->icmp6_id;
		hv += oic->icmp6_seq;
		hv = DOUBLE_HASH(hv);

		READ_ENTER(&ipf_state);
		for (isp = &ipf_state_table[hv]; ((is = *isp) != NULL); ) {
			ic = &is->is_icmp;
			isp = &is->is_hnext;
			if ((is->is_p == pr) &&
			    !(is->is_pass & FR_NOICMPERR) &&
			    (oic->icmp6_id == ic->ici_id) &&
			    (oic->icmp6_seq == ic->ici_seq) &&
			    (is = ipf_matchsrcdst(&ofin, is, &src,
						 &dst, NULL, FI_ICMPCMP))) {
			    	/*
			    	 * in the state table ICMP query's are stored
			    	 * with the type of the corresponding ICMP
			    	 * response. Correct here
			    	 */
				if (((ic->ici_type == ICMP6_ECHO_REPLY) &&
				     (oic->icmp6_type == ICMP6_ECHO_REQUEST)) ||
				     (ic->ici_type - 1 == oic->icmp6_type )) {
					if (!ipf_allowstateicmp(fin, is, &src))
						return is;
				}
			}
		}
		RWLOCK_EXIT(&ipf_state);
		ATOMIC_INCL(ipf_state_stats.iss_icmp6_miss);
		return NULL;
	}

	hv = (pr = oip6->ip6_nxt);
	src.in6 = oip6->ip6_src;
	hv += src.i6[0];
	hv += src.i6[1];
	hv += src.i6[2];
	hv += src.i6[3];
	dst.in6 = oip6->ip6_dst;
	hv += dst.i6[0];
	hv += dst.i6[1];
	hv += dst.i6[2];
	hv += dst.i6[3];

	tcp = NULL;

	switch (oip6->ip6_nxt)
	{
	case IPPROTO_TCP :
	case IPPROTO_UDP :
		tcp = (tcphdr_t *)(oip6 + 1);
		dport = tcp->th_dport;
		sport = tcp->th_sport;
		hv += dport;
		hv += sport;
		break;

	case IPPROTO_ICMPV6 :
		oic = (struct icmp6_hdr *)(oip6 + 1);
		hv += oic->icmp6_id;
		hv += oic->icmp6_seq;
		break;

	default :
		break;
	}

	hv = DOUBLE_HASH(hv);

	READ_ENTER(&ipf_state);
	for (isp = &ipf_state_table[hv]; ((is = *isp) != NULL); ) {
		isp = &is->is_hnext;
		/*
		 * Only allow this icmp though if the
		 * encapsulated packet was allowed through the
		 * other way around. Note that the minimal amount
		 * of info present does not allow for checking against
		 * tcp internals such as seq and ack numbers.
		 */
		if ((is->is_p != pr) || (is->is_v != 6) ||
		    (is->is_pass & FR_NOICMPERR))
			continue;
		is = ipf_matchsrcdst(&ofin, is, &src, &dst, tcp, FI_ICMPCMP);
		if ((is != NULL) && (ipf_allowstateicmp(fin, is, &src) == 0))
			return is;
	}
	RWLOCK_EXIT(&ipf_state);
	ATOMIC_INCL(ipf_state_stats.iss_icmp_miss);
	return NULL;
}
#endif


/* ------------------------------------------------------------------------ */
/* Function:    ipf_sttab_init                                              */
/* Returns:     Nil                                                         */
/* Parameters:  tqp(I) - pointer to an array of timeout queues for TCP      */
/*                                                                          */
/* Initialise the array of timeout queues for TCP.                          */
/* ------------------------------------------------------------------------ */
void
ipf_sttab_init(tqp)
	ipftq_t *tqp;
{
	int i;

	for (i = IPF_TCP_NSTATES - 1; i >= 0; i--) {
		IPFTQ_INIT(&tqp[i], 0, "ipftq tcp tab");
		tqp[i].ifq_next = tqp + i + 1;
	}
	tqp[IPF_TCP_NSTATES - 1].ifq_next = NULL;
	tqp[IPF_TCPS_CLOSED].ifq_ttl = ipf_tcpclosed;
	tqp[IPF_TCPS_LISTEN].ifq_ttl = ipf_tcptimeout;
	tqp[IPF_TCPS_SYN_SENT].ifq_ttl = ipf_tcpsynsent;
	tqp[IPF_TCPS_SYN_RECEIVED].ifq_ttl = ipf_tcpsynrecv;
	tqp[IPF_TCPS_ESTABLISHED].ifq_ttl = ipf_tcpidletimeout;
	tqp[IPF_TCPS_CLOSE_WAIT].ifq_ttl = ipf_tcphalfclosed;
	tqp[IPF_TCPS_FIN_WAIT_1].ifq_ttl = ipf_tcphalfclosed;
	tqp[IPF_TCPS_CLOSING].ifq_ttl = ipf_tcptimeout;
	tqp[IPF_TCPS_LAST_ACK].ifq_ttl = ipf_tcplastack;
	tqp[IPF_TCPS_FIN_WAIT_2].ifq_ttl = ipf_tcpclosewait;
	tqp[IPF_TCPS_TIME_WAIT].ifq_ttl = ipf_tcptimewait;
	tqp[IPF_TCPS_HALF_ESTAB].ifq_ttl = ipf_tcptimeout;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_sttab_destroy                                           */
/* Returns:     Nil                                                         */
/* Parameters:  tqp(I) - pointer to an array of timeout queues for TCP      */
/*                                                                          */
/* Do whatever is necessary to "destroy" each of the entries in the array   */
/* of timeout queues for TCP.                                               */
/* ------------------------------------------------------------------------ */
void
ipf_sttab_destroy(tqp)
	ipftq_t *tqp;
{
	int i;

	for (i = IPF_TCP_NSTATES - 1; i >= 0; i--)
		MUTEX_DESTROY(&tqp[i].ifq_lock);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_deref                                             */
/* Returns:     Nil                                                         */
/* Parameters:  isp(I) - pointer to pointer to state table entry            */
/*                                                                          */
/* Decrement the reference counter for this state table entry and free it   */
/* if there are no more things using it.                                    */
/*                                                                          */
/* This function is only called when cleaning up after increasing is_ref by */
/* one earlier in the 'code path' so if is_ref is 1 when entering, we do    */
/* have an orphan, otherwise not.  However there is a possible race between */
/* the entry being deleted via flushing with an ioctl call (that calls the  */
/* delete function directly) and the tail end of packet processing so we    */
/* need to grab is_lock before doing the check to synchronise the two code  */
/* paths.                                                                   */
/*                                                                          */
/* When operating in userland (ipftest), we have no timers to clear a state */
/* entry.  Therefore, we make a few simple tests before deleting an entry   */
/* outright.  We compare states on each side looking for a combination of   */
/* TIME_WAIT (should really be FIN_WAIT_2?) and LAST_ACK.  Then we factor   */
/* in packet direction with the interface list to make sure we don't        */
/* prematurely delete an entry on a final inbound packet that's we're also  */
/* supposed to route elsewhere.                                             */
/*                                                                          */
/* Internal parameters:                                                     */
/*    state[0] = state of source (host that initiated connection)           */
/*    state[1] = state of dest   (host that accepted the connection)        */
/*                                                                          */
/*    dir == 0 : a packet from source to dest                               */
/*    dir == 1 : a packet from dest to source                               */
/* ------------------------------------------------------------------------ */
void
ipf_state_deref(isp)
	ipstate_t **isp;
{
	ipstate_t *is = *isp;

	is = *isp;
	*isp = NULL;

	MUTEX_ENTER(&is->is_lock);
	if (is->is_ref > 1) {
		is->is_ref--;
		MUTEX_EXIT(&is->is_lock);
#ifndef	_KERNEL
		if ((is->is_sti.tqe_state[0] > IPF_TCPS_ESTABLISHED) ||
		    (is->is_sti.tqe_state[1] > IPF_TCPS_ESTABLISHED)) {
			ipf_state_del(is, ISL_EXPIRE);
		}
#endif
		return;
	}
	MUTEX_EXIT(&is->is_lock);

	WRITE_ENTER(&ipf_state);
	ipf_state_del(is, ISL_ORPHAN);
	RWLOCK_EXIT(&ipf_state);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_setqueue                                          */
/* Returns:     Nil                                                         */
/* Parameters:  is(I) - pointer to state structure                          */
/*              rev(I) - forward(0) or reverse(1) direction                 */
/* Locks:       ipf_state (read or write)                                   */
/*                                                                          */
/* Put the state entry on its default queue entry, using rev as a helped in */
/* determining which queue it should be placed on.                          */
/* ------------------------------------------------------------------------ */
void
ipf_state_setqueue(is, rev)
	ipstate_t *is;
	int rev;
{
	ipftq_t *oifq, *nifq;

	if ((is->is_sti.tqe_flags & TQE_RULEBASED) != 0)
		nifq = is->is_tqehead[rev];
	else
		nifq = NULL;

	if (nifq == NULL) {
		switch (is->is_p)
		{
#ifdef USE_INET6
		case IPPROTO_ICMPV6 :
			if (rev == 1)
				nifq = &ipf_state_icmpacktq;
			else
				nifq = &ipf_state_icmptq;
			break;
#endif
		case IPPROTO_ICMP :
			if (rev == 1)
				nifq = &ipf_state_icmpacktq;
			else
				nifq = &ipf_state_icmptq;
			break;
		case IPPROTO_TCP :
			nifq = ipf_state_tcptq + is->is_state[rev];
			break;

		case IPPROTO_UDP :
			if (rev == 1)
				nifq = &ipf_state_udpacktq;
			else
				nifq = &ipf_state_udptq;
			break;

		default :
			nifq = &ipf_state_iptq;
			break;
		}
	}

	oifq = is->is_sti.tqe_ifq;
	/*
	 * If it's currently on a timeout queue, move it from one queue to
	 * another, else put it on the end of the newly determined queue.
	 */
	if (oifq != NULL)
		ipf_movequeue(&is->is_sti, oifq, nifq);
	else
		ipf_queueappend(&is->is_sti, nifq, is);
	return;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_stateiter                                               */
/* Returns:     int - 0 == success, else error                              */
/* Parameters:  token(I) - pointer to ipftoken structure                    */
/*              itp(I)   - pointer to ipfgeniter structure                  */
/*                                                                          */
/* This function handles the SIOCGENITER ioctl for the state tables and     */
/* walks through the list of entries in the state table list (ipf_state_list.)    */
/* ------------------------------------------------------------------------ */
static int
ipf_stateiter(token, itp)
	ipftoken_t *token;
	ipfgeniter_t *itp;
{
	ipstate_t *is, *next, zero;
	int error, count;
	char *dst;

	if (itp->igi_data == NULL) {
		ipf_interror = 100026;
		return EFAULT;
	}

	if (itp->igi_nitems < 1) {
		ipf_interror = 100027;
		return ENOSPC;
	}

	if (itp->igi_type != IPFGENITER_STATE) {
		ipf_interror = 100028;
		return EINVAL;
	}

	error = 0;

	READ_ENTER(&ipf_state);

	/*
	 * Get "previous" entry from the token, and find the next entry
	 * to be processed.
	 */
	is = token->ipt_data;
	if (is == NULL) {
		next = ipf_state_list;
	} else {
		next = is->is_next;
	}

	dst = itp->igi_data;
	for (count = itp->igi_nitems; count > 0; count--) {
		/*
		 * If we found an entry, add a reference and update the token.
		 * Otherwise, zero out data to be returned and NULL out token.
		 */
		if (next != NULL) {
			MUTEX_ENTER(&next->is_lock);
			next->is_ref++;
			MUTEX_EXIT(&next->is_lock);
			token->ipt_data = next;
		} else {
			bzero(&zero, sizeof(zero));
			next = &zero;
			token->ipt_data = NULL;
		}

		/*
		 * Safe to release lock now the we have a reference.
		 */
		RWLOCK_EXIT(&ipf_state);

		/*
		 * Copy out data and clean up references and tokens.
		 */
		error = COPYOUT(next, dst, sizeof(*next));
		if (error != 0) {
			ipf_interror = 100030;
			error = EFAULT;
		}
		if (token->ipt_data == NULL) {
			ipf_freetoken(token);
			break;
		} else {
			if (is != NULL)
				ipf_state_deref(&is);
			if (next->is_next == NULL) {
				ipf_freetoken(token);
				break;
			}
		}

		if ((count == 1) || (error != 0))
			break;

		READ_ENTER(&ipf_state);
		dst += sizeof(*next);
		is = next;
		next = is->is_next;
	}

	return error;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_stgettable                                              */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  data(I) - pointer to ioctl data                             */
/*                                                                          */
/* This function handles ioctl requests for tables of state information.    */
/* At present the only table it deals with is the hash bucket statistics.   */
/* ------------------------------------------------------------------------ */
static int
ipf_stgettable(data)
	char *data;
{
	ipftable_t table;
	int error;

	error = ipf_inobj(data, &table, IPFOBJ_GTABLE);
	if (error != 0)
		return error;

	if (table.ita_type != IPFTABLE_BUCKETS) {
		ipf_interror = 100031;
		return EINVAL;
	}

	error = COPYOUT(ipf_state_stats.iss_bucketlen, table.ita_table,
			ipf_state_size * sizeof(u_int));
	if (error != 0) {
		ipf_interror = 100032;
		error = EFAULT;
	}
	return error;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_setpending                                        */
/* Returns:     Nil                                                         */
/* Parameters:  is(I) - pointer to state structure                          */
/* Locks:       ipf_state (read or write)                                   */
/*                                                                          */
/* Put the state entry on to the pending queue - this queue has a very      */
/* short lifetime where items are put that can't be deleted straight away   */
/* because of locking issues but we want to delete them ASAP, anyway.       */
/* ------------------------------------------------------------------------ */
void
ipf_state_setpending(is)
	ipstate_t *is;
{
	ipftq_t *oifq;

	oifq = is->is_sti.tqe_ifq;
	if (oifq != NULL)
		ipf_movequeue(&is->is_sti, oifq, &ipf_state_pending);
	else
		ipf_queueappend(&is->is_sti, &ipf_state_pending, is);

	if (is->is_me != NULL) {
		*is->is_me = NULL;
		is->is_me = NULL;
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_matchflush                                        */
/* Returns:     Nil                                                         */
/* Parameters:  is(I) - pointer to state structure                          */
/* Locks:       ipf_state (read or write)                                   */
/*                                                                          */
/* Flush all entries from the list of state entries that match the          */
/* properties in the array loaded.                                          */
/* ------------------------------------------------------------------------ */
int
ipf_state_matchflush(data)
	caddr_t data;
{
	int *array, flushed, error;
	ipstate_t *state, *statenext;
	ipfobj_t obj;

	error = ipf_matcharray_load(data, &obj, &array);
	if (error != 0)
		return error;

	flushed = 0;

	for (state = ipf_state_list; state != NULL; state = statenext) {
		statenext = state->is_next;
		if (ipf_state_matcharray(state, array) == 0) {
			ipf_state_del(state, ISL_FLUSH);
			flushed++;
		}
	}

	obj.ipfo_retval = flushed;
	error = BCOPYOUT(&obj, data, sizeof(obj));

	KFREES(array, array[0] * sizeof(*array));

	return error;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_matcharray                                        */
/* Returns:     int   - 0 = no match, 1 = match                             */
/* Parameters:  is(I) - pointer to state structure                          */
/* Locks:       ipf_state (read or write)                                   */
/*                                                                          */
/* Compare a state entry with the match array passed in and return a value  */
/* to indicate whether or not the matching was successful.                  */
/* ------------------------------------------------------------------------ */
static int
ipf_state_matcharray(state, array)
	ipstate_t *state;
	int *array;
{
	int i, n, *x, e, p;

	e = 0;
	n = array[0];
	x = array + 1;

	for (; n > 0; x += 3 + x[2]) {
		if (x[0] == IPF_EXP_END)
			break;

		n -= x[2] + 3;
		if (n < 0)
			break;

		e = 0;

		/*
		 * If we need to match the protocol and that doesn't match,
		 * don't even both with the instruction array.
		 */
		p = (x[0] >> 16) & 0xff;
		if (p != 0 && p != state->is_p)
			break;

		switch (x[0])
		{
		case IPF_EXP_IP_PR :
			for (i = 0; !e && i < x[2]; i++) {
				e |= (state->is_p == x[i + 3]);
			}
			break;

		case IPF_EXP_IP_SRCADDR :
			if (state->is_v != 4)
				break;
			for (i = 0; !e && i < x[2]; i++) {
				e |= ((state->is_saddr & x[i + 4]) ==
				      x[i + 3]);
			}
			break;

		case IPF_EXP_IP_DSTADDR :
			if (state->is_v != 4)
				break;
			for (i = 0; !e && i < x[2]; i++) {
				e |= ((state->is_daddr & x[i + 4]) ==
				      x[i + 3]);
			}
			break;

		case IPF_EXP_IP_ADDR :
			if (state->is_v != 4)
				break;
			for (i = 0; !e && i < x[2]; i++) {
				e |= ((state->is_saddr & x[i + 4]) ==
				      x[i + 3]) ||
				     ((state->is_daddr & x[i + 4]) ==
				      x[i + 3]);
			}
			break;

#ifdef USE_INET6
		case IPF_EXP_IP6_SRCADDR :
			if (state->is_v != 6)
				break;
			for (i = 0; !e && i < x[3]; i++) {
				e |= IP6_MASKEQ(&state->is_src.in6, x + i + 7,
						x + i + 3);
			}
			break;

		case IPF_EXP_IP6_DSTADDR :
			if (state->is_v != 6)
				break;
			for (i = 0; !e && i < x[3]; i++) {
				e |= IP6_MASKEQ(&state->is_dst.in6, x + i + 7,
						x + i + 3);
			}
			break;

		case IPF_EXP_IP6_ADDR :
			if (state->is_v != 6)
				break;
			for (i = 0; !e && i < x[3]; i++) {
				e |= IP6_MASKEQ(&state->is_src.in6, x + i + 7,
						x + i + 3) ||
				     IP6_MASKEQ(&state->is_dst.in6, x + i + 7,
						x + i + 3);
			}
			break;
#endif

		case IPF_EXP_UDP_PORT :
		case IPF_EXP_TCP_PORT :
			for (i = 0; !e && i < x[2]; i++) {
				e |= (state->is_sport == x[i + 3]) ||
				     (state->is_dport == x[i + 3]);
			}
			break;

		case IPF_EXP_UDP_SPORT :
		case IPF_EXP_TCP_SPORT :
			for (i = 0; !e && i < x[2]; i++) {
				e |= (state->is_sport == x[i + 3]);
			}
			break;

		case IPF_EXP_UDP_DPORT :
		case IPF_EXP_TCP_DPORT :
			for (i = 0; !e && i < x[2]; i++) {
				e |= (state->is_dport == x[i + 3]);
			}
			break;

		case IPF_EXP_TCP_STATE :
			for (i = 0; !e && i < x[2]; i++) {
				e |= (state->is_state[0] == x[i + 3]) ||
				     (state->is_state[1] == x[i + 3]);
			}
			break;

		case IPF_EXP_IDLE_GT :
			e |= (ipf_ticks - state->is_touched > x[3]);
			break;
		}

		/*
		 * Factor in doing a negative match.
		 */
		e ^= x[1];

		if (!e)
			break;
	}

	return e;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_settimeout                                        */
/* Returns:     int 0 = success, else failure                               */
/* Parameters:  t(I) - pointer to tuneable being changed                    */
/*              p(I) - pointer to the new value                             */
/*                                                                          */
/* Sets a timeout value for one of the many timeout queues.  We find the    */
/* correct queue using a somewhat manual process of comparing the timeout   */
/* names for each specific value available and calling ipf_apply_timeout on */
/* that queue so that all of the items on it are updated accordingly.       */
/* ------------------------------------------------------------------------ */
int
ipf_state_settimeout(t, p)
	ipftuneable_t *t;
	ipftuneval_t *p;
{

	/*
	 * In case there is nothing to do...
	 */
	if (*t->ipft_pint == p->ipftu_int)
		return 0;

	if (!strncmp(t->ipft_name, "tcp_", 4))
		return ipf_settimeout_tcp(t, p, ipf_state_tcptq);

	if (!strcmp(t->ipft_name, "udp_timeout")) {
		ipf_apply_timeout(&ipf_state_udptq, p->ipftu_int);
	} else if (!strcmp(t->ipft_name, "udp_ack_timeout")) {
		ipf_apply_timeout(&ipf_state_udpacktq, p->ipftu_int);
	} else if (!strcmp(t->ipft_name, "icmp_timeout")) {
		ipf_apply_timeout(&ipf_state_icmptq, p->ipftu_int);
	} else if (!strcmp(t->ipft_name, "icmp_ack_timeout")) {
		ipf_apply_timeout(&ipf_state_icmpacktq, p->ipftu_int);
	} else if (!strcmp(t->ipft_name, "ip_timeout")) {
		ipf_apply_timeout(&ipf_state_iptq, p->ipftu_int);
	} else {
		ipf_interror = 100034;
		return ESRCH;
	}

	/*
	 * Update the tuneable being set.
	 */
	*t->ipft_pint = p->ipftu_int;

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_state_rehash                                            */
/* Returns:     int 0 = success, else failure                               */
/* Parameters:  t(I) - pointer to tuneable being changed                    */
/*              p(I) - pointer to the new value                             */
/*                                                                          */
/* To change the size of the state hash table at runtime, a new table has   */
/* to be allocated and then all of the existing entries put in it, bumping  */
/* up the bucketlength for it as we go along.                               */
/* ------------------------------------------------------------------------ */
int
ipf_state_rehash(t, p)
	ipftuneable_t *t;
	ipftuneval_t *p;
{
	ipstate_t **newtab, *is;
	u_int *bucketlens;
	u_int maxbucket;
	u_int newsize;
	u_int hv;
	int i;

	newsize = p->ipftu_int;
	/*
	 * In case there is nothing to do...
	 */
	if (newsize == ipf_state_size)
		return 0;

	KMALLOCS(newtab, ipstate_t **, newsize * sizeof(ipstate_t *));
	if (newtab == NULL) {
		ipf_interror = 100035;
		return ENOMEM;
	}

	KMALLOCS(bucketlens, u_int *, newsize * sizeof(u_int));
	if (bucketlens == NULL) {
		KFREES(newtab, newsize * sizeof(*ipf_state_table));
		ipf_interror = 100036;
		return ENOMEM;
	}

	for (maxbucket = 0, i = newsize; i > 0; i >>= 1)
		maxbucket++;
	maxbucket *= 2;

	bzero((char *)newtab, newsize * sizeof(ipstate_t *));
	bzero((char *)bucketlens, newsize * sizeof(u_int));

	WRITE_ENTER(&ipf_state);

	if (ipf_state_table != NULL) {
		KFREES(ipf_state_table,
		       ipf_state_size * sizeof(*ipf_state_table));
	}
	ipf_state_table = newtab;

	if (ipf_state_stats.iss_bucketlen != NULL) {
		KFREES(ipf_state_stats.iss_bucketlen,
		       ipf_state_size * sizeof(u_int));
	}
	ipf_state_stats.iss_bucketlen = bucketlens;
	ipf_state_maxbucket = maxbucket;
	ipf_state_size = newsize;

	/*
	 * Walk through the entire list of state table entries and put them
	 * in the new state table, somewhere.  Because we have a new table,
	 * we need to restart the counter of how many chains are in use.
	 */
	ipf_state_stats.iss_inuse = 0;
	for (is = ipf_state_list; is != NULL; is = is->is_next) {
		is->is_hnext = NULL;
		is->is_phnext = NULL;
		hv = is->is_hv % ipf_state_size;

		if (ipf_state_table[hv] != NULL)
			ipf_state_table[hv]->is_phnext = &is->is_hnext;
		else
			ipf_state_stats.iss_inuse++;
		is->is_phnext = ipf_state_table + hv;
		is->is_hnext = ipf_state_table[hv];
		ipf_state_table[hv] = is;
		ipf_state_stats.iss_bucketlen[hv]++;
	}
	RWLOCK_EXIT(&ipf_state);

	return 0;
}
