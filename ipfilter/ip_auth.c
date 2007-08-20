/*
 * Copyright (C) 1998-2003 by Darren Reed & Guido van Rooij.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
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
#include <sys/time.h>
#include <sys/file.h>
#if !defined(_KERNEL)
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
#if !defined(linux)
# include <sys/protosw.h>
#endif
#include <sys/socket.h>
#if defined(_KERNEL)
# include <sys/systm.h>
# if !defined(__SVR4) && !defined(__svr4__) && !defined(linux)
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
#if (_BSDI_VERSION >= 199802) || (__FreeBSD_version >= 400000)
# include <sys/queue.h>
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(bsdi)
# include <machine/cpu.h>
#endif
#if defined(_KERNEL) && defined(__NetBSD__) && (__NetBSD_Version__ >= 104000000)
# include <sys/proc.h>
#endif
#include <net/if.h>
#ifdef sun
# include <net/af.h>
#endif
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#if !defined(_KERNEL) && !defined(__osf__) && !defined(__sgi)
# define	KERNEL
# define	_KERNEL
# define	NOT_KERNEL
#endif
#if !defined(linux)
# include <netinet/ip_var.h>
#endif
#ifdef	NOT_KERNEL
# undef	_KERNEL
# undef	KERNEL
#endif
#include <netinet/tcp.h>
#if defined(IRIX) && (IRIX < 60516) /* IRIX < 6 */
extern struct ifqueue   ipintrq;		/* ip packet input queue */
#else
# if !defined(__hpux) && !defined(linux)
#  if __FreeBSD_version >= 300000
#   include <net/if_var.h>
#   if __FreeBSD_version >= 500042
#    define IF_QFULL _IF_QFULL
#    define IF_DROP _IF_DROP
#   endif /* __FreeBSD_version >= 500042 */
#  endif
#  include <netinet/in_var.h>
#  include <netinet/tcp_fsm.h>
# endif
#endif
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "netinet/ip_compat.h"
#include <netinet/tcpip.h>
#include "netinet/ip_fil.h"
#include "netinet/ip_auth.h"
#if !defined(MENTAT) && !defined(linux)
# include <net/netisr.h>
# ifdef __FreeBSD__
#  include <machine/cpufunc.h>
# endif
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
static const char rcsid[] = "@(#)$Id$";
#endif


#if SOLARIS && defined(_KERNEL)
extern kcondvar_t ipf_auth_wait;
extern struct pollhead ipf_poll_head[IPL_LOGSIZE];
#endif /* SOLARIS */
#if defined(linux) && defined(_KERNEL)
wait_queue_head_t     ipf_auth_next_linux;
#endif

int	ipf_auth_size = FR_NUMAUTH;
int	ipf_auth_used = 0;
int	ipf_auth_defaultage = 600;
int	ipf_auth_lock = 0;
int	ipf_auth_inited = 0;
ipf_authstat_t	ipf_auth_stats;
static frauth_t *ipf_auth = NULL;
mb_t	**ipf_auth_pkts = NULL;
int	ipf_auth_start = 0, ipf_auth_end = 0, ipf_auth_next = 0;
frauthent_t	*ipf_auth_entries = NULL;
frentry_t	*ipf_auth_ip = NULL,
		*ipf_auth_rules = NULL;

void ipf_auth_deref __P((frauthent_t **));
int ipf_auth_geniter __P((ipftoken_t *, ipfgeniter_t *));
int ipf_auth_reply __P((char *));
int ipf_auth_wait __P((char *));

/* ------------------------------------------------------------------------ */
/* Function:    ipf_auth_init                                               */
/* Returns:     int - 0 == success, else error                              */
/* Parameters:  None                                                        */
/*                                                                          */
/* Allocate memory and initialise data structures used in handling auth     */
/* rules.                                                                   */
/* ------------------------------------------------------------------------ */
int
ipf_auth_init()
{
	KMALLOCS(ipf_auth, frauth_t *, ipf_auth_size * sizeof(*ipf_auth));
	if (ipf_auth != NULL)
		bzero((char *)ipf_auth, ipf_auth_size * sizeof(*ipf_auth));
	else
		return -1;

	KMALLOCS(ipf_auth_pkts, mb_t **,
		 ipf_auth_size * sizeof(*ipf_auth_pkts));
	if (ipf_auth_pkts != NULL)
		bzero((char *)ipf_auth_pkts,
		      ipf_auth_size * sizeof(*ipf_auth_pkts));
	else
		return -2;

	MUTEX_INIT(&ipf_auth_mx, "ipf auth log mutex");
	RWLOCK_INIT(&ipf_authlk, "ipf IP User-Auth rwlock");
#if SOLARIS && defined(_KERNEL)
	cv_init(&ipf_auth_wait, "ipf auth condvar", CV_DRIVER, NULL);
#endif
#if defined(linux) && defined(_KERNEL)
	init_waitqueue_head(&ipf_auth_next_linux);
#endif

	ipf_auth_inited = 1;

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_auth_check                                              */
/* Returns:     frentry_t* - pointer to ipf rule if match found, else NULL  */
/* Parameters:  fin(I)   - pointer to ipftoken structure                    */
/*              passp(I) - pointer to ipfgeniter structure                  */
/*                                                                          */
/* Check if a packet has authorization.  If the packet is found to match an */
/* authorization result and that would result in a feedback loop (i.e. it   */
/* will end up returning FR_AUTH) then return FR_BLOCK instead.             */
/* ------------------------------------------------------------------------ */
frentry_t *
ipf_auth_check(fin, passp)
	fr_info_t *fin;
	u_32_t *passp;
{
	frentry_t *fr;
	frauth_t *fra;
	u_32_t pass;
	u_short id;
	ip_t *ip;
	int i;

	if (ipf_auth_lock || !ipf_auth_used)
		return NULL;

	ip = fin->fin_ip;
	id = ip->ip_id;

	READ_ENTER(&ipf_authlk);
	for (i = ipf_auth_start; i != ipf_auth_end; ) {
		/*
		 * index becomes -2 only after an SIOCAUTHW.  Check this in
		 * case the same packet gets sent again and it hasn't yet been
		 * auth'd.
		 */
		fra = ipf_auth + i;
		if ((fra->fra_index == -2) && (id == fra->fra_info.fin_id) &&
		    !bcmp((char *)fin, (char *)&fra->fra_info, FI_CSIZE)) {
			/*
			 * Avoid feedback loop.
			 */
			if (!(pass = fra->fra_pass) || (FR_ISAUTH(pass))) {
				pass = FR_BLOCK;
				fin->fin_reason = 9;
			}
			/*
			 * Create a dummy rule for the stateful checking to
			 * use and return.  Zero out any values we don't
			 * trust from userland!
			 */
			if ((pass & FR_KEEPSTATE) || ((pass & FR_KEEPFRAG) &&
			     (fin->fin_flx & FI_FRAG))) {
				KMALLOC(fr, frentry_t *);
				if (fr) {
					bcopy((char *)fra->fra_info.fin_fr,
					      (char *)fr, sizeof(*fr));
					fr->fr_grp = NULL;
					fr->fr_ifa = fin->fin_ifp;
					fr->fr_func = NULL;
					fr->fr_ref = 1;
					fr->fr_flags = pass;
					fr->fr_ifas[1] = NULL;
					fr->fr_ifas[2] = NULL;
					fr->fr_ifas[3] = NULL;
				}
			} else
				fr = fra->fra_info.fin_fr;
			fin->fin_fr = fr;
			RWLOCK_EXIT(&ipf_authlk);

			WRITE_ENTER(&ipf_authlk);
			/*
			 * ipf_auth_rules is populated with the rules malloc'd
			 * above and only those.
			 */
			if ((fr != NULL) && (fr != fra->fra_info.fin_fr)) {
				fr->fr_next = ipf_auth_rules;
				ipf_auth_rules = fr;
			}
			ipf_auth_stats.fas_hits++;
			fra->fra_index = -1;
			ipf_auth_used--;
			if (i == ipf_auth_start) {
				while (fra->fra_index == -1) {
					i++;
					fra++;
					if (i == ipf_auth_size) {
						i = 0;
						fra = ipf_auth;
					}
					ipf_auth_start = i;
					if (i == ipf_auth_end)
						break;
				}
				if (ipf_auth_start == ipf_auth_end) {
					ipf_auth_next = 0;
					ipf_auth_start = ipf_auth_end = 0;
				}
			}
			RWLOCK_EXIT(&ipf_authlk);
			if (passp != NULL)
				*passp = pass;
			ATOMIC_INC64(ipf_auth_stats.fas_hits);
			return fr;
		}
		i++;
		if (i == ipf_auth_size)
			i = 0;
	}
	ipf_auth_stats.fas_miss++;
	RWLOCK_EXIT(&ipf_authlk);
	ATOMIC_INC64(ipf_auth_stats.fas_miss);
	return NULL;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_auth_new                                                */
/* Returns:     int - 0 == success, else error                              */
/* Parameters:  m(I)   - pointer to mb_t with packet in it                  */
/*              fin(I) - pointer to packet information                      */
/*                                                                          */
/* Check if we have room in the auth array to hold details for another      */
/* packet. If we do, store it and wake up any user programs which are       */
/* waiting to hear about these events.                                      */
/* ------------------------------------------------------------------------ */
int
ipf_auth_new(m, fin)
	mb_t *m;
	fr_info_t *fin;
{
#if defined(_KERNEL) && defined(MENTAT)
	qpktinfo_t *qpi = fin->fin_qpi;
#endif
	frauth_t *fra;
#if !defined(sparc) && !defined(m68k)
	ip_t *ip;
#endif
	int i;

	if (ipf_auth_lock)
		return 0;

	WRITE_ENTER(&ipf_authlk);
	if (((ipf_auth_end + 1) % ipf_auth_size) == ipf_auth_start) {
		ipf_auth_stats.fas_nospace++;
		RWLOCK_EXIT(&ipf_authlk);
		return 0;
	}

	ipf_auth_stats.fas_added++;
	ipf_auth_used++;
	i = ipf_auth_end++;
	if (ipf_auth_end == ipf_auth_size)
		ipf_auth_end = 0;
	RWLOCK_EXIT(&ipf_authlk);

	fra = ipf_auth + i;
	fra->fra_index = i;
	if (fin->fin_fr != NULL)
		fra->fra_pass = fin->fin_fr->fr_flags;
	else
		fra->fra_pass = 0;
	fra->fra_age = ipf_auth_defaultage;
	bcopy((char *)fin, (char *)&fra->fra_info, sizeof(*fin));
#if !defined(sparc) && !defined(m68k)
	/*
	 * No need to copyback here as we want to undo the changes, not keep
	 * them.
	 */
	ip = fin->fin_ip;
# if defined(MENTAT) && defined(_KERNEL)
	if ((ip == (ip_t *)m->b_rptr) && (fin->fin_v == 4))
# endif
	{
		register u_short bo;

		bo = ip->ip_len;
		ip->ip_len = htons(bo);
		bo = ip->ip_off;
		ip->ip_off = htons(bo);
	}
#endif
#if SOLARIS && defined(_KERNEL)
	COPYIFNAME(fin->fin_ifp, fra->fra_info.fin_ifname);
	m->b_rptr -= qpi->qpi_off;
	ipf_auth_pkts[i] = *(mblk_t **)fin->fin_mp;
	fra->fra_q = qpi->qpi_q;	/* The queue can disappear! */
	fra->fra_m = *fin->fin_mp;
	fra->fra_info.fin_mp = &fra->fra_m;
	cv_signal(&ipf_auth_wait);
	pollwakeup(&ipf_poll_head[IPL_LOGAUTH], POLLIN|POLLRDNORM);
#else
	ipf_auth_pkts[i] = m;
	WAKEUP(&ipf_auth_next,0);
#endif
	return 1;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_auth_ioctl                                              */
/* Returns:     int - 0 == success, else error                              */
/* Parameters:  data(IO) - pointer to ioctl data                            */
/*              cmd(I)   - ioctl command                                    */
/*              mode(I)  - mode flags associated with open descriptor       */
/*              uid(I)   - uid associatd with application making the call   */
/*              ctx(I)   - pointer for context                              */
/*                                                                          */
/* This function handles all of the ioctls recognised by the auth component */
/* in IPFilter - ie ioctls called on an open fd for /dev/ipf_auth_ip        */
/* ------------------------------------------------------------------------ */
int
ipf_auth_ioctl(data, cmd, mode, uid, ctx)
	caddr_t data;
	ioctlcmd_t cmd;
	int mode, uid;
	void *ctx;
{
	int error = 0, i;
	SPL_INT(s);

	switch (cmd)
	{
	case SIOCGENITER :
	    {
		ipftoken_t *token;
		ipfgeniter_t iter;

		error = ipf_inobj(data, &iter, IPFOBJ_GENITER);
		if (error != 0)
			break;

		SPL_SCHED(s);
		token = ipf_findtoken(IPFGENITER_AUTH, uid, ctx);
		if (token != NULL)
			error = ipf_auth_geniter(token, &iter);
		else {
			ipf_interror = 10001;
			error = ESRCH;
		}
		RWLOCK_EXIT(&ipf_tokens);
		SPL_X(s);

		break;
	    }

	case SIOCADAFR :
	case SIOCRMAFR :
		if (!(mode & FWRITE)) {
			ipf_interror = 10002;
			error = EPERM;
		} else
			error = frrequest(IPL_LOGAUTH, cmd, data,
					  ipf_active, 1);
		break;

	case SIOCSTLCK :
		if (!(mode & FWRITE)) {
			ipf_interror = 10003;
			error = EPERM;
		} else {
			error = ipf_lock(data, &ipf_auth_lock);
		}
		break;

	case SIOCATHST:
		ipf_auth_stats.fas_faelist = ipf_auth_entries;
		error = ipf_outobj(data, &ipf_auth_stats, IPFOBJ_AUTHSTAT);
		break;

	case SIOCIPFFL:
		SPL_NET(s);
		WRITE_ENTER(&ipf_authlk);
		i = ipf_auth_flush();
		RWLOCK_EXIT(&ipf_authlk);
		SPL_X(s);
		error = BCOPYOUT(&i, data, sizeof(i));
		if (error != 0) {
			ipf_interror = 10004;
			error = EFAULT;
		}
		break;

	case SIOCAUTHW:
		error = ipf_auth_wait(data);
		break;

	case SIOCAUTHR:
		error = ipf_auth_reply(data);
		break;

	default :
		ipf_interror = 10005;
		error = EINVAL;
		break;
	}
	return error;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_auth_unload                                             */
/* Returns:     None                                                        */
/* Parameters:  None                                                        */
/*                                                                          */
/* Free all network buffer memory used to keep saved packets.               */
/* ------------------------------------------------------------------------ */
void
ipf_auth_unload()
{
	register int i;
	register frauthent_t *fae, **faep;
	frentry_t *fr, **frp;
	mb_t *m;

	if (ipf_auth != NULL) {
		KFREES(ipf_auth, ipf_auth_size * sizeof(*ipf_authlk));
		ipf_auth = NULL;
	}

	if (ipf_auth_pkts != NULL) {
		for (i = 0; i < ipf_auth_size; i++) {
			m = ipf_auth_pkts[i];
			if (m != NULL) {
				FREE_MB_T(m);
				ipf_auth_pkts[i] = NULL;
			}
		}
		KFREES(ipf_auth_pkts, ipf_auth_size * sizeof(*ipf_auth_pkts));
		ipf_auth_pkts = NULL;
	}

	faep = &ipf_auth_entries;
	while ((fae = *faep) != NULL) {
		*faep = fae->fae_next;
		KFREE(fae);
	}
	ipf_auth_ip = NULL;

	if (ipf_auth_rules != NULL) {
		for (frp = &ipf_auth_rules; ((fr = *frp) != NULL); ) {
			if (fr->fr_ref == 1) {
				*frp = fr->fr_next;
				KFREE(fr);
			} else
				frp = &fr->fr_next;
		}
	}

	if (ipf_auth_inited == 1) {
# if SOLARIS && defined(_KERNEL)
		cv_destroy(&ipf_auth_wait);
# endif
		MUTEX_DESTROY(&ipf_auth_mx);
		RW_DESTROY(&ipf_authlk);

		ipf_auth_inited = 0;
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_auth_expire                                             */
/* Returns:     None                                                        */
/* Parameters:  None                                                        */
/*                                                                          */
/* Slowly expire held auth records.  Timeouts are set in expectation of     */
/* this being called twice per second.                                      */
/* ------------------------------------------------------------------------ */
void
ipf_auth_expire()
{
	frauthent_t *fae, **faep;
	frentry_t *fr, **frp;
	frauth_t *fra;
	mb_t *m;
	int i;
	SPL_INT(s);

	if (ipf_auth_lock)
		return;

	SPL_NET(s);
	WRITE_ENTER(&ipf_authlk);
	for (i = 0, fra = ipf_auth; i < ipf_auth_size; i++, fra++) {
		fra->fra_age--;
		if ((fra->fra_age == 0) && (m = ipf_auth_pkts[i])) {
			FREE_MB_T(m);
			ipf_auth_pkts[i] = NULL;
			ipf_auth[i].fra_index = -1;
			ipf_auth_stats.fas_expire++;
			ipf_auth_used--;
		}
	}

	/*
	 * Expire pre-auth rules
	 */
	for (faep = &ipf_auth_entries; ((fae = *faep) != NULL); ) {
		fae->fae_age--;
		if (fae->fae_age == 0) {
			ipf_auth_deref(&fae);
			ipf_auth_stats.fas_expire++;
		} else
			faep = &fae->fae_next;
	}
	if (ipf_auth_entries != NULL)
		ipf_auth_ip = &ipf_auth_entries->fae_fr;
	else
		ipf_auth_ip = NULL;

	for (frp = &ipf_auth_rules; ((fr = *frp) != NULL); ) {
		if (fr->fr_ref == 1) {
			*frp = fr->fr_next;
			KFREE(fr);
		} else
			frp = &fr->fr_next;
	}
	RWLOCK_EXIT(&ipf_authlk);
	SPL_X(s);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_auth_precmd                                             */
/* Returns:     int - 0 == success, else error                              */
/* Parameters:  cmd(I)  - ioctl command for rule                            */
/*              fr(I)   - pointer to ipf rule                               */
/*              fptr(I) - pointer to caller's 'fr'                          */
/*                                                                          */
/* ------------------------------------------------------------------------ */
int
ipf_auth_precmd(cmd, fr, frptr)
	ioctlcmd_t cmd;
	frentry_t *fr, **frptr;
{
	frauthent_t *fae, **faep;
	int error = 0;
	SPL_INT(s);

	if ((cmd != SIOCADAFR) && (cmd != SIOCRMAFR)) {
		ipf_interror = 10006;
		return EIO;
	}

	for (faep = &ipf_auth_entries; ((fae = *faep) != NULL); ) {
		if (&fae->fae_fr == fr)
			break;
		else
			faep = &fae->fae_next;
	}

	if (cmd == (ioctlcmd_t)SIOCRMAFR) {
		if (fr == NULL || frptr == NULL) {
			ipf_interror = 10007;
			error = EINVAL;

		} else if (fae == NULL) {
			ipf_interror = 10008;
			error = ESRCH;

		} else {
			SPL_NET(s);
			WRITE_ENTER(&ipf_authlk);
			*faep = fae->fae_next;
			if (ipf_auth_ip == &fae->fae_fr)
				ipf_auth_ip = ipf_auth_entries ?
					      &ipf_auth_entries->fae_fr : NULL;
			RWLOCK_EXIT(&ipf_authlk);
			SPL_X(s);

			KFREE(fae);
		}
	} else if (fr != NULL && frptr != NULL) {
		KMALLOC(fae, frauthent_t *);
		if (fae != NULL) {
			bcopy((char *)fr, (char *)&fae->fae_fr,
			      sizeof(*fr));
			SPL_NET(s);
			WRITE_ENTER(&ipf_authlk);
			fae->fae_age = ipf_auth_defaultage;
			fae->fae_fr.fr_hits = 0;
			fae->fae_fr.fr_next = *frptr;
			fae->fae_ref = 1;
			*frptr = &fae->fae_fr;
			fae->fae_next = *faep;
			*faep = fae;
			ipf_auth_ip = &ipf_auth_entries->fae_fr;
			RWLOCK_EXIT(&ipf_authlk);
			SPL_X(s);
		} else {
			ipf_interror = 10009;
			error = ENOMEM;
		}
	} else {
		ipf_interror = 10010;
		error = EINVAL;
	}
	return error;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_auth_flush                                              */
/* Returns:     int - number of auth entries flushed                        */
/* Parameters:  None                                                        */
/* Locks:       WRITE(ipf_authlk)                                           */
/*                                                                          */
/* This function flushs the ipf_auth_pkts array of any packet data with     */
/* references still there.                                                  */
/* It is expected that the caller has already acquired the correct locks or */
/* set the priority level correctly for this to block out other code paths  */
/* into these data structures.                                              */
/* ------------------------------------------------------------------------ */
int
ipf_auth_flush()
{
	register int i, num_flushed;
	mb_t *m;

	if (ipf_auth_lock)
		return -1;

	num_flushed = 0;

	for (i = 0 ; i < ipf_auth_size; i++) {
		m = ipf_auth_pkts[i];
		if (m != NULL) {
			FREE_MB_T(m);
			ipf_auth_pkts[i] = NULL;
			ipf_auth[i].fra_index = -1;
			/* perhaps add & use a flush counter inst.*/
			ipf_auth_stats.fas_expire++;
			ipf_auth_used--;
			num_flushed++;
		}
	}

	ipf_auth_start = 0;
	ipf_auth_end = 0;
	ipf_auth_next = 0;

	return num_flushed;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_auth_waiting                                            */
/* Returns:     int - number of packets in the auth queue                   */
/* Parameters:  None                                                        */
/*                                                                          */
/* Simple truth check to see if there are any packets waiting in the auth   */
/* queue.                                                                   */
/* ------------------------------------------------------------------------ */
int
ipf_auth_waiting()
{
	return (ipf_auth_used != 0);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_auth_geniter                                            */
/* Returns:     int - 0 == success, else error                              */
/* Parameters:  token(I) - pointer to ipftoken structure                    */
/*              itp(I)   - pointer to ipfgeniter structure                  */
/*                                                                          */
/* ------------------------------------------------------------------------ */
int
ipf_auth_geniter(token, itp)
	ipftoken_t *token;
	ipfgeniter_t *itp;
{
	frauthent_t *fae, *next, zero;
	int error;

	if (itp->igi_data == NULL) {
		ipf_interror = 10011;
		return EFAULT;
	}

	if (itp->igi_type != IPFGENITER_AUTH)
		ipf_interror = 10012;
		return EINVAL;

	fae = token->ipt_data;
	READ_ENTER(&ipf_authlk);
	if (fae == NULL) {
		next = ipf_auth_entries;
	} else {
		next = fae->fae_next;
	}

	if (next != NULL) {
		/*
		 * If we find an auth entry to use, bump its reference count
		 * so that it can be used for is_next when we come back.
		 */
		ATOMIC_INC(next->fae_ref);
		if (next->fae_next == NULL) {
			ipf_freetoken(token);
			token = NULL;
		} else {
			token->ipt_data = next;
		}
	} else {
		bzero(&zero, sizeof(zero));
		next = &zero;
	}
	RWLOCK_EXIT(&ipf_authlk);

	/*
	 * If we had a prior pointer to an auth entry, release it.
	 */
	if (fae != NULL) {
		WRITE_ENTER(&ipf_authlk);
		ipf_auth_deref(&fae);
		RWLOCK_EXIT(&ipf_authlk);
	}

	/*
	 * This should arguably be via ipf_outobj() so that the auth
	 * structure can (if required) be massaged going out.
	 */
	error = COPYOUT(next, itp->igi_data, sizeof(*next));
	if (error != 0) {
		ipf_interror = 10013;
		error = EFAULT;
	}

	return error;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_auth_deref                                              */
/* Returns:     None                                                        */
/* Parameters:  faep(IO) - pointer to caller's frauthent_t pointer          */
/* Locks:       WRITE(ipf_authlk)                                           */
/*                                                                          */
/* This function unconditionally sets the pointer in the caller to NULL,    */
/* to make it clear that it should no longer use that pointer, and drops    */
/* the reference count on the structure by 1.  If it reaches 0, free it up. */
/* ------------------------------------------------------------------------ */
void
ipf_auth_deref(faep)
	frauthent_t **faep;
{
	frauthent_t *fae;

	fae = *faep;
	*faep = NULL;

	fae->fae_ref--;
	if (fae->fae_ref == 0) {
		KFREE(fae);
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_auth_wait                                               */
/* Returns:     int - 0 == success, else error                              */
/* Parameters:  data(I) - pointer to data from ioctl call                   */
/*                                                                          */
/* This function is called when an application is waiting for a packet to   */
/* match an "auth" rule by issuing an SIOCAUTHW ioctl.  If there is already */
/* a packet waiting on the queue then we will return that _one_ immediately.*/
/* If there are no packets present in the queue (ipf_auth_pkts) then we go  */
/* to sleep.                                                                */
/* ------------------------------------------------------------------------ */
int
ipf_auth_wait(data)
	char *data;
{
	frauth_t auth, *au = &auth;
	int error, len, i;
	mb_t *m;
	char *t;
	SPL_INT(s);

ipf_auth_ioctlloop:
	error = ipf_inobj(data, au, IPFOBJ_FRAUTH);
	if (error != 0)
		return error;

	/*
	 * XXX Locks are held below over calls to copyout...a better
	 * solution needs to be found so this isn't necessary.  The situation
	 * we are trying to guard against here is an error in the copyout
	 * steps should not cause the packet to "disappear" from the queue.
	 */
	READ_ENTER(&ipf_authlk);

	/*
	 * If ipf_auth_next is not equal to ipf_auth_end it will be because
	 * there is a packet waiting to be delt with in the ipf_auth_pkts
	 * array.  We copy as much of that out to user space as requested.
	 */
	if (ipf_auth_used > 0) {
		while (ipf_auth_pkts[ipf_auth_next] == NULL) {
			ipf_auth_next++;
			if (ipf_auth_next == ipf_auth_size)
				ipf_auth_next = 0;
		}

		error = ipf_outobj(data, &ipf_auth[ipf_auth_next],
				   IPFOBJ_FRAUTH);
		if (error != 0)
			return error;

		if (auth.fra_len != 0 && auth.fra_buf != NULL) {
			/*
			 * Copy packet contents out to user space if
			 * requested.  Bail on an error.
			 */
			m = ipf_auth_pkts[ipf_auth_next];
			len = MSGDSIZE(m);
			if (len > auth.fra_len)
				len = auth.fra_len;
			auth.fra_len = len;

			for (t = auth.fra_buf; m && (len > 0); ) {
				i = MIN(M_LEN(m), len);
				error = copyoutptr(MTOD(m, char *), &t, i);
				len -= i;
				t += i;
				if (error != 0)
					return error;
				m = m->m_next;
			}
		}
		RWLOCK_EXIT(&ipf_authlk);

		SPL_NET(s);
		WRITE_ENTER(&ipf_authlk);
		ipf_auth_next++;
		if (ipf_auth_next == ipf_auth_size)
			ipf_auth_next = 0;
		RWLOCK_EXIT(&ipf_authlk);
		SPL_X(s);

		return 0;
	}
	RWLOCK_EXIT(&ipf_authlk);

	/*
	 * We exit ipf_global here because a program that enters in
	 * here will have a lock on it and goto sleep having this lock.
	 * If someone were to do an 'ipf -D' the system would then
	 * deadlock.  The catch with releasing it here is that the
	 * caller of this function expects it to be held when we
	 * return so we have to reacquire it in here.
	 */
	RWLOCK_EXIT(&ipf_global);

	MUTEX_ENTER(&ipf_auth_mx);
#ifdef	_KERNEL
# if	SOLARIS
	error = 0;
	if (!cv_wait_sig(&ipf_auth_wait, &ipf_auth_mx.ipf_lk)) {
		ipf_interror = 10014;
		error = EINTR;
	}
# else /* SOLARIS */
#  ifdef __hpux
	{
	lock_t *l;

	l = get_sleep_lock(&ipf_auth_next);
	error = sleep(&ipf_auth_next, PZERO+1);
	spinunlock(l);
	}
#  else
#   ifdef __osf__
	error = mpsleep(&ipf_auth_next, PSUSP|PCATCH, "ipf_auth_next", 0,
			&ipf_auth_mx, MS_LOCK_SIMPLE);
#   else
	error = SLEEP(&ipf_auth_next, "ipf_auth_next");
#   endif /* __osf__ */
#  endif /* __hpux */
# endif /* SOLARIS */
#endif
	MUTEX_EXIT(&ipf_auth_mx);
	READ_ENTER(&ipf_global);
	if (error == 0)
		goto ipf_auth_ioctlloop;
	return error;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_auth_reply                                              */
/* Returns:     int - 0 == success, else error                              */
/* Parameters:  data(I) - pointer to data from ioctl call                   */
/*                                                                          */
/* This function is called by an application when it wants to return a      */
/* decision on a packet using the SIOCAUTHR ioctl.  This is after it has    */
/* received information using an SIOCAUTHW.  The decision returned in the   */
/* form of flags, the same as those used in each rule.                      */
/* ------------------------------------------------------------------------ */
int
ipf_auth_reply(data)
	char *data;
{
	frauth_t auth, *au = &auth, *fra;
	int error, i;
	mb_t *m;
	SPL_INT(s);

	error = ipf_inobj(data, &auth, IPFOBJ_FRAUTH);
	if (error != 0)
		return error;

	SPL_NET(s);
	WRITE_ENTER(&ipf_authlk);

	i = au->fra_index;
	fra = ipf_auth + i;
	error = 0;

	/*
	 * Check the validity of the information being returned with two simple
	 * checks.  First, the auth index value should be within the size of
	 * the array and second the packet id being returned should also match.
	 */
	if ((i < 0) || (i >= ipf_auth_size)) {
		RWLOCK_EXIT(&ipf_authlk);
		SPL_X(s);
		ipf_interror = 10015;
		return ESRCH;
	}
	if  (fra->fra_info.fin_id != au->fra_info.fin_id) {
		RWLOCK_EXIT(&ipf_authlk);
		SPL_X(s);
		ipf_interror = 10019;
		return ESRCH;
	}

	m = ipf_auth_pkts[i];
	fra->fra_index = -2;
	fra->fra_pass = au->fra_pass;
	ipf_auth_pkts[i] = NULL;

	RWLOCK_EXIT(&ipf_authlk);

	/*
	 * Re-insert the packet back into the packet stream flowing through
	 * the kernel in a manner that will mean IPFilter sees the packet
	 * again.  This is not the same as is done with fastroute,
	 * deliberately, as we want to resume the normal packet processing
	 * path for it.
	 */
#ifdef	_KERNEL
	if ((m != NULL) && (au->fra_info.fin_out != 0)) {
		error = ipf_inject(&fra->fra_info, m);
		if (error != 0) {
			ipf_interror = 10016;
			error = ENOBUFS;
			ipf_auth_stats.fas_sendfail++;
		} else {
			ipf_auth_stats.fas_sendok++;
		}
	} else if (m) {
		error = ipf_inject(&fra->fra_info, m);
		if (error != 0) {
			ipf_interror = 10017;
			error = ENOBUFS;
			ipf_auth_stats.fas_quefail++;
		} else {
			ipf_auth_stats.fas_queok++;
		}
	} else {
		ipf_interror = 10018;
		error = EINVAL;
	}

	/*
	 * If we experience an error which will result in the packet
	 * not being processed, make sure we advance to the next one.
	 */
	if (error == ENOBUFS) {
		ipf_auth_used--;
		fra->fra_index = -1;
		fra->fra_pass = 0;
		if (i == ipf_auth_start) {
			while (fra->fra_index == -1) {
				i++;
				if (i == ipf_auth_size)
					i = 0;
				ipf_auth_start = i;
				if (i == ipf_auth_end)
					break;
			}
			if (ipf_auth_start == ipf_auth_end) {
				ipf_auth_next = 0;
				ipf_auth_start = ipf_auth_end = 0;
			}
		}
	}
#endif /* _KERNEL */
	SPL_X(s);

	return 0;
}
