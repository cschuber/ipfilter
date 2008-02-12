/*
 * Copyright (C) 1995-1998 by Darren Reed.
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
#include <sys/file.h>
#if !defined(_KERNEL) && !defined(__KERNEL__)
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# define _KERNEL
# define KERNEL
# ifdef __OpenBSD__
struct file;
# endif
# include <sys/uio.h>
# undef _KERNEL
# undef KERNEL
#else
# include <sys/systm.h>
# if !defined(__SVR4) && !defined(__svr4__)
#  include <sys/mbuf.h>
# endif
# include <sys/select.h>
# if __FreeBSD_version >= 500000
#  include <sys/selinfo.h>
# endif
#endif
#if defined(__NetBSD__) && (__NetBSD_Version__ >= 104000000)
# include <sys/proc.h>
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
#include "netinet/ip_sync.h"
#ifdef  USE_INET6
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
static const char rcsid[] = "@(#)$Id$";
#endif

#define	SYNC_STATETABSZ	256
#define	SYNC_NATTABSZ	256

#ifdef	IPFILTER_SYNC
# if SOLARIS && defined(_KERNEL)
extern	struct pollhead	ipf_poll_head[IPL_LOGSIZE];
# endif 

ipfmutex_t	ipf_syncadd, ipsl_mutex;
ipfrwlock_t	ipf_syncstate, ipf_syncnat;
#if SOLARIS && defined(_KERNEL)
kcondvar_t	ipslwait;
#endif
synclist_t	**syncstatetab;
synclist_t	**syncnattab;
synclogent_t	*synclog;
syncupdent_t	*syncupd;
u_int		ipf_sync_num;
u_int		ipf_sync_wrap;
u_int		sl_idx;			/* next available sync log entry */
u_int		su_idx;			/* next available sync update entry */
u_int		sl_tail;		/* next sync log entry to read */
u_int		su_tail;		/* next sync update entry to read */
int		ipf_sync_log_sz = SYNCLOG_SZ;
int		ipf_sync_nat_tab_sz = SYNC_STATETABSZ;
int		ipf_sync_state_tab_sz = SYNC_STATETABSZ;
int		ipf_sync_debug = 0;
int		ipf_sync_events;
u_32_t		ipf_sync_lastwakeup;
int		ipf_sync_wake_interval = 0;
int		ipf_sync_event_high_wm = SYNCLOG_SZ * 100 / 90;	/* 90% */
int		ipf_sync_queue_high_wm = SYNCLOG_SZ * 100 / 90;	/* 90% */
int		ipf_sync_inited = 0;


static int ipf_sync_flush_table __P((int, synclist_t **));
static void ipf_sync_wakeup __P((void));
static void ipf_sync_del __P((synclist_t *));
static void ipf_sync_poll_wakeup __P((void));

# if !defined(sparc) && !defined(__hppa)
void ipf_sync_tcporder __P((int, struct tcpdata *));
void ipf_sync_natorder __P((int, struct nat *));
void ipf_sync_storder __P((int, struct ipstate *));
# endif


/* ------------------------------------------------------------------------ */
/* Function:    ipf_sync_init                                               */
/* Returns:     int - 0 == success, -1 == failure                           */
/* Parameters:  Nil                                                         */
/*                                                                          */
/* Initialise all of the locks required for the sync code and initialise    */
/* any data structures, as required.                                        */
/* ------------------------------------------------------------------------ */
int
ipf_sync_init()
{

# if SOLARIS && defined(_KERNEL)
	cv_init(&ipslwait, "ipsl condvar", CV_DRIVER, NULL);
# endif

	KMALLOCS(synclog, synclogent_t *, ipf_sync_log_sz * sizeof(*synclog));
	if (synclog == NULL)
		return -1;

	KMALLOCS(syncupd, syncupdent_t *, ipf_sync_log_sz * sizeof(*syncupd));
	if (syncupd == NULL)
		return -2;

	KMALLOCS(syncstatetab, synclist_t **,
		 ipf_sync_state_tab_sz * sizeof(*syncstatetab));
	if (syncstatetab == NULL)
		return -3;
	bzero((char *)syncstatetab, 
	      ipf_sync_state_tab_sz * sizeof(*syncstatetab));

	KMALLOCS(syncnattab, synclist_t **,
		 ipf_sync_nat_tab_sz * sizeof(*syncnattab));
	if (syncnattab == NULL)
		return -3;
	bzero((char *)syncnattab, ipf_sync_nat_tab_sz * sizeof(*syncnattab));

	ipf_sync_num = 1;
	ipf_sync_wrap = 0;
	sl_idx = 0;
	su_idx = 0;
	sl_tail = 0;
	su_tail = 0;
	ipf_sync_events = 0;
	ipf_sync_lastwakeup = 0;

	RWLOCK_INIT(&ipf_syncstate, "add things to state sync table");
	RWLOCK_INIT(&ipf_syncnat, "add things to nat sync table");
	MUTEX_INIT(&ipf_syncadd, "add things to sync table");
	MUTEX_INIT(&ipsl_mutex, "read ring lock");

	ipf_sync_inited = 1;

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_sync_unload                                             */
/* Returns:     int - 0 == success, -1 == failure                           */
/* Parameters:  Nil                                                         */
/*                                                                          */
/* Destroy the locks created when initialising and free any memory in use   */
/* with the synchronisation tables.                                         */
/* ------------------------------------------------------------------------ */
int
ipf_sync_unload()
{

	if (syncnattab != NULL) {
		ipf_sync_flush_table(ipf_sync_nat_tab_sz, syncnattab);
		KFREES(syncnattab, ipf_sync_nat_tab_sz * sizeof(*syncnattab));
		syncnattab = NULL;
	}

	if (syncstatetab != NULL) {
		ipf_sync_flush_table(ipf_sync_state_tab_sz, syncstatetab);
		KFREES(syncstatetab,
		       ipf_sync_state_tab_sz * sizeof(*syncstatetab));
		syncstatetab = NULL;
	}

	if (syncupd != NULL) {
		KFREES(syncupd, ipf_sync_log_sz * sizeof(*syncupd));
		syncupd = NULL;
	}

	if (synclog != NULL) {
		KFREES(synclog, ipf_sync_log_sz * sizeof(*synclog));
		synclog = NULL;
	}

	if (ipf_sync_inited == 1) {
		MUTEX_DESTROY(&ipsl_mutex);
		MUTEX_DESTROY(&ipf_syncadd);
		RW_DESTROY(&ipf_syncnat);
		RW_DESTROY(&ipf_syncstate);
		ipf_sync_inited = 0;
	}

	return 0;
}


# if !defined(sparc) && !defined(__hppa)
/* ------------------------------------------------------------------------ */
/* Function:    ipf_sync_tcporder                                           */
/* Returns:     Nil                                                         */
/* Parameters:  way(I) - direction of byte order conversion.                */
/*              td(IO) - pointer to data to be converted.                   */
/*                                                                          */
/* Do byte swapping on values in the TCP state information structure that   */
/* need to be used at both ends by the host in their native byte order.     */
/* ------------------------------------------------------------------------ */
void
ipf_sync_tcporder(way, td)
	int way;
	tcpdata_t *td;
{
	if (way) {
		td->td_maxwin = htons(td->td_maxwin);
		td->td_end = htonl(td->td_end);
		td->td_maxend = htonl(td->td_maxend);
	} else {
		td->td_maxwin = ntohs(td->td_maxwin);
		td->td_end = ntohl(td->td_end);
		td->td_maxend = ntohl(td->td_maxend);
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_sync_natorder                                           */
/* Returns:     Nil                                                         */
/* Parameters:  way(I)  - direction of byte order conversion.               */
/*              nat(IO) - pointer to data to be converted.                  */
/*                                                                          */
/* Do byte swapping on values in the NAT data structure that need to be     */
/* used at both ends by the host in their native byte order.                */
/* ------------------------------------------------------------------------ */
void
ipf_sync_natorder(way, n)
	int way;
	nat_t *n;
{
	if (way) {
		n->nat_age = htonl(n->nat_age);
		n->nat_flags = htonl(n->nat_flags);
		n->nat_ipsumd = htonl(n->nat_ipsumd);
		n->nat_use = htonl(n->nat_use);
		n->nat_dir = htonl(n->nat_dir);
	} else {
		n->nat_age = ntohl(n->nat_age);
		n->nat_flags = ntohl(n->nat_flags);
		n->nat_ipsumd = ntohl(n->nat_ipsumd);
		n->nat_use = ntohl(n->nat_use);
		n->nat_dir = ntohl(n->nat_dir);
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_sync_storder                                            */
/* Returns:     Nil                                                         */
/* Parameters:  way(I)  - direction of byte order conversion.               */
/*              ips(IO) - pointer to data to be converted.                  */
/*                                                                          */
/* Do byte swapping on values in the IP state data structure that need to   */
/* be used at both ends by the host in their native byte order.             */
/* ------------------------------------------------------------------------ */
void
ipf_sync_storder(way, ips)
	int way;
	ipstate_t *ips;
{
	ipf_sync_tcporder(way, &ips->is_tcp.ts_data[0]);
	ipf_sync_tcporder(way, &ips->is_tcp.ts_data[1]);

	if (way) {
		ips->is_hv = htonl(ips->is_hv);
		ips->is_die = htonl(ips->is_die);
		ips->is_pass = htonl(ips->is_pass);
		ips->is_flags = htonl(ips->is_flags);
		ips->is_opt[0] = htonl(ips->is_opt[0]);
		ips->is_opt[1] = htonl(ips->is_opt[1]);
		ips->is_optmsk[0] = htonl(ips->is_optmsk[0]);
		ips->is_optmsk[1] = htonl(ips->is_optmsk[1]);
		ips->is_sec = htons(ips->is_sec);
		ips->is_secmsk = htons(ips->is_secmsk);
		ips->is_auth = htons(ips->is_auth);
		ips->is_authmsk = htons(ips->is_authmsk);
		ips->is_s0[0] = htonl(ips->is_s0[0]);
		ips->is_s0[1] = htonl(ips->is_s0[1]);
		ips->is_smsk[0] = htons(ips->is_smsk[0]);
		ips->is_smsk[1] = htons(ips->is_smsk[1]);
	} else {
		ips->is_hv = ntohl(ips->is_hv);
		ips->is_die = ntohl(ips->is_die);
		ips->is_pass = ntohl(ips->is_pass);
		ips->is_flags = ntohl(ips->is_flags);
		ips->is_opt[0] = ntohl(ips->is_opt[0]);
		ips->is_opt[1] = ntohl(ips->is_opt[1]);
		ips->is_optmsk[0] = ntohl(ips->is_optmsk[0]);
		ips->is_optmsk[1] = ntohl(ips->is_optmsk[1]);
		ips->is_sec = ntohs(ips->is_sec);
		ips->is_secmsk = ntohs(ips->is_secmsk);
		ips->is_auth = ntohs(ips->is_auth);
		ips->is_authmsk = ntohs(ips->is_authmsk);
		ips->is_s0[0] = ntohl(ips->is_s0[0]);
		ips->is_s0[1] = ntohl(ips->is_s0[1]);
		ips->is_smsk[0] = ntohl(ips->is_smsk[0]);
		ips->is_smsk[1] = ntohl(ips->is_smsk[1]);
	}
}
# else /* !defined(sparc) && !defined(__hppa) */
#  define	ipf_sync_tcporder(x,y)
#  define	ipf_sync_natorder(x,y)
#  define	ipf_sync_storder(x,y)
# endif /* !defined(sparc) && !defined(__hppa) */

# ifdef _KERNEL
/* ------------------------------------------------------------------------ */
/* Function:    ipf_sync_write                                              */
/* Returns:     int    - 0 == success, else error value.                    */
/* Parameters:  uio(I) - pointer to information about data to write         */
/*                                                                          */
/* Moves data from user space into the kernel and uses it for updating data */
/* structures in the state/NAT tables.                                      */
/* ------------------------------------------------------------------------ */
int
ipf_sync_write(uio)
	struct uio *uio;
{
	synchdr_t sh;

	/*
	 * THIS MUST BE SUFFICIENT LARGE TO STORE
	 * ANY POSSIBLE DATA TYPE
	 */
	char data[2048];

	int err = 0;

#  if (BSD >= 199306) || defined(__FreeBSD__) || defined(__osf__)
	uio->uio_rw = UIO_WRITE;
#  endif

	/* Try to get bytes */
	while (uio->uio_resid > 0) {

		if (uio->uio_resid >= sizeof(sh)) {

			err = UIOMOVE(&sh, sizeof(sh), UIO_WRITE, uio);

			if (err) {
				if (ipf_sync_debug > 2)
					printf("uiomove(header) failed: %d\n",
						err);
				return err;
			}

			/* convert to host order */
			sh.sm_magic = ntohl(sh.sm_magic);
			sh.sm_len = ntohl(sh.sm_len);
			sh.sm_num = ntohl(sh.sm_num);

			if (ipf_sync_debug > 8)
				printf("[%d] Read v:%d p:%d cmd:%d table:%d rev:%d len:%d magic:%x\n",
					sh.sm_num, sh.sm_v, sh.sm_p, sh.sm_cmd,
					sh.sm_table, sh.sm_rev, sh.sm_len,
					sh.sm_magic);

			if (sh.sm_magic != SYNHDRMAGIC) {
				if (ipf_sync_debug > 2)
					printf("uiomove(header) invalid %s\n",
						"magic");
				ipf_interror = 110001;
				return EINVAL;
			}

			if (sh.sm_v != 4 && sh.sm_v != 6) {
				if (ipf_sync_debug > 2)
					printf("uiomove(header) invalid %s\n",
						"protocol");
				ipf_interror = 110002;
				return EINVAL;
			}

			if (sh.sm_cmd > SMC_MAXCMD) {
				if (ipf_sync_debug > 2)
					printf("uiomove(header) invalid %s\n",
						"command");
				ipf_interror = 110003;
				return EINVAL;
			}


			if (sh.sm_table > SMC_MAXTBL) {
				if (ipf_sync_debug > 2)
					printf("uiomove(header) invalid %s\n",
						"table");
				ipf_interror = 110004;
				return EINVAL;
			}

		} else {
			/* unsufficient data, wait until next call */
			if (ipf_sync_debug > 2)
				printf("uiomove(header) insufficient data");
			ipf_interror = 110005;
			return EAGAIN;
	 	}


		/*
		 * We have a header, so try to read the amount of data
		 * needed for the request
		 */

		/* not supported */
		if (sh.sm_len == 0) {
			if (ipf_sync_debug > 2)
				printf("uiomove(data zero length %s\n",
					"not supported");
			ipf_interror = 110006;
			return EINVAL;
		}

		if (uio->uio_resid >= sh.sm_len) {

			err = UIOMOVE(data, sh.sm_len, UIO_WRITE, uio);

			if (err) {
				if (ipf_sync_debug > 2)
					printf("uiomove(data) failed: %d\n",
						err);
				return err;
			}

			if (ipf_sync_debug > 7)
				printf("uiomove(data) %d bytes read\n",
					sh.sm_len);

			if (sh.sm_table == SMC_STATE)
				err = ipf_sync_state(&sh, data);
			else if (sh.sm_table == SMC_NAT)
				err = ipf_sync_nat(&sh, data);
			if (ipf_sync_debug > 7)
				printf("[%d] Finished with error %d\n",
					sh.sm_num, err);

		} else {
			/* insufficient data, wait until next call */
			if (ipf_sync_debug > 2)
				printf("uiomove(data) %s %d bytes, got %d\n",
					"insufficient data, need",
					sh.sm_len, uio->uio_resid);
			ipf_interror = 110007;
			return EAGAIN;
		}
	}

	/* no more data */
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_sync_read                                               */
/* Returns:     int    - 0 == success, else error value.                    */
/* Parameters:  uio(O) - pointer to information about where to store data   */
/*                                                                          */
/* This function is called when a user program wants to read some data      */
/* for pending state/NAT updates.  If no data is available, the caller is   */
/* put to sleep, pending a wakeup from the "lower half" of this code.       */
/* ------------------------------------------------------------------------ */
int
ipf_sync_read(uio)
	struct uio *uio;
{
	syncupdent_t *su;
	synclogent_t *sl;
	int err = 0;

	if ((uio->uio_resid & 3) || (uio->uio_resid < 8)) {
		ipf_interror = 110008;
		return EINVAL;
	}

#  if (BSD >= 199306) || defined(__FreeBSD__) || defined(__osf__)
	uio->uio_rw = UIO_READ;
#  endif

	MUTEX_ENTER(&ipsl_mutex);
	while ((sl_tail == sl_idx) && (su_tail == su_idx)) {
#  if SOLARIS && defined(_KERNEL)
		if (!cv_wait_sig(&ipslwait, &ipsl_mutex)) {
			MUTEX_EXIT(&ipsl_mutex);
			ipf_interror = 110009;
			return EINTR;
		}
#  else
#   ifdef __hpux
		{
		lock_t *l;

		l = get_sleep_lock(&sl_tail);
		err = sleep(&sl_tail, PZERO+1);
		if (err) {
			MUTEX_EXIT(&ipsl_mutex);
			ipf_interror = 110010;
			return EINTR;
		}
		spinunlock(l);
		}
#   else /* __hpux */
#    ifdef __osf__
		err = mpsleep(&sl_tail, PSUSP|PCATCH,  "ipl sleep", 0,
			      &ipsl_mutex, MS_LOCK_SIMPLE);
		if (err) {
			ipf_interror = 110011;
			return EINTR;
		}
#    else
		MUTEX_EXIT(&ipsl_mutex);
		err = SLEEP(&sl_tail, "ipl sleep");
		if (err) {
			ipf_interror = 110012;
			return EINTR;
		}
		MUTEX_ENTER(&ipsl_mutex);
#    endif /* __osf__ */
#   endif /* __hpux */
#  endif /* SOLARIS */
	}

	while ((sl_tail < sl_idx)  && (uio->uio_resid > sizeof(*sl))) {
		sl = synclog + sl_tail++;
		MUTEX_EXIT(&ipsl_mutex);
		err = UIOMOVE(sl, sizeof(*sl), UIO_READ, uio);
		if (err != 0)
			goto goterror;
		MUTEX_ENTER(&ipsl_mutex);
	}

	while ((su_tail < su_idx)  && (uio->uio_resid > sizeof(*su))) {
		su = syncupd + su_tail;
		su_tail++;
		MUTEX_EXIT(&ipsl_mutex);
		err = UIOMOVE(su, sizeof(*su), UIO_READ, uio);
		if (err != 0)
			goto goterror;
		MUTEX_ENTER(&ipsl_mutex);
		if (su->sup_hdr.sm_sl != NULL)
			su->sup_hdr.sm_sl->sl_idx = -1;
	}
	if (sl_tail == sl_idx)
		sl_tail = sl_idx = 0;
	if (su_tail == su_idx)
		su_tail = su_idx = 0;
	MUTEX_EXIT(&ipsl_mutex);
goterror:
	return err;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_sync_state                                              */
/* Returns:     int    - 0 == success, else error value.                    */
/* Parameters:  sp(I)  - pointer to sync packet data header                 */
/*              uio(I) - pointer to user data for further information       */
/*                                                                          */
/* Updates the state table according to information passed in the sync      */
/* header.  As required, more data is fetched from the uio structure but    */
/* varies depending on the contents of the sync header.  This function can  */
/* create a new state entry or update one.  Deletion is left to the state   */
/* structures being timed out correctly.                                    */
/* ------------------------------------------------------------------------ */
int
ipf_sync_state(sp, data)
	synchdr_t *sp;
	void *data;
{
	synctcp_update_t su;
	ipstate_t *is, sn;
	synclist_t *sl;
	frentry_t *fr;
	u_int hv;
	int err = 0;

	hv = sp->sm_num & (ipf_sync_state_tab_sz - 1);

	switch (sp->sm_cmd)
	{
	case SMC_CREATE :

		bcopy(data, &sn, sizeof(sn));
		KMALLOC(is, ipstate_t *);
		if (is == NULL) {
			ipf_interror = 110013;
			err = ENOMEM;
			break;
		}

		KMALLOC(sl, synclist_t *);
		if (sl == NULL) {
			ipf_interror = 110014;
			err = ENOMEM;
			KFREE(is);
			break;
		}

		bzero((char *)is, offsetof(ipstate_t, is_die));
		bcopy((char *)&sn.is_die, (char *)&is->is_die,
		      sizeof(*is) - offsetof(ipstate_t, is_die));
		ipf_sync_storder(0, is);

		/*
		 * We need to find the same rule on the slave as was used on
		 * the master to create this state entry.
		 */
		READ_ENTER(&ipf_mutex);
		fr = ipf_getrulen(IPL_LOGIPF, sn.is_group, sn.is_rulen);
		if (fr != NULL) {
			MUTEX_ENTER(&fr->fr_lock);
			fr->fr_ref++;
			fr->fr_statecnt++;
			MUTEX_EXIT(&fr->fr_lock);
		}
		RWLOCK_EXIT(&ipf_mutex);

		if (ipf_sync_debug > 4)
			printf("[%d] Filter rules = %p\n", sp->sm_num, fr);

		is->is_rule = fr;
		is->is_sync = sl;

		sl->sl_idx = -1;
		sl->sl_ips = is;
		bcopy(sp, &sl->sl_hdr, sizeof(struct synchdr));

		WRITE_ENTER(&ipf_syncstate);
		WRITE_ENTER(&ipf_state);

		sl->sl_pnext = syncstatetab + hv;
		sl->sl_next = syncstatetab[hv];
		if (syncstatetab[hv] != NULL)
			syncstatetab[hv]->sl_pnext = &sl->sl_next;
		syncstatetab[hv] = sl;
		MUTEX_DOWNGRADE(&ipf_syncstate);
		ipf_state_insert(is, sp->sm_rev);
		/*
		 * Do not initialise the interface pointers for the state
		 * entry as the full complement of interface names may not
		 * be present.
		 *
		 * Put this state entry on its timeout queue.
		 */
		/*fr_setstatequeue(is, sp->sm_rev);*/
		break;

	case SMC_UPDATE :
		bcopy(data, &su, sizeof(su));

		if (ipf_sync_debug > 4)
			printf("[%d] Update age %lu state %d/%d \n",
				sp->sm_num, su.stu_age, su.stu_state[0],
				su.stu_state[1]);

		READ_ENTER(&ipf_syncstate);
		for (sl = syncstatetab[hv]; (sl != NULL); sl = sl->sl_next)
			if (sl->sl_hdr.sm_num == sp->sm_num)
				break;
		if (sl == NULL) {
			if (ipf_sync_debug > 1)
				printf("[%d] State not found - can't update\n",
					sp->sm_num);
			RWLOCK_EXIT(&ipf_syncstate);
			ipf_interror = 110015;
			err = ENOENT;
			break;
		}

		READ_ENTER(&ipf_state);

		if (ipf_sync_debug > 6)
			printf("[%d] Data from state v:%d p:%d cmd:%d table:%d rev:%d\n",
				sp->sm_num, sl->sl_hdr.sm_v, sl->sl_hdr.sm_p,
				sl->sl_hdr.sm_cmd, sl->sl_hdr.sm_table,
				sl->sl_hdr.sm_rev);

		is = sl->sl_ips;

		MUTEX_ENTER(&is->is_lock);
		switch (sp->sm_p)
		{
		case IPPROTO_TCP :
			/* XXX FV --- shouldn't we do ntohl/htonl???? XXX */
			is->is_send = su.stu_data[0].td_end;
			is->is_maxsend = su.stu_data[0].td_maxend;
			is->is_maxswin = su.stu_data[0].td_maxwin;
			is->is_state[0] = su.stu_state[0];
			is->is_dend = su.stu_data[1].td_end;
			is->is_maxdend = su.stu_data[1].td_maxend;
			is->is_maxdwin = su.stu_data[1].td_maxwin;
			is->is_state[1] = su.stu_state[1];
			break;
		default :
			break;
		}

		if (ipf_sync_debug > 6)
			printf("[%d] Setting timers for state\n", sp->sm_num);

		ipf_state_setqueue(is, sp->sm_rev);

		MUTEX_EXIT(&is->is_lock);
		break;

	default :
		ipf_interror = 110016;
		err = EINVAL;
		break;
	}

	if (err == 0) {
		RWLOCK_EXIT(&ipf_state);
		RWLOCK_EXIT(&ipf_syncstate);
	}

	if (ipf_sync_debug > 6)
		printf("[%d] Update completed with error %d\n",
			sp->sm_num, err);

	return err;
}
# endif /* _KERNEL */


/* ------------------------------------------------------------------------ */
/* Function:    ipf_sync_del                                                */
/* Returns:     Nil                                                         */
/* Parameters:  sl(I) - pointer to synclist object to delete                */
/*                                                                          */
/* Deletes an object from the synclist.                                     */
/* ------------------------------------------------------------------------ */
static void
ipf_sync_del(sl)
	synclist_t *sl;
{
	*sl->sl_pnext = sl->sl_next;
	if (sl->sl_next != NULL)
		sl->sl_next->sl_pnext = sl->sl_pnext;
	if (sl->sl_idx != -1)
		syncupd[sl->sl_idx].sup_hdr.sm_sl = NULL;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_sync_del_state                                          */
/* Returns:     Nil                                                         */
/* Parameters:  sl(I) - pointer to synclist object to delete                */
/*                                                                          */
/* Deletes an object from the synclist state table and free's its memory.   */
/* ------------------------------------------------------------------------ */
void
ipf_sync_del_state(sl)
	synclist_t *sl;
{
	WRITE_ENTER(&ipf_syncstate);
	ipf_sync_del(sl);
	RWLOCK_EXIT(&ipf_syncstate);
	KFREE(sl);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_sync_del_nat                                            */
/* Returns:     Nil                                                         */
/* Parameters:  sl(I) - pointer to synclist object to delete                */
/*                                                                          */
/* Deletes an object from the synclist nat table and free's its memory.     */
/* ------------------------------------------------------------------------ */
void
ipf_sync_del_nat(sl)
	synclist_t *sl;
{
	WRITE_ENTER(&ipf_syncnat);
	ipf_sync_del(sl);
	RWLOCK_EXIT(&ipf_syncnat);
	KFREE(sl);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_sync_nat                                                */
/* Returns:     int    - 0 == success, else error value.                    */
/* Parameters:  sp(I)  - pointer to sync packet data header                 */
/*              uio(I) - pointer to user data for further information       */
/*                                                                          */
/* Updates the NAT  table according to information passed in the sync       */
/* header.  As required, more data is fetched from the uio structure but    */
/* varies depending on the contents of the sync header.  This function can  */
/* create a new NAT entry or update one.  Deletion is left to the NAT       */
/* structures being timed out correctly.                                    */
/* ------------------------------------------------------------------------ */
int
ipf_sync_nat(sp, data)
	synchdr_t *sp;
	void *data;
{
	syncupdent_t su;
	nat_t *n, *nat;
	synclist_t *sl;
	u_int hv = 0;
	int err;

	READ_ENTER(&ipf_syncnat);

	switch (sp->sm_cmd)
	{
	case SMC_CREATE :
		KMALLOC(n, nat_t *);
		if (n == NULL) {
			ipf_interror = 110017;
			err = ENOMEM;
			break;
		}

		KMALLOC(sl, synclist_t *);
		if (sl == NULL) {
			ipf_interror = 110018;
			err = ENOMEM;
			KFREE(n);
			break;
		}

		nat = (nat_t *)data;
		bzero((char *)n, offsetof(nat_t, nat_age));
		bcopy((char *)&nat->nat_age, (char *)&n->nat_age,
		      sizeof(*n) - offsetof(nat_t, nat_age));
		ipf_sync_natorder(0, n);
		n->nat_sync = sl;

		sl->sl_idx = -1;
		sl->sl_ipn = n;
		sl->sl_num = ntohl(sp->sm_num);

		WRITE_ENTER(&ipf_nat);
		sl->sl_pnext = syncnattab + hv;
		sl->sl_next = syncnattab[hv];
		if (syncnattab[hv] != NULL)
			syncnattab[hv]->sl_pnext = &sl->sl_next;
		syncnattab[hv] = sl;
		ipf_nat_insert(n, sl->sl_rev);
		RWLOCK_EXIT(&ipf_nat);
		break;

	case SMC_UPDATE :
		bcopy(data, &su, sizeof(su));

		READ_ENTER(&ipf_syncnat);
		for (sl = syncnattab[hv]; (sl != NULL); sl = sl->sl_next)
			if (sl->sl_hdr.sm_num == sp->sm_num)
				break;
		if (sl == NULL) {
			ipf_interror = 110019;
			err = ENOENT;
			break;
		}

		READ_ENTER(&ipf_nat);

		nat = sl->sl_ipn;

		MUTEX_ENTER(&nat->nat_lock);
		ipf_nat_setqueue(nat, sl->sl_rev);
		MUTEX_EXIT(&nat->nat_lock);

		RWLOCK_EXIT(&ipf_nat);

		break;

	default :
		ipf_interror = 110020;
		err = EINVAL;
		break;
	}

	RWLOCK_EXIT(&ipf_syncnat);
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_sync_new                                                */
/* Returns:     synclist_t* - NULL == failure, else pointer to new synclist */
/*                            data structure.                               */
/* Parameters:  tab(I) - type of synclist_t to create                       */
/*              fin(I) - pointer to packet information                      */
/*              ptr(I) - pointer to owning object                           */
/*                                                                          */
/* Creates a new sync table entry and notifies any sleepers that it's there */
/* waiting to be processed.                                                 */
/* ------------------------------------------------------------------------ */
synclist_t *
ipf_sync_new(tab, fin, ptr)
	int tab;
	fr_info_t *fin;
	void *ptr;
{
	synclist_t *sl, *ss;
	synclogent_t *sle;
	u_int hv, sz;

	if (sl_idx == ipf_sync_log_sz)
		return NULL;
	KMALLOC(sl, synclist_t *);
	if (sl == NULL)
		return NULL;

	MUTEX_ENTER(&ipf_syncadd);
	/*
	 * Get a unique number for this synclist_t.  The number is only meant
	 * to be unique for the lifetime of the structure and may be reused
	 * later.
	 */
	ipf_sync_num++;
	if (ipf_sync_num == 0) {
		ipf_sync_num = 1;
		ipf_sync_wrap++;
	}

	/*
	 * Use the synch number of the object as the hash key.  Should end up
	 * with relatively even distribution over time.
	 * XXX - an attacker could lunch an DoS attack, of sorts, if they are
	 * the only one causing new table entries by only keeping open every
	 * nth connection they make, where n is a value in the interval
	 * [0, SYNC_STATETABSZ-1].
	 */
	switch (tab)
	{
	case SMC_STATE :
		hv = ipf_sync_num & (ipf_sync_state_tab_sz - 1);
		while (ipf_sync_wrap != 0) {
			for (ss = syncstatetab[hv]; ss; ss = ss->sl_next)
				if (ss->sl_hdr.sm_num == ipf_sync_num)
					break;
			if (ss == NULL)
				break;
			ipf_sync_num++;
			hv = ipf_sync_num & (ipf_sync_state_tab_sz - 1);
		}
		sl->sl_pnext = syncstatetab + hv;
		sl->sl_next = syncstatetab[hv];
		syncstatetab[hv] = sl;
		break;

	case SMC_NAT :
		hv = ipf_sync_num & (ipf_sync_nat_tab_sz - 1);
		while (ipf_sync_wrap != 0) {
			for (ss = syncnattab[hv]; ss; ss = ss->sl_next)
				if (ss->sl_hdr.sm_num == ipf_sync_num)
					break;
			if (ss == NULL)
				break;
			ipf_sync_num++;
			hv = ipf_sync_num & (ipf_sync_nat_tab_sz - 1);
		}
		sl->sl_pnext = syncnattab + hv;
		sl->sl_next = syncnattab[hv];
		syncnattab[hv] = sl;
		break;

	default :
		break;
	}

	sl->sl_num = ipf_sync_num;
	MUTEX_EXIT(&ipf_syncadd);

	sl->sl_magic = htonl(SYNHDRMAGIC);
	sl->sl_v = fin->fin_v;
	sl->sl_p = fin->fin_p;
	sl->sl_cmd = SMC_CREATE;
	sl->sl_idx = -1;
	sl->sl_table = tab;
	sl->sl_rev = fin->fin_rev;
	if (tab == SMC_STATE) {
		sl->sl_ips = ptr;
		sz = sizeof(*sl->sl_ips);
	} else if (tab == SMC_NAT) {
		sl->sl_ipn = ptr;
		sz = sizeof(*sl->sl_ipn);
	} else {
		ptr = NULL;
		sz = 0;
	}
	sl->sl_len = sz;

	/*
	 * Create the log entry to be read by a user daemon.  When it has been
	 * finished and put on the queue, send a signal to wakeup any waiters.
	 */
	MUTEX_ENTER(&ipf_syncadd);
	sle = synclog + sl_idx++;
	bcopy((char *)&sl->sl_hdr, (char *)&sle->sle_hdr,
	      sizeof(sle->sle_hdr));
	sle->sle_hdr.sm_num = htonl(sle->sle_hdr.sm_num);
	sle->sle_hdr.sm_len = htonl(sle->sle_hdr.sm_len);
	if (ptr != NULL) {
		bcopy((char *)ptr, (char *)&sle->sle_un, sz);
		if (tab == SMC_STATE) {
			ipf_sync_storder(1, &sle->sle_un.sleu_ips);
		} else if (tab == SMC_NAT) {
			ipf_sync_natorder(1, &sle->sle_un.sleu_ipn);
		}
	}
	MUTEX_EXIT(&ipf_syncadd);

	ipf_sync_wakeup();
	return sl;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_sync_update                                             */
/* Returns:     Nil                                                         */
/* Parameters:  tab(I) - type of synclist_t to create                       */
/*              fin(I) - pointer to packet information                      */
/*              sl(I)  - pointer to synchronisation object                  */
/*                                                                          */
/* For outbound packets, only, create an sync update record for the user    */
/* process to read.                                                         */
/* ------------------------------------------------------------------------ */
void
ipf_sync_update(tab, fin, sl)
	int tab;
	fr_info_t *fin;
	synclist_t *sl;
{
	synctcp_update_t *st;
	syncupdent_t *slu;
	ipstate_t *ips;
	nat_t *nat;
	ipfrwlock_t *lock;

	if (fin->fin_out == 0 || sl == NULL)
		return;

	if (tab == SMC_STATE) {
		lock = &ipf_syncstate;
	} else {
		lock = &ipf_syncnat;
	}

	READ_ENTER(lock);
	if (sl->sl_idx == -1) {
		MUTEX_ENTER(&ipf_syncadd);
		slu = syncupd + su_idx;
		sl->sl_idx = su_idx++;
		MUTEX_EXIT(&ipf_syncadd);

		bcopy((char *)&sl->sl_hdr, (char *)&slu->sup_hdr,
		      sizeof(slu->sup_hdr));
		slu->sup_hdr.sm_magic = htonl(SYNHDRMAGIC);
		slu->sup_hdr.sm_sl = sl;
		slu->sup_hdr.sm_cmd = SMC_UPDATE;
		slu->sup_hdr.sm_table = tab;
		slu->sup_hdr.sm_num = htonl(sl->sl_num);
		slu->sup_hdr.sm_len = htonl(sizeof(struct synctcp_update));
		slu->sup_hdr.sm_rev = fin->fin_rev;
# if 0
		if (fin->fin_p == IPPROTO_TCP) {
			st->stu_len[0] = 0;
			st->stu_len[1] = 0;
		}
# endif
	} else
		slu = syncupd + sl->sl_idx;

	/*
	 * Only TCP has complex timeouts, others just use default timeouts.
	 * For TCP, we only need to track the connection state and window.
	 */
	if (fin->fin_p == IPPROTO_TCP) {
		st = &slu->sup_tcp;
		if (tab == SMC_STATE) {
			ips = sl->sl_ips;
			st->stu_age = htonl(ips->is_die);
			st->stu_data[0].td_end = ips->is_send;
			st->stu_data[0].td_maxend = ips->is_maxsend;
			st->stu_data[0].td_maxwin = ips->is_maxswin;
			st->stu_state[0] = ips->is_state[0];
			st->stu_data[1].td_end = ips->is_dend;
			st->stu_data[1].td_maxend = ips->is_maxdend;
			st->stu_data[1].td_maxwin = ips->is_maxdwin;
			st->stu_state[1] = ips->is_state[1];
		} else if (tab == SMC_NAT) {
			nat = sl->sl_ipn;
			st->stu_age = htonl(nat->nat_age);
		}
	}
	RWLOCK_EXIT(lock);

	ipf_sync_wakeup();
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_sync_flush_table                                        */
/* Returns:     int - number of entries freed by flushing table             */
/* Parameters:  tabsize(I) - size of the array pointed to by table          */
/*              table(I)   - pointer to sync table to empty                 */
/*                                                                          */
/* Walk through a table of sync entries and free each one.  It is assumed   */
/* that some lock is held so that nobody else tries to access the table     */
/* during this cleanup.                                                     */
/* ------------------------------------------------------------------------ */
static int
ipf_sync_flush_table(tabsize, table)
	int tabsize;
	synclist_t **table;
{
	synclist_t *sl;
	int i, items;

	items = 0;

	for (i = 0; i < tabsize; i++) {
		while ((sl = table[i]) != NULL) {
			if (sl->sl_next != NULL)
				sl->sl_next->sl_pnext = sl->sl_pnext;
			table[i] = sl->sl_next;
			if (sl->sl_idx != -1)
				syncupd[sl->sl_idx].sup_hdr.sm_sl = NULL;
			KFREE(sl);
			items++;
		}
	}

	return items;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_sync_ioctl                                              */
/* Returns:     int - 0 == success, != 0 == failure                         */
/* Parameters:  data(I) - pointer to ioctl data                             */
/*              cmd(I)  - ioctl command integer                             */
/*              mode(I) - file mode bits used with open                     */
/*                                                                          */
/* This function currently does not handle any ioctls and so just returns   */
/* EINVAL on all occasions.                                                 */
/* ------------------------------------------------------------------------ */
int
ipf_sync_ioctl(data, cmd, mode, uid, ctx)
	caddr_t data;
	ioctlcmd_t cmd;
	int mode, uid;
	void *ctx;
{
	int error, i;
	SPL_INT(s);

	switch (cmd)
	{
        case SIOCIPFFL:
		error = BCOPYIN(data, &i, sizeof(i));
		if (error != 0) {
			ipf_interror = 110023;
			error = EFAULT;
			break;
		}

		switch (i)
		{
		case SMC_RLOG :
			SPL_NET(s);
			MUTEX_ENTER(&ipsl_mutex);
			i = (sl_tail - sl_idx) + (su_tail - su_idx);
			sl_idx = 0;
			su_idx = 0;
			sl_tail = 0;
			su_tail = 0;
			MUTEX_EXIT(&ipsl_mutex);
			SPL_X(s);
			break;

		case SMC_NAT :
			SPL_NET(s);
			WRITE_ENTER(&ipf_syncnat);
			i = ipf_sync_flush_table(SYNC_NATTABSZ, syncnattab);
			RWLOCK_EXIT(&ipf_syncnat);
			SPL_X(s);
			break;

		case SMC_STATE :
			SPL_NET(s);
			WRITE_ENTER(&ipf_syncstate);
			i = ipf_sync_flush_table(SYNC_STATETABSZ, syncstatetab);
			RWLOCK_EXIT(&ipf_syncstate);
			SPL_X(s);
			break;
		}

		error = BCOPYOUT(&i, data, sizeof(i));
		if (error != 0) {
			ipf_interror = 110022;
			error = EFAULT;
		}
		break;

	default :
		ipf_interror = 110021;
		error = EINVAL;
		break;
	}

	return error;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_sync_canread                                            */
/* Returns:     int - 0 == success, != 0 == failure                         */
/* Parameters:  Nil                                                         */
/*                                                                          */
/* This function provides input to the poll handler about whether or not    */
/* there is data waiting to be read from the /dev/ipsync device.            */
/* ------------------------------------------------------------------------ */
int
ipf_sync_canread()
{
	return !((sl_tail == sl_idx) && (su_tail == su_idx));
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_sync_canwrite                                           */
/* Returns:     int - 1 == can always write                                 */
/* Parameters:  Nil                                                         */
/*                                                                          */
/* This function lets the poll handler know that it is always ready willing */
/* to accept write events.                                                  */
/* XXX Maybe this should return false if the sync table is full?            */
/* ------------------------------------------------------------------------ */
int
ipf_sync_canwrite()
{
	return 1;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_sync_wakeup                                             */
/* Parameters:  Nil                                                         */
/* Returns:     Nil                                                         */
/*                                                                          */
/* This function implements the heuristics that decide how often to         */
/* generate a poll wakeup for programs that are waiting for information     */
/* about when they can do a read on /dev/ipsync.                            */
/*                                                                          */
/* There are three different considerations here:                           */
/* - do not keep a program waiting too long: ipf_sync_wake_interval is the  */
/*   maximum number of ipf ticks to let pass by;                            */
/* - do not let the queue of ouststanding things to generate notifies for   */
/*   get too full (ipf_sync_queue_high_wm is the high water mark);          */
/* - do not let too many events get collapsed in before deciding that the   */
/*   other host(s) need an update (ipf_sync_event_high_wm is the high water */
/*   mark for this counter.)                                                */
/* ------------------------------------------------------------------------ */
static void
ipf_sync_wakeup()
{
	ipf_sync_events++;
	if ((ipf_ticks > ipf_sync_lastwakeup + ipf_sync_wake_interval) ||
	    (ipf_sync_events > ipf_sync_event_high_wm) ||
	    ((sl_tail - sl_idx) > ipf_sync_queue_high_wm) ||
	    ((su_tail - su_idx) > ipf_sync_queue_high_wm)) {

		ipf_sync_poll_wakeup();
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_sync_poll_wakeup                                        */
/* Parameters:  Nil                                                         */
/* Returns:     Nil                                                         */
/*                                                                          */
/* Deliver a poll wakeup and reset counters for two of the three heuristics */
/* ------------------------------------------------------------------------ */
static void
ipf_sync_poll_wakeup()
{

	ipf_sync_events = 0;
	ipf_sync_lastwakeup = ipf_ticks;

# ifdef _KERNEL
#  if SOLARIS
	MUTEX_ENTER(&ipsl_mutex);
	cv_signal(&ipslwait);
	MUTEX_EXIT(&ipsl_mutex);
	pollwakeup(&ipf_poll_head[IPL_LOGSYNC], POLLIN|POLLRDNORM);
#  else
	wakeup(&sl_tail);
	POLLWAKEUP(IPL_LOGSYNC);
#  endif
# endif
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_sync_expire                                             */
/* Parameters:  Nil                                                         */
/* Returns:     Nil                                                         */
/*                                                                          */
/* This is the function called even ipf_tick.  It implements one of the     */
/* three heuristics above *IF* there are events waiting.                    */
/* ------------------------------------------------------------------------ */
void
ipf_sync_expire()
{
	if ((ipf_sync_events > 0) &&
	    (ipf_ticks > ipf_sync_lastwakeup + ipf_sync_wake_interval)) {
		ipf_sync_poll_wakeup();
	}
}
#endif /* IPFILTER_SYNC */
