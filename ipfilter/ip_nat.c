/*
 * Copyright (C) 1995-2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 */
#if defined(KERNEL) || defined(_KERNEL)
# undef KERNEL
# undef ipf_nat_KERNEL
# define        KERNEL	1
# define        ipf_nat_KERNEL	1
#endif
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/file.h>
#if defined(_KERNEL) && defined(__NetBSD_Version__) && \
    (__NetBSD_Version__ >= 399002000)
# include <sys/kauth.h>
#endif
#if defined(__NetBSD__) && (NetBSD >= 199905) && !defined(IPFILTER_LKM) && \
    defined(_KERNEL)
#if defined(__NetBSD_Version__) && (__NetBSD_Version__ < 399001400)
#  include "opt_ipfilter_log.h"
# else
#  include "opt_ipfilter.h"
# endif
#endif
#if !defined(_KERNEL)
# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# define ipf_nat_KERNEL
# ifdef ipf_nat__OpenBSD__
struct file;
# endif
# include <sys/uio.h>
# undef ipf_nat_KERNEL
#endif
#if defined(_KERNEL) && (__FreeBSD_version >= 220000)
# include <sys/filio.h>
# include <sys/fcntl.h>
#else
# include <sys/ioctl.h>
#endif
#if !defined(AIX)
# include <sys/fcntl.h>
#endif
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
# ifdef ipf_nat_KERNEL
#  include <sys/dditypes.h>
# endif
# include <sys/stream.h>
# include <sys/kmem.h>
#endif
#if ipf_nat__FreeBSD_version >= 300000
# include <sys/queue.h>
#endif
#include <net/if.h>
#if ipf_nat__FreeBSD_version >= 300000
# include <net/if_var.h>
# if defined(_KERNEL) && !defined(IPFILTER_LKM)
#  include "opt_ipfilter.h"
# endif
#endif
#ifdef sun
# include <net/af.h>
#endif
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#ifdef RFC1825
# include <vpn/md5.h>
# include <vpn/ipsec.h>
extern struct ifnet vpnif;
#endif

#if !defined(linux)
# include <netinet/ip_var.h>
#endif
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "netinet/ip_compat.h"
#include <netinet/tcpip.h>
#include "netinet/ip_fil.h"
#include "netinet/ip_nat.h"
#include "netinet/ip_frag.h"
#include "netinet/ip_state.h"
#include "netinet/ip_proxy.h"
#ifdef	IPFILTER_SYNC
#include "netinet/ip_sync.h"
#endif
#if (__FreeBSD_version >= 300000)
# include <sys/malloc.h>
#endif
#include "md5.h"
/* END OF INCLUDES */

#undef	SOCKADDR_IN
#define	SOCKADDR_IN	struct sockaddr_in

#if !defined(lint)
static const char sccsid[] = "@(#)ip_nat.c	1.11 6/5/96 (C) 1995 Darren Reed";
static const char rcsid[] = "@(#)$Id$";
#endif


/* ======================================================================== */
/* How the NAT is organised and works.                                      */
/*                                                                          */
/* Inside (interface y) NAT       Outside (interface x)                     */
/* -------------------- -+- -------------------------------------           */
/* Packet going          |   out, processsed by ipf_nat_checkout() for x    */
/* ------------>         |   ------------>                                  */
/* src=10.1.1.1          |   src=192.1.1.1                                  */
/*                       |                                                  */
/*                       |   in, processed by ipf_nat_checkin() for x       */
/* <------------         |   <------------                                  */
/* dst=10.1.1.1          |   dst=192.1.1.1                                  */
/* -------------------- -+- -------------------------------------           */
/* ipf_nat_checkout() - changes ip_src and if required, sport               */
/*             - creates a new mapping, if required.                        */
/* ipf_nat_checkin()  - changes ip_dst and if required, dport               */
/*                                                                          */
/* In the NAT table, internal source is recorded as "in" and externally     */
/* seen as "out".                                                           */
/* ======================================================================== */


nat_t	**ipf_nat_table[2] = { NULL, NULL },
	*ipf_nat_instances = NULL;
ipnat_t	*ipf_nat_list = NULL;
u_int	ipf_nat_table_max = NAT_TABLE_MAX;
u_int	ipf_nat_table_sz = NAT_TABLE_SZ;
u_int	ipf_nat_maprules_sz = NAT_SIZE;
u_int	ipf_nat_rdrrules_sz = RDR_SIZE;
u_int	ipf_nat_hostmap_sz = HOSTMAP_SIZE;
u_int	ipf_nat_maxbucket = 0,
	ipf_nat_maxbucket_reset = 1;
u_32_t	ipf_nat_map_masks = 0;
u_32_t	ipf_nat_rdr_masks = 0;
u_int	ipf_nat_last_force_flush = 0;
ipnat_t	**ipf_nat_map_rules = NULL;
ipnat_t	**ipf_nat_rdr_rules = NULL;
hostmap_t	**ipf_hm_maptable  = NULL;
hostmap_t	*ipf_hm_maplist  = NULL;
ipftq_t	ipf_nat_tqb[IPF_TCP_NSTATES];
ipftq_t	ipf_nat_udptq;
ipftq_t	ipf_nat_icmptq;
ipftq_t	ipf_nat_iptq;
ipftq_t	ipf_nat_pending;
ipftq_t	*ipf_nat_utqe = NULL;
frentry_t ipfnatblock;
int	ipf_nat_doflush = 0;
#ifdef  IPFILTER_LOG
int	ipf_nat_logging = 1;
#else
int	ipf_nat_logging = 0;
#endif

u_int	ipf_nat_defage = DEF_NAT_AGE,
	ipf_nat_defipage = 120,		/* 60 seconds */
	ipf_nat_deficmpage = 6;		/* 3 seconds */
natstat_t ipf_nat_stats;
int	ipf_nat_lock = 0;
int	ipf_nat_inited = 0;
int	ipf_nat_table_wm_high = 99;
int	ipf_nat_table_wm_low = 90;

#if SOLARIS
extern	int		pfil_delayed_copy;
#endif

static	nat_t	*ipf_nat_clone __P((fr_info_t *, nat_t *));
static	int	ipf_nat_flush_entry __P((void *));
static	int	ipf_nat_getent __P((caddr_t, int));
static	int	ipf_nat_getsz __P((caddr_t, int));
static	int	ipf_nat_putent __P((caddr_t, int));
static	void	ipf_nat_addencap __P((ipnat_t *));
static	void	ipf_nat_addnat __P((struct ipnat *));
static	void	ipf_nat_addrdr __P((struct ipnat *));
static	int	ipf_nat_builddivertmp __P((ipnat_t *));
static	int	ipf_nat_clearlist __P((void));
static	int	ipf_nat_decap __P((fr_info_t *, nat_t *));
static	void	ipf_nat_delnat __P((struct ipnat *));
static	void	ipf_nat_delrdr __P((struct ipnat *));
static	void	ipf_nat_delrule __P((struct ipnat *));
static	int	ipf_nat_encapok __P((fr_info_t *, nat_t *));
static	int	ipf_nat_extraflush __P((int));
static	int	ipf_nat_finalise __P((fr_info_t *, nat_t *, natinfo_t *,
				      nat_t **, int));
static	int	ipf_nat_flushtable __P((void));
static	int	ipf_nat_getnext __P((ipftoken_t *, ipfgeniter_t *));
static	int	ipf_nat_gettable __P((char *));
static	hostmap_t *ipf_nat_hostmap __P((ipnat_t *, struct in_addr,
					struct in_addr, struct in_addr,
					u_32_t));
static	int	ipf_nat_icmpquerytype4 __P((int));
static	int	ipf_nat_iterator __P((ipftoken_t *, ipfgeniter_t *));
static	int	ipf_nat_match_v4 __P((fr_info_t *, ipnat_t *));
static	int	ipf_nat_matcharray __P((nat_t *, int *));
static	int	ipf_nat_matchencap __P((fr_info_t *, ipnat_t *));
static	int	ipf_nat_matchflush __P((caddr_t));
static	void	ipf_nat_mssclamp __P((tcphdr_t *, u_32_t, fr_info_t *,
				      u_short *));
static	nat_t	*ipf_nat_clone __P((fr_info_t *, nat_t *));
static	int	ipf_nat_newmap __P((fr_info_t *, nat_t *, natinfo_t *));
static	int	ipf_nat_newdivert __P((fr_info_t *, nat_t *, natinfo_t *));
static	int	ipf_nat_newrdr __P((fr_info_t *, nat_t *, natinfo_t *));
static	int	ipf_nat_newrewrite __P((fr_info_t *, nat_t *, natinfo_t *));
static	int	ipf_nat_nextaddr __P((fr_info_t *, nat_addr_t *, u_32_t *,
				      u_32_t *));
static	int	ipf_nat_nextaddrinit __P((nat_addr_t *, int, void *));
static	nat_t	*ipf_nat_rebuildencapicmp __P((fr_info_t *, nat_t *));
static	int	ipf_nat_resolverule __P((ipnat_t *));
static	int	ipf_nat_siocaddnat __P((ipnat_t *, ipnat_t **, int));
static	void	ipf_nat_siocdelnat __P((ipnat_t *, ipnat_t **, int));
static	void	ipf_nat_tabmove __P((nat_t *));
static	int	ipf_nat_wildok __P((nat_t *, int, int, int, int));


#define	NATFSUM(n,f)	((n)->nat_v == 4 ? (n)->f.in4.s_addr : (n)->f.i6[0] + \
			 (n)->f.i6[1] + (n)->f.i6[2] + (n)->f.i6[3])

/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_init                                                */
/* Returns:     int - 0 == success, -1 == failure                           */
/* Parameters:  Nil                                                         */
/*                                                                          */
/* Initialise all of the NAT locks, tables and other structures.            */
/* ------------------------------------------------------------------------ */
int
ipf_nat_init()
{
	int i;

	KMALLOCS(ipf_nat_table[0], nat_t **, \
		 sizeof(nat_t *) * ipf_nat_table_sz);

	if (ipf_nat_table[0] != NULL) {
		bzero((char *)ipf_nat_table[0],
		      ipf_nat_table_sz * sizeof(nat_t *));
	} else {
		return -1;
	}

	KMALLOCS(ipf_nat_table[1], nat_t **, \
		 sizeof(nat_t *) * ipf_nat_table_sz);

	if (ipf_nat_table[1] != NULL) {
		bzero((char *)ipf_nat_table[1],
		      ipf_nat_table_sz * sizeof(nat_t *));
	} else {
		return -2;
	}

	KMALLOCS(ipf_nat_map_rules, ipnat_t **, \
		 sizeof(ipnat_t *) * ipf_nat_maprules_sz);

	if (ipf_nat_map_rules != NULL) {
		bzero((char *)ipf_nat_map_rules,
		      ipf_nat_maprules_sz * sizeof(ipnat_t *));
	} else {
		return -3;
	}

	KMALLOCS(ipf_nat_rdr_rules, ipnat_t **, \
		 sizeof(ipnat_t *) * ipf_nat_rdrrules_sz);

	if (ipf_nat_rdr_rules != NULL) {
		bzero((char *)ipf_nat_rdr_rules,
		      ipf_nat_rdrrules_sz * sizeof(ipnat_t *));
	} else {
		return -4;
	}

	KMALLOCS(ipf_hm_maptable, hostmap_t **, \
		 sizeof(hostmap_t *) * ipf_nat_hostmap_sz);

	if (ipf_hm_maptable != NULL) {
		bzero((char *)ipf_hm_maptable,
		      sizeof(hostmap_t *) * ipf_nat_hostmap_sz);
	} else {
		return -5;
	}
	ipf_hm_maplist = NULL;

	KMALLOCS(ipf_nat_stats.ns_side[0].ns_bucketlen, u_int *,
		 ipf_nat_table_sz * sizeof(u_int));

	if (ipf_nat_stats.ns_side[0].ns_bucketlen == NULL) {
		return -6;
	}
	bzero((char *)ipf_nat_stats.ns_side[0].ns_bucketlen,
	      ipf_nat_table_sz * sizeof(u_int));

	KMALLOCS(ipf_nat_stats.ns_side[1].ns_bucketlen, u_int *,
		 ipf_nat_table_sz * sizeof(u_int));

	if (ipf_nat_stats.ns_side[1].ns_bucketlen == NULL) {
		return -7;
	}

	bzero((char *)ipf_nat_stats.ns_side[1].ns_bucketlen,
	      ipf_nat_table_sz * sizeof(u_int));

	if (ipf_nat_maxbucket == 0) {
		for (i = ipf_nat_table_sz; i > 0; i >>= 1)
			ipf_nat_maxbucket++;
		ipf_nat_maxbucket *= 2;
	}

	ipf_sttab_init(ipf_nat_tqb);
	/*
	 * Increase this because we may have "keep state" following this too
	 * and packet storms can occur if this is removed too quickly.
	 */
	ipf_nat_tqb[IPF_TCPS_CLOSED].ifq_ttl = ipf_tcplastack;
	ipf_nat_tqb[IPF_TCP_NSTATES - 1].ifq_next = &ipf_nat_udptq;

	IPFTQ_INIT(&ipf_nat_udptq, ipf_nat_defage, "nat ipftq udp tab");
	ipf_nat_udptq.ifq_next = &ipf_nat_icmptq;

	IPFTQ_INIT(&ipf_nat_icmptq, ipf_nat_deficmpage, "nat icmp ipftq tab");
	ipf_nat_icmptq.ifq_next = &ipf_nat_iptq;

	IPFTQ_INIT(&ipf_nat_iptq, ipf_nat_defipage, "nat ip ipftq tab");
	ipf_nat_iptq.ifq_next = &ipf_nat_pending;

	IPFTQ_INIT(&ipf_nat_pending, 1, "nat pending ipftq tab");
	ipf_nat_pending.ifq_next = NULL;

	for (i = 0; i < IPF_TCP_NSTATES; i++) {
		if (ipf_nat_tqb[i].ifq_ttl < ipf_nat_deficmpage)
			ipf_nat_tqb[i].ifq_ttl = ipf_nat_deficmpage;
#ifdef LARGE_NAT
		else if (ipf_nat_tqb[i].ifq_ttl > ipf_nat_defage)
			ipf_nat_tqb[i].ifq_ttl = ipf_nat_defage;
#endif
	}

	/*
	 * Increase this because we may have "keep state" following
	 * this too and packet storms can occur if this is removed
	 * too quickly.
	 */
	ipf_nat_tqb[IPF_TCPS_CLOSED].ifq_ttl = ipf_nat_tqb[IPF_TCPS_LAST_ACK].ifq_ttl;

	RWLOCK_INIT(&ipf_nat, "ipf IP NAT rwlock");
	RWLOCK_INIT(&ipf_natfrag, "ipf IP NAT-Frag rwlock");
	MUTEX_INIT(&ipf_nat_new, "ipf nat new mutex");
	MUTEX_INIT(&ipf_natio, "ipf nat io mutex");

	bzero((char *)&ipfnatblock, sizeof(ipfnatblock));
	ipfnatblock.fr_flags = FR_BLOCK|FR_QUICK;
	ipfnatblock.fr_ref = 1;

	ipf_nat_inited = 1;

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_addrdr                                              */
/* Returns:     Nil                                                         */
/* Parameters:  n(I) - pointer to NAT rule to add                           */
/*                                                                          */
/* Adds a redirect rule to the hash table of redirect rules and the list of */
/* loaded NAT rules.  Updates the bitmask indicating which netmasks are in  */
/* use by redirect rules.                                                   */
/* ------------------------------------------------------------------------ */
static void
ipf_nat_addrdr(n)
	ipnat_t *n;
{
	ipnat_t **np;
	u_32_t j;
	u_int hv;
	int k;

	if (n->in_odstatype == FRI_NORMAL) {
		k = count4bits(n->in_odstmsk);
		if ((k >= 0) && (k != 32))
			ipf_nat_rdr_masks |= 1 << k;
		j = (n->in_odstaddr & n->in_odstmsk);
		hv = NAT_HASH_FN(j, 0, ipf_nat_rdrrules_sz);
	} else {
		ipf_nat_rdr_masks |= 1;
		j = 0;
		hv = 0;
	}
	np = ipf_nat_rdr_rules + hv;
	while (*np != NULL)
		np = &(*np)->in_rnext;
	n->in_rnext = NULL;
	n->in_prnext = np;
	n->in_hv[0] = hv;
	*np = n;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_addnat                                              */
/* Returns:     Nil                                                         */
/* Parameters:  n(I) - pointer to NAT rule to add                           */
/*                                                                          */
/* Adds a NAT map rule to the hash table of rules and the list of  loaded   */
/* NAT rules.  Updates the bitmask indicating which netmasks are in use by  */
/* redirect rules.                                                          */
/* ------------------------------------------------------------------------ */
static void
ipf_nat_addnat(n)
	ipnat_t *n;
{
	ipnat_t **np;
	u_32_t j;
	u_int hv;
	int k;

	if (n->in_osrcatype == FRI_NORMAL) {
		k = count4bits(n->in_osrcmsk);
		if ((k >= 0) && (k != 32))
			ipf_nat_map_masks |= 1 << k;
		j = (n->in_osrcaddr & n->in_osrcmsk);
		hv = NAT_HASH_FN(j, 0, ipf_nat_maprules_sz);
	} else {
		ipf_nat_map_masks |= 1;
		j = 0;
		hv = 0;
	}
	np = ipf_nat_map_rules + hv;
	while (*np != NULL)
		np = &(*np)->in_mnext;
	n->in_mnext = NULL;
	n->in_pmnext = np;
	n->in_hv[1] = hv;
	*np = n;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_addencap                                            */
/* Returns:     Nil                                                         */
/* Parameters:  n(I) - pointer to NAT rule to add                           */
/*                                                                          */
/* Here we add in a pointer in the NAT rules hash table to match reply      */
/* packets that are encapsulated.  For encap rules that are "out", what we  */
/* will want to match upon will be the source address in the encap rule as  */
/* this is what will become the destination in packets coming back to us.   */
/* For encaps pointing in, it is still the same because it is still the     */
/* reply packet we want to match.                                           */
/* ------------------------------------------------------------------------ */
static void
ipf_nat_addencap(n)
	ipnat_t *n;
{
	ipnat_t **np;
	u_32_t j;
	u_int hv;
	int k;

	k = -1;

	/*
	 * It is the new source address we're after...
	 */
	if (n->in_nsrcatype == FRI_NORMAL) {
		k = count4bits(n->in_nsrcmsk);
		j = (n->in_nsrcaddr & n->in_nsrcmsk);
		hv = NAT_HASH_FN(j, 0, ipf_nat_maprules_sz);
	} else {
		j = 0;
		hv = 0;
	}

	/*
	 * And place the rules table entry in the reverse spot, so for out
	 * we use the rdr-links and for rdr, we use the map-links/
	 */
	if (n->in_redir & NAT_MAP) {
		if ((k >= 0) && (k != 32))
			ipf_nat_rdr_masks |= 1 << k;
		else
			ipf_nat_rdr_masks |= 1;
		np = ipf_nat_rdr_rules + hv;
		while (*np != NULL)
			np = &(*np)->in_rnext;
		n->in_rnext = NULL;
		n->in_prnext = np;
		n->in_hv[0] = hv;
		*np = n;
	} else if (n->in_redir & NAT_REDIRECT) {
		if ((k >= 0) && (k != 32))
			ipf_nat_map_masks |= 1 << k;
		else
			ipf_nat_map_masks |= 1;
		np = ipf_nat_map_rules + hv;
		while (*np != NULL)
			np = &(*np)->in_mnext;
		n->in_mnext = NULL;
		n->in_pmnext = np;
		n->in_hv[1] = hv;
		*np = n;
	}

	/* TRACE(n, hv, k) */
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_delrdr                                              */
/* Returns:     Nil                                                         */
/* Parameters:  n(I) - pointer to NAT rule to delete                        */
/*                                                                          */
/* Removes a redirect rule from the hash table of redirect rules.           */
/* ------------------------------------------------------------------------ */
static void
ipf_nat_delrdr(n)
	ipnat_t *n;
{
	if (n->in_rnext)
		n->in_rnext->in_prnext = n->in_prnext;
	*n->in_prnext = n->in_rnext;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_delnat                                              */
/* Returns:     Nil                                                         */
/* Parameters:  n(I) - pointer to NAT rule to delete                        */
/*                                                                          */
/* Removes a NAT map rule from the hash table of NAT map rules.             */
/* ------------------------------------------------------------------------ */
static void
ipf_nat_delnat(n)
	ipnat_t *n;
{
	if (n->in_mnext != NULL)
		n->in_mnext->in_pmnext = n->in_pmnext;
	*n->in_pmnext = n->in_mnext;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_hostmap                                             */
/* Returns:     struct hostmap* - NULL if no hostmap could be created,      */
/*                                else a pointer to the hostmapping to use  */
/* Parameters:  np(I)   - pointer to NAT rule                               */
/*              real(I) - real IP address                                   */
/*              map(I)  - mapped IP address                                 */
/*              port(I) - destination port number                           */
/* Write Locks: ipf_nat                                                     */
/*                                                                          */
/* Check if an ip address has already been allocated for a given mapping    */
/* that is not doing port based translation.  If is not yet allocated, then */
/* create a new entry if a non-NULL NAT rule pointer has been supplied.     */
/* ------------------------------------------------------------------------ */
static struct hostmap *
ipf_nat_hostmap(np, src, dst, map, port)
	ipnat_t *np;
	struct in_addr src;
	struct in_addr dst;
	struct in_addr map;
	u_32_t port;
{
	hostmap_t *hm;
	u_int hv;

	hv = (src.s_addr ^ dst.s_addr);
	hv += src.s_addr;
	hv += dst.s_addr;
	hv %= HOSTMAP_SIZE;
	for (hm = ipf_hm_maptable[hv]; hm; hm = hm->hm_next)
		if ((hm->hm_osrcip.s_addr == src.s_addr) &&
		    (hm->hm_odstip.s_addr == dst.s_addr) &&
		    ((np == NULL) || (np == hm->hm_ipnat)) &&
		    ((port == 0) || (port == hm->hm_port))) {
			ipf_nat_stats.ns_hm_addref++;
			hm->hm_ref++;
			return hm;
		}

	if (np == NULL) {
		ipf_nat_stats.ns_hm_nullnp++;
		return NULL;
	}

	KMALLOC(hm, hostmap_t *);
	if (hm) {
		hm->hm_next = ipf_hm_maplist;
		hm->hm_pnext = &ipf_hm_maplist;
		if (ipf_hm_maplist != NULL)
			ipf_hm_maplist->hm_pnext = &hm->hm_next;
		ipf_hm_maplist = hm;
		hm->hm_hnext = ipf_hm_maptable[hv];
		hm->hm_phnext = ipf_hm_maptable + hv;
		if (ipf_hm_maptable[hv] != NULL)
			ipf_hm_maptable[hv]->hm_phnext = &hm->hm_hnext;
		ipf_hm_maptable[hv] = hm;
		hm->hm_ipnat = np;
		hm->hm_osrcip = src;
		hm->hm_odstip = dst;
		hm->hm_nsrcip = map;
		hm->hm_ndstip.s_addr = 0;
		hm->hm_ref = 1;
		hm->hm_port = port;
		hm->hm_hv = hv;
		ipf_nat_stats.ns_hm_new++;
	} else {
		ipf_nat_stats.ns_hm_newfail++;
	}
	return hm;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_hostmapdel                                          */
/* Returns:     Nil                                                         */
/* Parameters:  hmp(I) - pointer to hostmap structure pointer               */
/* Write Locks: ipf_nat                                                     */
/*                                                                          */
/* Decrement the references to this hostmap structure by one.  If this      */
/* reaches zero then remove it and free it.                                 */
/* ------------------------------------------------------------------------ */
void
ipf_nat_hostmapdel(hmp)
	struct hostmap **hmp;
{
	struct hostmap *hm;

	hm = *hmp;
	*hmp = NULL;

	hm->hm_ref--;
	if (hm->hm_ref == 0) {
		if (hm->hm_hnext)
			hm->hm_hnext->hm_phnext = hm->hm_phnext;
		*hm->hm_phnext = hm->hm_hnext;
		if (hm->hm_next)
			hm->hm_next->hm_pnext = hm->hm_pnext;
		*hm->hm_pnext = hm->hm_next;
		KFREE(hm);
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_fix_outcksum                                            */
/* Returns:     Nil                                                         */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              sp(I)  - location of 16bit checksum to update               */
/*              n((I)  - amount to adjust checksum by                       */
/*                                                                          */
/* Adjusts the 16bit checksum by "n" for packets going out.                 */
/* ------------------------------------------------------------------------ */
void
ipf_fix_outcksum(fin, sp, n)
	fr_info_t *fin;
	u_short *sp;
	u_32_t n;
{
	u_short sumshort;
	u_32_t sum1;

	if (n == 0)
		return;

	if (n & NAT_HW_CKSUM) {
		n &= 0xffff;
		n += fin->fin_dlen;
		n = (n & 0xffff) + (n >> 16);
		*sp = n & 0xffff;
		return;
	}
	sum1 = (~ntohs(*sp)) & 0xffff;
	sum1 += (n);
	sum1 = (sum1 >> 16) + (sum1 & 0xffff);
	/* Again */
	sum1 = (sum1 >> 16) + (sum1 & 0xffff);
	sumshort = ~(u_short)sum1;
	*(sp) = htons(sumshort);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_fix_incksum                                             */
/* Returns:     Nil                                                         */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              sp(I)  - location of 16bit checksum to update               */
/*              n((I)  - amount to adjust checksum by                       */
/*                                                                          */
/* Adjusts the 16bit checksum by "n" for packets going in.                  */
/* ------------------------------------------------------------------------ */
void
ipf_fix_incksum(fin, sp, n)
	fr_info_t *fin;
	u_short *sp;
	u_32_t n;
{
	u_short sumshort;
	u_32_t sum1;

	if (n == 0)
		return;

	if (n & NAT_HW_CKSUM) {
		n &= 0xffff;
		n += fin->fin_dlen;
		n = (n & 0xffff) + (n >> 16);
		*sp = n & 0xffff;
		return;
	}
	sum1 = (~ntohs(*sp)) & 0xffff;
	sum1 += ~(n) & 0xffff;
	sum1 = (sum1 >> 16) + (sum1 & 0xffff);
	/* Again */
	sum1 = (sum1 >> 16) + (sum1 & 0xffff);
	sumshort = ~(u_short)sum1;
	*(sp) = htons(sumshort);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_fix_datacksum                                           */
/* Returns:     Nil                                                         */
/* Parameters:  sp(I)  - location of 16bit checksum to update               */
/*              n((I)  - amount to adjust checksum by                       */
/*                                                                          */
/* Fix_datacksum is used *only* for the adjustments of checksums in the     */
/* data section of an IP packet.                                            */
/*                                                                          */
/* The only situation in which you need to do this is when NAT'ing an       */
/* ICMP error message. Such a message, contains in its body the IP header   */
/* of the original IP packet, that causes the error.                        */
/*                                                                          */
/* You can't use fix_incksum or fix_outcksum in that case, because for the  */
/* kernel the data section of the ICMP error is just data, and no special   */
/* processing like hardware cksum or ntohs processing have been done by the */
/* kernel on the data section.                                              */
/* ------------------------------------------------------------------------ */
void
ipf_fix_datacksum(sp, n)
	u_short *sp;
	u_32_t n;
{
	u_short sumshort;
	u_32_t sum1;

	if (n == 0)
		return;

	sum1 = (~ntohs(*sp)) & 0xffff;
	sum1 += (n);
	sum1 = (sum1 >> 16) + (sum1 & 0xffff);
	/* Again */
	sum1 = (sum1 >> 16) + (sum1 & 0xffff);
	sumshort = ~(u_short)sum1;
	*(sp) = htons(sumshort);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_ioctl                                               */
/* Returns:     int - 0 == success, != 0 == failure                         */
/* Parameters:  data(I) - pointer to ioctl data                             */
/*              cmd(I)  - ioctl command integer                             */
/*              mode(I) - file mode bits used with open                     */
/*                                                                          */
/* Processes an ioctl call made to operate on the IP Filter NAT device.     */
/* ------------------------------------------------------------------------ */
int
ipf_nat_ioctl(data, cmd, mode, uid, ctx)
	ioctlcmd_t cmd;
	caddr_t data;
	int mode, uid;
	void *ctx;
{
	ipnat_t *nat, *nt, *n = NULL, **np = NULL;
	int error = 0, ret, arg, getlock;
	ipnat_t natd;
	SPL_INT(s);

#if (BSD >= 199306) && defined(_KERNEL)
# if defined(__NetBSD_Version__) && (__NetBSD_Version__ >= 399002000)
	if ((mode & FWRITE) &&
	     kauth_authorize_network(curlwp->l_cred, KAUTH_NETWORK_FIREWALL,
				     KAUTH_REQ_NETWORK_FIREWALL_FW,
				     NULL, NULL, NULL))
# else
	if ((securelevel >= 2) && (mode & FWRITE))
# endif
	{
		ipf_interror = 60001;
		return EPERM;
	}
#endif

#if defined(__osf__) && defined(_KERNEL)
	getlock = 0;
#else
	getlock = (mode & NAT_LOCKHELD) ? 0 : 1;
#endif

	nat = NULL;     /* XXX gcc -Wuninitialized */
	if (cmd == (ioctlcmd_t)SIOCADNAT) {
		KMALLOC(nt, ipnat_t *);
	} else {
		nt = NULL;
	}

	if ((cmd == (ioctlcmd_t)SIOCADNAT) || (cmd == (ioctlcmd_t)SIOCRMNAT)) {
		if (mode & NAT_SYSSPACE) {
			bcopy(data, (char *)&natd, sizeof(natd));
			error = 0;
		} else {
			error = ipf_inobj(data, &natd, IPFOBJ_IPNAT);
		}
	}

	if (error != 0)
		goto done;

	/*
	 * For add/delete, look to see if the NAT entry is already present
	 */
	if ((cmd == (ioctlcmd_t)SIOCADNAT) || (cmd == (ioctlcmd_t)SIOCRMNAT)) {
		nat = &natd;
		nat->in_flags &= IPN_USERFLAGS;
		if ((nat->in_redir & NAT_MAPBLK) == 0) {
			if (nat->in_osrcatype == FRI_NORMAL ||
			    nat->in_osrcatype == FRI_NONE)
				nat->in_osrcaddr &= nat->in_osrcmsk;
			if (nat->in_odstatype == FRI_NORMAL ||
			    nat->in_odstatype == FRI_NONE)
				nat->in_odstaddr &= nat->in_odstmsk;
			if ((nat->in_flags & (IPN_SPLIT|IPN_SIPRANGE)) == 0) {
				if (nat->in_nsrcatype == FRI_NORMAL)
					nat->in_nsrcaddr &= nat->in_nsrcmsk;
				if (nat->in_ndstatype == FRI_NORMAL)
					nat->in_ndstaddr &= nat->in_ndstmsk;
			}
		}
		MUTEX_ENTER(&ipf_natio);
		for (np = &ipf_nat_list; ((n = *np) != NULL); np = &n->in_next)
			if (!bcmp((char *)&nat->in_v, (char *)&n->in_v,
					IPN_CMPSIZ))
				break;
	}

	switch (cmd)
	{
#ifdef  IPFILTER_LOG
	case SIOCIPFFB :
	{
		int tmp;

		if (!(mode & FWRITE)) {
			ipf_interror = 60002;
			error = EPERM;
		} else {
			tmp = ipf_log_clear(IPL_LOGNAT);
			error = BCOPYOUT(&tmp, data, sizeof(tmp));
			if (error != 0) {
				ipf_interror = 60057;
				error = EFAULT;
			}
		}
		break;
	}

	case SIOCSETLG :
		if (!(mode & FWRITE)) {
			ipf_interror = 60003;
			error = EPERM;
		} else {
			error = BCOPYIN(data, &ipf_nat_logging,
					sizeof(ipf_nat_logging));
			if (error != 0)
				error = EFAULT;
		}
		break;

	case SIOCGETLG :
		error = BCOPYOUT(&ipf_nat_logging, data,
				 sizeof(ipf_nat_logging));
		if (error != 0) {
			ipf_interror = 60004;
			error = EFAULT;
		}
		break;

	case FIONREAD :
		arg = iplused[IPL_LOGNAT];
		error = BCOPYOUT(&arg, data, sizeof(arg));
		if (error != 0) {
			ipf_interror = 60005;
			error = EFAULT;
		}
		break;
#endif
	case SIOCADNAT :
		if (!(mode & FWRITE)) {
			ipf_interror = 60006;
			error = EPERM;
		} else if (n != NULL) {
			ipf_interror = 60007;
			error = EEXIST;
		} else if (nt == NULL) {
			ipf_interror = 60008;
			error = ENOMEM;
		}
		if (error != 0) {
			MUTEX_EXIT(&ipf_natio);
			break;
		}
		bcopy((char *)nat, (char *)nt, sizeof(*n));
		error = ipf_nat_siocaddnat(nt, np, getlock);
		MUTEX_EXIT(&ipf_natio);
		if (error == 0)
			nt = NULL;
		break;

	case SIOCRMNAT :
		if (!(mode & FWRITE)) {
			ipf_interror = 60009;
			error = EPERM;
			n = NULL;
		} else if (n == NULL) {
			ipf_interror = 60010;
			error = ESRCH;
		}

		if (error != 0) {
			MUTEX_EXIT(&ipf_natio);
			break;
		}
		ipf_nat_siocdelnat(n, np, getlock);

		MUTEX_EXIT(&ipf_natio);
		n = NULL;
		break;

	case SIOCGNATS :
		ipf_nat_stats.ns_side[0].ns_table = ipf_nat_table[0];
		ipf_nat_stats.ns_side[1].ns_table = ipf_nat_table[1];
		ipf_nat_stats.ns_list = ipf_nat_list;
		ipf_nat_stats.ns_maptable = ipf_hm_maptable;
		ipf_nat_stats.ns_maplist = ipf_hm_maplist;
		ipf_nat_stats.ns_nattab_sz = ipf_nat_table_sz;
		ipf_nat_stats.ns_nattab_max = ipf_nat_table_max;
		ipf_nat_stats.ns_rultab_sz = ipf_nat_maprules_sz;
		ipf_nat_stats.ns_rdrtab_sz = ipf_nat_rdrrules_sz;
		ipf_nat_stats.ns_hostmap_sz = ipf_nat_hostmap_sz;
		ipf_nat_stats.ns_instances = ipf_nat_instances;
		ipf_nat_stats.ns_apslist = ap_sess_list;
		ipf_nat_stats.ns_ticks = ipf_ticks;
		error = ipf_outobj(data, &ipf_nat_stats, IPFOBJ_NATSTAT);
		break;

	case SIOCGNATL :
	    {
		natlookup_t nl;

		error = ipf_inobj(data, &nl, IPFOBJ_NATLOOKUP);
		if (error == 0) {
			void *ptr;

			if (getlock) {
				READ_ENTER(&ipf_nat);
			}
			ptr = ipf_nat_lookupredir(&nl);
			if (getlock) {
				RWLOCK_EXIT(&ipf_nat);
			}
			if (ptr != NULL) {
				error = ipf_outobj(data, &nl, IPFOBJ_NATLOOKUP);
			} else {
				ipf_interror = 60011;
				error = ESRCH;
			}
		}
		break;
	    }

	case SIOCIPFFL :	/* old SIOCFLNAT & SIOCCNATL */
		if (!(mode & FWRITE)) {
			ipf_interror = 60012;
			error = EPERM;
			break;
		}
		if (getlock) {
			WRITE_ENTER(&ipf_nat);
		}

		error = BCOPYIN(data, &arg, sizeof(arg));
		if (error != 0) {
			ipf_interror = 60013;
			error = EFAULT;
		} else {
			if (arg == 0)
				ret = ipf_nat_flushtable();
			else if (arg == 1)
				ret = ipf_nat_clearlist();
			else
				ret = ipf_nat_extraflush(arg);
			appr_flush(arg);
		}

		if (getlock) {
			RWLOCK_EXIT(&ipf_nat);
		}
		if (error == 0) {
			error = BCOPYOUT(&ret, data, sizeof(ret));
		}
		break;

	case SIOCMATCHFLUSH :
		if (!(mode & FWRITE)) {
			ipf_interror = 60014;
			error = EPERM;
			break;
		}
		if (getlock) {
			WRITE_ENTER(&ipf_nat);
		}

		error = ipf_nat_matchflush(data);

		if (getlock) {
			RWLOCK_EXIT(&ipf_nat);
		}
		break;

	case SIOCPROXY :
		error = appr_ioctl(data, cmd, mode, ctx);
		break;

	case SIOCSTLCK :
		if (!(mode & FWRITE)) {
			ipf_interror = 60015;
			error = EPERM;
		} else {
			error = ipf_lock(data, &ipf_nat_lock);
		}
		break;

	case SIOCSTPUT :
		if ((mode & FWRITE) != 0) {
			error = ipf_nat_putent(data, getlock);
		} else {
			ipf_interror = 60016;
			error = EACCES;
		}
		break;

	case SIOCSTGSZ :
		if (ipf_nat_lock) {
			error = ipf_nat_getsz(data, getlock);
		} else {
			ipf_interror = 60017;
			error = EACCES;
		}
		break;

	case SIOCSTGET :
		if (ipf_nat_lock) {
			error = ipf_nat_getent(data, getlock);
		} else {
			ipf_interror = 60018;
			error = EACCES;
		}
		break;

	case SIOCGENITER :
	    {
		ipfgeniter_t iter;
		ipftoken_t *token;

		error = ipf_inobj(data, &iter, IPFOBJ_GENITER);
		if (error != 0)
			break;

		SPL_SCHED(s);
		token = ipf_findtoken(iter.igi_type, uid, ctx);
		if (token != NULL) {
			error  = ipf_nat_iterator(token, &iter);
		}
		RWLOCK_EXIT(&ipf_tokens);
		SPL_X(s);
		break;
	    }

	case SIOCIPFDELTOK :
		error = BCOPYIN(data, &arg, sizeof(arg));
		if (error == 0) {
			SPL_SCHED(s);
			error = ipf_deltoken(arg, uid, ctx);
			SPL_X(s);
		} else {
			ipf_interror = 60019;
			error = EFAULT;
		}
		break;

	case SIOCGTQTAB :
		error = ipf_outobj(data, ipf_nat_tqb, IPFOBJ_STATETQTAB);
		break;

	case SIOCGTABL :
		error = ipf_nat_gettable(data);
		break;

	default :
		ipf_interror = 60020;
		error = EINVAL;
		break;
	}
done:
	if (nt != NULL)
		KFREE(nt);
	return error;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_siocaddnat                                          */
/* Returns:     int - 0 == success, != 0 == failure                         */
/* Parameters:  n(I)       - pointer to new NAT rule                        */
/*              np(I)      - pointer to where to insert new NAT rule        */
/*              getlock(I) - flag indicating if lock on  is held            */
/* Mutex Locks: ipf_natio                                                   */
/*                                                                          */
/* Handle SIOCADNAT.  Resolve and calculate details inside the NAT rule     */
/* from information passed to the kernel, then add it  to the appropriate   */
/* NAT rule table(s).                                                       */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_siocaddnat(n, np, getlock)
	ipnat_t *n, **np;
	int getlock;
{
	int error = 0;
	int idx;

	/*
	 * This combination of flags is incompatible because in_flags will
	 * be checked for packets coming back in too.
	 */
	if ((n->in_flags & IPN_TCPUDP) && (n->in_redir & NAT_ENCAP)) {
		ipf_interror = 60021;
		return EINVAL;
	}

	if (ipf_nat_resolverule(n) != 0) {
		ipf_interror = 60022;
		return ENOENT;
	}

	if ((n->in_age[0] == 0) && (n->in_age[1] != 0)) {
		ipf_interror = 60023;
		return EINVAL;
	}

	n->in_use = 0;

	if ((n->in_flags & IPN_SIPRANGE) != 0)
		n->in_nsrcatype = FRI_RANGE;

	if ((n->in_flags & IPN_DIPRANGE) != 0)
		n->in_ndstatype = FRI_RANGE;

	if ((n->in_flags & IPN_SPLIT) != 0)
		n->in_ndstatype = FRI_SPLIT;

	if (n->in_redir == NAT_BIMAP) {
		n->in_ndstaddr = n->in_osrcaddr;
		n->in_ndstmsk = n->in_osrcmsk;
		n->in_odstaddr = n->in_nsrcaddr;
		n->in_odstmsk = n->in_nsrcmsk;

	}

	if ((n->in_redir & (NAT_MAP|NAT_REWRITE|NAT_DIVERTUDP)) != 0)
		n->in_spnext = n->in_spmin;

	if ((n->in_redir & (NAT_REWRITE|NAT_DIVERTUDP)) != 0) {
		n->in_dpnext = n->in_dpmin;
	} else if (n->in_redir == NAT_REDIRECT) {
		n->in_dpnext = n->in_dpmin;
	}

	n->in_stepnext = 0;

	if (n->in_redir & NAT_REDIRECT)
		idx = 1;
	else
		idx = 0;
	/*
	 * Initialise all of the address fields.
	 */
	error = ipf_nat_nextaddrinit(&n->in_osrc, 1, n->in_ifps[idx]);
	if (error != 0)
		return error;

	error = ipf_nat_nextaddrinit(&n->in_odst, 1, n->in_ifps[idx]);
	if (error != 0)
		return error;

	error = ipf_nat_nextaddrinit(&n->in_nsrc, 1, n->in_ifps[idx]);
	if (error != 0)
		return error;

	error = ipf_nat_nextaddrinit(&n->in_ndst, 1, n->in_ifps[idx]);
	if (error != 0)
		return error;

	if (getlock) {
		WRITE_ENTER(&ipf_nat);
	}
	n->in_next = NULL;
	*np = n;

	if (n->in_age[0] != 0)
		n->in_tqehead[0] = ipf_addtimeoutqueue(&ipf_nat_utqe,
						       n->in_age[0]);

	if (n->in_age[1] != 0)
		n->in_tqehead[1] = ipf_addtimeoutqueue(&ipf_nat_utqe,
						       n->in_age[1]);

	if (n->in_redir & NAT_REDIRECT) {
		n->in_flags &= ~IPN_NOTDST;
		ipf_nat_addrdr(n);
		if (n->in_redir & NAT_ENCAP)
			ipf_nat_addencap(n);
	}

	if (n->in_redir & (NAT_MAP|NAT_MAPBLK)) {
		n->in_flags &= ~IPN_NOTSRC;
		ipf_nat_addnat(n);
		if (n->in_redir & NAT_ENCAP)
			ipf_nat_addencap(n);
	}

	if (n->in_redir & (NAT_ENCAP|NAT_DIVERTUDP))
		ipf_nat_builddivertmp(n);

	MUTEX_INIT(&n->in_lock, "ipnat rule lock");

	n = NULL;
	ATOMIC_INC(ipf_nat_stats.ns_rules);
#if SOLARIS
	pfil_delayed_copy = 0;
#endif
	if (getlock) {
		RWLOCK_EXIT(&ipf_nat);			/* WRITE */
	}

	return error;
}


/* ------------------------------------------------------------------------ */
/* Function:    nat_resolvrule                                              */
/* Returns:     Nil                                                         */
/* Parameters:  n(I)  - pointer to NAT rule                                 */
/*                                                                          */
/* Handle SIOCADNAT.  Resolve and calculate details inside the NAT rule     */
/* from information passed to the kernel, then add it  to the appropriate   */
/* NAT rule table(s).                                                       */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_resolverule(n)
	ipnat_t *n;
{
	n->in_ifnames[0][LIFNAMSIZ - 1] = '\0';
	n->in_ifps[0] = ipf_resolvenic(n->in_ifnames[0], n->in_v);

	n->in_ifnames[1][LIFNAMSIZ - 1] = '\0';
	if (n->in_ifnames[1][0] == '\0') {
		(void) strncpy(n->in_ifnames[1], n->in_ifnames[0], LIFNAMSIZ);
		n->in_ifps[1] = n->in_ifps[0];
	} else {
		n->in_ifps[1] = ipf_resolvenic(n->in_ifnames[1], n->in_v);
	}

	if (n->in_plabel[0] != '\0') {
		if (n->in_redir & NAT_REDIRECT)
			n->in_apr = appr_lookup(n->in_pr[0], n->in_plabel);
		else
			n->in_apr = appr_lookup(n->in_pr[1], n->in_plabel);
		if (n->in_apr == NULL)
			return -1;
	}
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    nat_siocdelnat                                              */
/* Returns:     int - 0 == success, != 0 == failure                         */
/* Parameters:  n(I)       - pointer to new NAT rule                        */
/*              np(I)      - pointer to where to insert new NAT rule        */
/*              getlock(I) - flag indicating if lock on  is held            */
/* Mutex Locks: ipf_natio                                                   */
/*                                                                          */
/* Handle SIOCADNAT.  Resolve and calculate details inside the NAT rule     */
/* from information passed to the kernel, then add it  to the appropriate   */
/* NAT rule table(s).                                                       */
/* ------------------------------------------------------------------------ */
static void
ipf_nat_siocdelnat(n, np, getlock)
	ipnat_t *n, **np;
	int getlock;
{
	if (getlock) {
		WRITE_ENTER(&ipf_nat);
	}
	if (n->in_redir & NAT_REDIRECT)
		ipf_nat_delrdr(n);
	if (n->in_redir & (NAT_MAPBLK|NAT_MAP))
		ipf_nat_delnat(n);
	if (ipf_nat_list == NULL) {
		ipf_nat_map_masks = 0;
		ipf_nat_rdr_masks = 0;
	}

	if (n->in_tqehead[0] != NULL) {
		if (ipf_deletetimeoutqueue(n->in_tqehead[0]) == 0) {
			ipf_freetimeoutqueue(n->in_tqehead[1]);
		}
	}

	if (n->in_tqehead[1] != NULL) {
		if (ipf_deletetimeoutqueue(n->in_tqehead[1]) == 0) {
			ipf_freetimeoutqueue(n->in_tqehead[1]);
		}
	}

	*np = n->in_next;

	if (n->in_use == 0) {
		if (n->in_apr)
			appr_free(n->in_apr);
		KFREE(n);
		ATOMIC_DEC(ipf_nat_stats.ns_rules);
#if SOLARIS
		if (ipf_nat_stats.ns_rules == 0)
			pfil_delayed_copy = 1;
#endif
	} else {
		n->in_flags |= IPN_DELETE;
		n->in_next = NULL;
	}
	if (getlock) {
		RWLOCK_EXIT(&ipf_nat);			/* READ/WRITE */
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_getsz                                               */
/* Returns:     int - 0 == success, != 0 is the error value.                */
/* Parameters:  data(I)    - pointer to natget structure with kernel        */
/*                           pointer get the size of.                       */
/*              getlock(I) - flag indicating whether or not the caller      */
/*                           holds a lock on ipf_nat                        */
/*                                                                          */
/* Handle SIOCSTGSZ.                                                        */
/* Return the size of the nat list entry to be copied back to user space.   */
/* The size of the entry is stored in the ng_sz field and the enture natget */
/* structure is copied back to the user.                                    */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_getsz(data, getlock)
	caddr_t data;
	int getlock;
{
	ap_session_t *aps;
	nat_t *nat, *n;
	natget_t ng;
	int error;

	error = BCOPYIN(data, &ng, sizeof(ng));
	if (error != 0) {
		ipf_interror = 60024;
		return EFAULT;
	}

	if (getlock) {
		READ_ENTER(&ipf_nat);
	}

	nat = ng.ng_ptr;
	if (!nat) {
		nat = ipf_nat_instances;
		ng.ng_sz = 0;
		/*
		 * Empty list so the size returned is 0.  Simple.
		 */
		if (nat == NULL) {
			if (getlock) {
				RWLOCK_EXIT(&ipf_nat);
			}
			error = BCOPYOUT(&ng, data, sizeof(ng));
			if (error != 0) {
				ipf_interror = 60025;
				return EFAULT;
			}
			return 0;
		}
	} else {
		/*
		 * Make sure the pointer we're copying from exists in the
		 * current list of entries.  Security precaution to prevent
		 * copying of random kernel data.
		 */
		for (n = ipf_nat_instances; n; n = n->nat_next)
			if (n == nat)
				break;
		if (n == NULL) {
			if (getlock) {
				RWLOCK_EXIT(&ipf_nat);
			}
			ipf_interror = 60026;
			return ESRCH;
		}
	}

	/*
	 * Incluse any space required for proxy data structures.
	 */
	ng.ng_sz = sizeof(nat_save_t);
	aps = nat->nat_aps;
	if (aps != NULL) {
		ng.ng_sz += sizeof(ap_session_t) - 4;
		if (aps->aps_data != 0)
			ng.ng_sz += aps->aps_psiz;
	}
	if (getlock) {
		RWLOCK_EXIT(&ipf_nat);
	}

	error = BCOPYOUT(&ng, data, sizeof(ng));
	if (error != 0) {
		ipf_interror = 60027;
		return EFAULT;
	}
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_getent                                              */
/* Returns:     int - 0 == success, != 0 is the error value.                */
/* Parameters:  data(I)    - pointer to natget structure with kernel pointer*/
/*                           to NAT structure to copy out.                  */
/*              getlock(I) - flag indicating whether or not the caller      */
/*                           holds a lock on ipf_nat                        */
/*                                                                          */
/* Handle SIOCSTGET.                                                        */
/* Copies out NAT entry to user space.  Any additional data held for a      */
/* proxy is also copied, as to is the NAT rule which was responsible for it */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_getent(data, getlock)
	caddr_t data;
	int getlock;
{
	int error, outsize;
	ap_session_t *aps;
	nat_save_t *ipn, ipns;
	nat_t *n, *nat;

	error = ipf_inobj(data, &ipns, IPFOBJ_NATSAVE);
	if (error != 0)
		return error;

	if ((ipns.ipn_dsize < sizeof(ipns)) || (ipns.ipn_dsize > 81920)) {
		ipf_interror = 60028;
		return EINVAL;
	}

	KMALLOCS(ipn, nat_save_t *, ipns.ipn_dsize);
	if (ipn == NULL) {
		ipf_interror = 60029;
		return ENOMEM;
	}

	if (getlock) {
		READ_ENTER(&ipf_nat);
	}

	ipn->ipn_dsize = ipns.ipn_dsize;
	nat = ipns.ipn_next;
	if (nat == NULL) {
		nat = ipf_nat_instances;
		if (nat == NULL) {
			if (ipf_nat_instances == NULL) {
				ipf_interror = 60030;
				error = ENOENT;
			}
			goto finished;
		}
	} else {
		/*
		 * Make sure the pointer we're copying from exists in the
		 * current list of entries.  Security precaution to prevent
		 * copying of random kernel data.
		 */
		for (n = ipf_nat_instances; n; n = n->nat_next)
			if (n == nat)
				break;
		if (n == NULL) {
			ipf_interror = 60031;
			error = ESRCH;
			goto finished;
		}
	}
	ipn->ipn_next = nat->nat_next;

	/*
	 * Copy the NAT structure.
	 */
	bcopy((char *)nat, &ipn->ipn_nat, sizeof(*nat));

	/*
	 * If we have a pointer to the NAT rule it belongs to, save that too.
	 */
	if (nat->nat_ptr != NULL)
		bcopy((char *)nat->nat_ptr, (char *)&ipn->ipn_ipnat,
		      sizeof(ipn->ipn_ipnat));

	/*
	 * If we also know the NAT entry has an associated filter rule,
	 * save that too.
	 */
	if (nat->nat_fr != NULL)
		bcopy((char *)nat->nat_fr, (char *)&ipn->ipn_fr,
		      sizeof(ipn->ipn_fr));

	/*
	 * Last but not least, if there is an application proxy session set
	 * up for this NAT entry, then copy that out too, including any
	 * private data saved along side it by the proxy.
	 */
	aps = nat->nat_aps;
	outsize = ipn->ipn_dsize - sizeof(*ipn) + sizeof(ipn->ipn_data);
	if (aps != NULL) {
		char *s;

		if (outsize < sizeof(*aps)) {
			ipf_interror = 60032;
			error = ENOBUFS;
			goto finished;
		}

		s = ipn->ipn_data;
		bcopy((char *)aps, s, sizeof(*aps));
		s += sizeof(*aps);
		outsize -= sizeof(*aps);
		if ((aps->aps_data != NULL) && (outsize >= aps->aps_psiz))
			bcopy(aps->aps_data, s, aps->aps_psiz);
		else {
			ipf_interror = 60033;
			error = ENOBUFS;
		}
	}
	if (error == 0) {
		if (getlock) {
			READ_ENTER(&ipf_nat);
			getlock = 0;
		}
		error = ipf_outobjsz(data, ipn, IPFOBJ_NATSAVE, ipns.ipn_dsize);
	}

finished:
	if (getlock) {
		READ_ENTER(&ipf_nat);
	}
	if (ipn != NULL) {
		KFREES(ipn, ipns.ipn_dsize);
	}
	return error;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_putent                                              */
/* Returns:     int - 0 == success, != 0 is the error value.                */
/* Parameters:  data(I) -     pointer to natget structure with NAT          */
/*                            structure information to load into the kernel */
/*              getlock(I) - flag indicating whether or not a write lock    */
/*                           on  is already held.                    */
/*                                                                          */
/* Handle SIOCSTPUT.                                                        */
/* Loads a NAT table entry from user space, including a NAT rule, proxy and */
/* firewall rule data structures, if pointers to them indicate so.          */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_putent(data, getlock)
	caddr_t data;
	int getlock;
{
	nat_save_t ipn, *ipnn;
	ap_session_t *aps;
	nat_t *n, *nat;
	frentry_t *fr;
	fr_info_t fin;
	ipnat_t *in;
	int error;

	error = ipf_inobj(data, &ipn, IPFOBJ_NATSAVE);
	if (error != 0)
		return error;

	/*
	 * Initialise early because of code at junkput label.
	 */
	in = NULL;
	aps = NULL;
	nat = NULL;
	ipnn = NULL;
	fr = NULL;

	/*
	 * New entry, copy in the rest of the NAT entry if it's size is more
	 * than just the nat_t structure.
	 */
	if (ipn.ipn_dsize > sizeof(ipn)) {
		if (ipn.ipn_dsize > 81920) {
			ipf_interror = 60034;
			error = ENOMEM;
			goto junkput;
		}

		KMALLOCS(ipnn, nat_save_t *, ipn.ipn_dsize);
		if (ipnn == NULL) {
			ipf_interror = 60035;
			return ENOMEM;
		}

		error = ipf_inobjsz(data, ipnn, IPFOBJ_NATSAVE, ipn.ipn_dsize);
		if (error != 0) {
			goto junkput;
		}
	} else
		ipnn = &ipn;

	KMALLOC(nat, nat_t *);
	if (nat == NULL) {
		ipf_interror = 60037;
		error = ENOMEM;
		goto junkput;
	}

	bcopy((char *)&ipnn->ipn_nat, (char *)nat, sizeof(*nat));
	/*
	 * Initialize all these so that ipf_nat_delete() doesn't cause a crash.
	 */
	bzero((char *)nat, offsetof(struct nat, nat_tqe));
	nat->nat_tqe.tqe_pnext = NULL;
	nat->nat_tqe.tqe_next = NULL;
	nat->nat_tqe.tqe_ifq = NULL;
	nat->nat_tqe.tqe_parent = nat;

	/*
	 * Restore the rule associated with this nat session
	 */
	in = ipnn->ipn_nat.nat_ptr;
	if (in != NULL) {
		KMALLOC(in, ipnat_t *);
		nat->nat_ptr = in;
		if (in == NULL) {
			ipf_interror = 60038;
			error = ENOMEM;
			goto junkput;
		}
		bzero((char *)in, offsetof(struct ipnat, in_space));
		bcopy((char *)&ipnn->ipn_ipnat, (char *)in, sizeof(*in));
		in->in_use = 1;
		in->in_flags |= IPN_DELETE;

		ATOMIC_INC(ipf_nat_stats.ns_rules);

		if (ipf_nat_resolverule(in) != 0) {
			ipf_interror = 60039;
			error = ESRCH;
			goto junkput;
		}
	}

	/*
	 * Check that the NAT entry doesn't already exist in the kernel.
	 *
	 * For NAT_OUTBOUND, we're lookup for a duplicate MAP entry.  To do
	 * this, we check to see if the inbound combination of addresses and
	 * ports is already known.  Similar logic is applied for NAT_INBOUND.
	 *
	 */
	bzero((char *)&fin, sizeof(fin));
	fin.fin_p = nat->nat_pr[0];
	fin.fin_ifp = nat->nat_ifps[0];
	fin.fin_data[0] = ntohs(nat->nat_ndport);
	fin.fin_data[1] = ntohs(nat->nat_nsport);

	if (nat->nat_dir == NAT_OUTBOUND) {
		if (getlock) {
			READ_ENTER(&ipf_nat);
		}
		n = ipf_nat_inlookup(&fin, nat->nat_flags, fin.fin_p,
				 nat->nat_ndstip, nat->nat_nsrcip);
		if (getlock) {
			RWLOCK_EXIT(&ipf_nat);
		}
		if (n != NULL) {
			ipf_interror = 60040;
			error = EEXIST;
			goto junkput;
		}
	} else if (nat->nat_dir == NAT_INBOUND) {
		if (getlock) {
			READ_ENTER(&ipf_nat);
		}
		n = ipf_nat_outlookup(&fin, nat->nat_flags, fin.fin_p,
				  nat->nat_ndstip, nat->nat_nsrcip);
		if (getlock) {
			RWLOCK_EXIT(&ipf_nat);
		}
		if (n != NULL) {
			ipf_interror = 60041;
			error = EEXIST;
			goto junkput;
		}
	} else {
		ipf_interror = 60042;
		error = EINVAL;
		goto junkput;
	}

	/*
	 * Restore ap_session_t structure.  Include the private data allocated
	 * if it was there.
	 */
	aps = nat->nat_aps;
	if (aps != NULL) {
		KMALLOC(aps, ap_session_t *);
		nat->nat_aps = aps;
		if (aps == NULL) {
			ipf_interror = 60043;
			error = ENOMEM;
			goto junkput;
		}
		bcopy(ipnn->ipn_data, (char *)aps, sizeof(*aps));
		if (in != NULL)
			aps->aps_apr = in->in_apr;
		else
			aps->aps_apr = NULL;
		if (aps->aps_psiz != 0) {
			if (aps->aps_psiz > 81920) {
				ipf_interror = 60044;
				error = ENOMEM;
				goto junkput;
			}
			KMALLOCS(aps->aps_data, void *, aps->aps_psiz);
			if (aps->aps_data == NULL) {
				ipf_interror = 60045;
				error = ENOMEM;
				goto junkput;
			}
			bcopy(ipnn->ipn_data + sizeof(*aps), aps->aps_data,
			      aps->aps_psiz);
		} else {
			aps->aps_psiz = 0;
			aps->aps_data = NULL;
		}
	}

	/*
	 * If there was a filtering rule associated with this entry then
	 * build up a new one.
	 */
	fr = nat->nat_fr;
	if (fr != NULL) {
		if ((nat->nat_flags & SI_NEWFR) != 0) {
			KMALLOC(fr, frentry_t *);
			nat->nat_fr = fr;
			if (fr == NULL) {
				ipf_interror = 60046;
				error = ENOMEM;
				goto junkput;
			}
			ipnn->ipn_nat.nat_fr = fr;
			fr->fr_ref = 1;
			(void) ipf_outobj(data, ipnn, IPFOBJ_NATSAVE);
			bcopy((char *)&ipnn->ipn_fr, (char *)fr, sizeof(*fr));

			fr->fr_ref = 1;
			fr->fr_dsize = 0;
			fr->fr_data = NULL;
			fr->fr_type = FR_T_NONE;

			MUTEX_NUKE(&fr->fr_lock);
			MUTEX_INIT(&fr->fr_lock, "nat-filter rule lock");
		} else {
			if (getlock) {
				READ_ENTER(&ipf_nat);
			}
			for (n = ipf_nat_instances; n; n = n->nat_next)
				if (n->nat_fr == fr)
					break;

			if (n != NULL) {
				MUTEX_ENTER(&fr->fr_lock);
				fr->fr_ref++;
				MUTEX_EXIT(&fr->fr_lock);
			}
			if (getlock) {
				RWLOCK_EXIT(&ipf_nat);
			}

			if (n == NULL) {
				ipf_interror = 60047;
				error = ESRCH;
				goto junkput;
			}
		}
	}

	if (ipnn != &ipn) {
		KFREES(ipnn, ipn.ipn_dsize);
		ipnn = NULL;
	}

	if (getlock) {
		WRITE_ENTER(&ipf_nat);
	}
	error = ipf_nat_insert(nat, nat->nat_rev);
	if ((error == 0) && (aps != NULL)) {
		aps->aps_next = ap_sess_list;
		ap_sess_list = aps;
	}
	if (getlock) {
		RWLOCK_EXIT(&ipf_nat);
	}

	if (error == 0)
		return 0;

	ipf_interror = 60048;
	error = ENOMEM;

junkput:
	if (fr != NULL) {
		(void) ipf_derefrule(&fr);
	}

	if ((ipnn != NULL) && (ipnn != &ipn)) {
		KFREES(ipnn, ipn.ipn_dsize);
	}
	if (nat != NULL) {
		if (aps != NULL) {
			if (aps->aps_data != NULL) {
				KFREES(aps->aps_data, aps->aps_psiz);
			}
			KFREE(aps);
		}
		if (in != NULL) {
			if (in->in_apr)
				appr_free(in->in_apr);
			KFREE(in);
		}
		KFREE(nat);
	}
	return error;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_delete                                              */
/* Returns:     Nil                                                         */
/* Parameters:  natd(I)    - pointer to NAT structure to delete             */
/*              logtype(I) - type of LOG record to create before deleting   */
/* Write Lock:  ipf_nat                                                     */
/*                                                                          */
/* Delete a nat entry from the various lists and table.  If NAT logging is  */
/* enabled then generate a NAT log record for this event.                   */
/* ------------------------------------------------------------------------ */
void
ipf_nat_delete(nat, logtype)
	struct nat *nat;
	int logtype;
{
	int madeorphan = 0, bkt, removed = 0;
	struct ipnat *ipn;

	if (logtype != 0 && ipf_nat_logging != 0)
		ipf_nat_log(nat, logtype);

	/*
	 * Take it as a general indication that all the pointers are set if
	 * nat_pnext is set.
	 */
	if (nat->nat_pnext != NULL) {
		removed = 1;

		bkt = nat->nat_hv[0];
		ipf_nat_stats.ns_side[0].ns_bucketlen[bkt]--;
		if (ipf_nat_stats.ns_side[0].ns_bucketlen[bkt] == 0) {
			ipf_nat_stats.ns_side[0].ns_inuse--;
		}
		bkt = nat->nat_hv[1];
		ipf_nat_stats.ns_side[1].ns_bucketlen[bkt]--;
		if (ipf_nat_stats.ns_side[1].ns_bucketlen[bkt] == 0) {
			ipf_nat_stats.ns_side[1].ns_inuse--;
		}

		*nat->nat_pnext = nat->nat_next;
		if (nat->nat_next != NULL) {
			nat->nat_next->nat_pnext = nat->nat_pnext;
			nat->nat_next = NULL;
		}
		nat->nat_pnext = NULL;

		*nat->nat_phnext[0] = nat->nat_hnext[0];
		if (nat->nat_hnext[0] != NULL) {
			nat->nat_hnext[0]->nat_phnext[0] = nat->nat_phnext[0];
			nat->nat_hnext[0] = NULL;
		}
		nat->nat_phnext[0] = NULL;

		*nat->nat_phnext[1] = nat->nat_hnext[1];
		if (nat->nat_hnext[1] != NULL) {
			nat->nat_hnext[1]->nat_phnext[1] = nat->nat_phnext[1];
			nat->nat_hnext[1] = NULL;
		}
		nat->nat_phnext[1] = NULL;

		if ((nat->nat_flags & SI_WILDP) != 0) {
			ATOMIC_DEC(ipf_nat_stats.ns_wilds);
		}
		madeorphan = 1;
	}

	if (nat->nat_me != NULL) {
		*nat->nat_me = NULL;
		nat->nat_me = NULL;
	}

	if (nat->nat_tqe.tqe_ifq != NULL)
		ipf_deletequeueentry(&nat->nat_tqe);

	if (logtype == NL_EXPIRE)
		ipf_nat_stats.ns_expire++;

	MUTEX_ENTER(&nat->nat_lock);
	/*
	 * NL_DESTROY should only be passed in when we've got nat_ref >= 2.
	 * This happens when a nat'd packet is blocked and we want to throw
	 * away the NAT session.
	 */
	if (logtype == NL_DESTROY) {
		if (nat->nat_ref > 2) {
			nat->nat_ref -= 2;
			MUTEX_EXIT(&nat->nat_lock);
			if (removed)
				ipf_nat_stats.ns_orphans++;
			return;
		}
	} else if (nat->nat_ref > 1) {
		nat->nat_ref--;
		MUTEX_EXIT(&nat->nat_lock);
		if (madeorphan == 1)
			ipf_nat_stats.ns_orphans++;
		return;
	}
	MUTEX_EXIT(&nat->nat_lock);

	nat->nat_ref = 0;

	if (madeorphan == 0)
		ipf_nat_stats.ns_orphans--;

	/*
	 * At this point, nat_ref can be either 0 or -1
	 */
	if (nat->nat_flags & SI_WILDP)
		ipf_nat_stats.ns_wilds--;
	ipf_nat_stats.ns_proto[nat->nat_pr[0]]--;

#ifdef	IPFILTER_SYNC
	if (nat->nat_sync)
		ipf_sync_del_nat(nat->nat_sync);
#endif

	if (nat->nat_fr != NULL) {
		(void) ipf_derefrule(&nat->nat_fr);
	}

	if (nat->nat_hm != NULL) {
		ipf_nat_hostmapdel(&nat->nat_hm);
	}

	/*
	 * If there is an active reference from the nat entry to its parent
	 * rule, decrement the rule's reference count and free it too if no
	 * longer being used.
	 */
	ipn = nat->nat_ptr;
	nat->nat_ptr = NULL;

	if (ipn != NULL) {
		ipf_nat_rulederef(&ipn);
	}

	MUTEX_DESTROY(&nat->nat_lock);

	aps_free(nat->nat_aps);
	ipf_nat_stats.ns_active--;

	/*
	 * If there's a fragment table entry too for this nat entry, then
	 * dereference that as well.  This is after nat_lock is released
	 * because of Tru64.
	 */
	ipf_frag_natforget((void *)nat);

	KFREE(nat);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_flushtable                                          */
/* Returns:     int - number of NAT rules deleted                           */
/* Parameters:  Nil                                                         */
/* Write Lock:  ipf_nat                                                     */
/*                                                                          */
/* Deletes all currently active NAT sessions.  In deleting each NAT entry a */
/* log record should be emitted in ipf_nat_delete() if NAT logging is       */
/* enabled.                                                                 */
/* ------------------------------------------------------------------------ */
/*
 * nat_flushtable - clear the NAT table of all mapping entries.
 */
static int
ipf_nat_flushtable()
{
	nat_t *nat;
	int j = 0;

	/*
	 * ALL NAT mappings deleted, so lets just make the deletions
	 * quicker.
	 */
	if (ipf_nat_table[0] != NULL)
		bzero((char *)ipf_nat_table[0],
		      sizeof(ipf_nat_table[0]) * ipf_nat_table_sz);
	if (ipf_nat_table[1] != NULL)
		bzero((char *)ipf_nat_table[1],
		      sizeof(ipf_nat_table[1]) * ipf_nat_table_sz);

	while ((nat = ipf_nat_instances) != NULL) {
		ipf_nat_delete(nat, NL_FLUSH);
		j++;
	}

	return j;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_clearlist                                           */
/* Returns:     int - number of NAT/RDR rules deleted                       */
/* Parameters:  Nil                                                         */
/*                                                                          */
/* Delete all rules in the current list of rules.  There is nothing elegant */
/* about this cleanup: simply free all entries on the list of rules and     */
/* clear out the tables used for hashed NAT rule lookups.                   */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_clearlist()
{
	ipnat_t *n, **np = &ipf_nat_list;
	int i = 0;

	if (ipf_nat_map_rules != NULL) {
		bzero((char *)ipf_nat_map_rules,
		      sizeof(*ipf_nat_map_rules) * ipf_nat_maprules_sz);
	}
	if (ipf_nat_rdr_rules != NULL) {
		bzero((char *)ipf_nat_rdr_rules,
		      sizeof(*ipf_nat_rdr_rules) * ipf_nat_rdrrules_sz);
	}

	while ((n = *np) != NULL) {
		*np = n->in_next;
		ipf_nat_delrule(n);
		i++;
	}
#if SOLARIS
	pfil_delayed_copy = 1;
#endif
	ipf_nat_map_masks = 0;
	ipf_nat_rdr_masks = 0;
	return i;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_delrule                                             */
/* Returns:     Nil                                                         */
/* Parameters:  np(I) - pointer to NAT rule to delete                       */
/*                                                                          */
/* ------------------------------------------------------------------------ */
static void
ipf_nat_delrule(np)
	ipnat_t *np;
{
	if (np->in_use == 0) {
		if (np->in_apr != NULL)
			appr_free(np->in_apr);

		if (np->in_divmp != NULL) {
			FREE_MB_T(np->in_divmp);
		}

		KFREE(np);
		ipf_nat_stats.ns_rules--;
	} else {
		np->in_flags |= IPN_DELETE;
		np->in_next = NULL;
	}

}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_newmap                                              */
/* Returns:     int - -1 == error, 0 == success                             */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              nat(I) - pointer to NAT entry                               */
/*              ni(I)  - pointer to structure with misc. information needed */
/*                       to create new NAT entry.                           */
/*                                                                          */
/* Given an empty NAT structure, populate it with new information about a   */
/* new NAT session, as defined by the matching NAT rule.                    */
/* ni.nai_ip is passed in uninitialised and must be set, in host byte order,*/
/* to the new IP address for the translation.                               */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_newmap(fin, nat, ni)
	fr_info_t *fin;
	nat_t *nat;
	natinfo_t *ni;
{
	u_short st_port, dport, sport, port, sp, dp;
	struct in_addr in, inb;
	hostmap_t *hm;
	u_32_t flags;
	u_32_t st_ip;
	ipnat_t *np;
	nat_t *natl;
	int l;

	/*
	 * If it's an outbound packet which doesn't match any existing
	 * record, then create a new port
	 */
	l = 0;
	hm = NULL;
	np = ni->nai_np;
	st_ip = np->in_snip;
	st_port = np->in_spnext;
	flags = ni->nai_flags;

	if (flags & IPN_ICMPQUERY) {
		sport = fin->fin_data[1];
		dport = 0;
	} else {
		sport = htons(fin->fin_data[0]);
		dport = htons(fin->fin_data[1]);
	}

	/*
	 * Do a loop until we either run out of entries to try or we find
	 * a NAT mapping that isn't currently being used.  This is done
	 * because the change to the source is not (usually) being fixed.
	 */
	do {
		port = 0;
		in.s_addr = htonl(np->in_snip);
		if (l == 0) {
			/*
			 * Check to see if there is an existing NAT
			 * setup for this IP address pair.
			 */
			hm = ipf_nat_hostmap(np, fin->fin_src, fin->fin_dst,
					 in, 0);
			if (hm != NULL)
				in.s_addr = hm->hm_nsrcip.s_addr;
		} else if ((l == 1) && (hm != NULL)) {
			ipf_nat_hostmapdel(&hm);
		}
		in.s_addr = ntohl(in.s_addr);

		nat->nat_hm = hm;

		if ((np->in_nsrcmsk == 0xffffffff) && (np->in_spnext == 0)) {
			if (l > 0) {
				ATOMIC_INCL(ipf_nat_stats.ns_side[1].
					    ns_exhausted);
				return -1;
			}
		}

		if (np->in_redir == NAT_BIMAP &&
		    np->in_osrcmsk == np->in_nsrcmsk) {
			/*
			 * map the address block in a 1:1 fashion
			 */
			in.s_addr = np->in_nsrcaddr;
			in.s_addr |= fin->fin_saddr & ~np->in_osrcmsk;
			in.s_addr = ntohl(in.s_addr);

		} else if (np->in_redir & NAT_MAPBLK) {
			if ((l >= np->in_ppip) || ((l > 0) &&
			     !(flags & IPN_TCPUDP))) {
				ATOMIC_INCL(ipf_nat_stats.ns_side[1].
					    ns_exhausted);
				return -1;
			}
			/*
			 * map-block - Calculate destination address.
			 */
			in.s_addr = ntohl(fin->fin_saddr);
			in.s_addr &= ntohl(~np->in_osrcmsk);
			inb.s_addr = in.s_addr;
			in.s_addr /= np->in_ippip;
			in.s_addr &= ntohl(~np->in_nsrcmsk);
			in.s_addr += ntohl(np->in_nsrcaddr);
			/*
			 * Calculate destination port.
			 */
			if ((flags & IPN_TCPUDP) &&
			    (np->in_ppip != 0)) {
				port = ntohs(sport) + l;
				port %= np->in_ppip;
				port += np->in_ppip *
					(inb.s_addr % np->in_ippip);
				port += MAPBLK_MINPORT;
				port = htons(port);
			}

		} else if ((np->in_nsrcaddr == 0) &&
			   (np->in_nsrcmsk == 0xffffffff)) {
			i6addr_t in6;

			/*
			 * 0/32 - use the interface's IP address.
			 */
			if ((l > 0) ||
			    ipf_ifpaddr(fin->fin_v, FRI_NORMAL, fin->fin_ifp,
				       &in6, NULL) == -1) {
				ATOMIC_INCL(ipf_nat_stats.ns_side[1].
					    ns_new_ifpaddr);
				return -1;
			}
			if (fin->fin_v == 4)
				in.s_addr = ntohl(in6.in4.s_addr);

		} else if ((np->in_nsrcaddr == 0) && (np->in_nsrcmsk == 0)) {
			/*
			 * 0/0 - use the original source address/port.
			 */
			if (l > 0) {
				ATOMIC_INCL(ipf_nat_stats.ns_side[1].
					    ns_exhausted);
				return -1;
			}
			in.s_addr = ntohl(fin->fin_saddr);

		} else if ((np->in_nsrcmsk != 0xffffffff) &&
			   (np->in_spnext == 0) && ((l > 0) || (hm == NULL)))
			np->in_snip++;

		natl = NULL;

		if ((flags & IPN_TCPUDP) &&
		    ((np->in_redir & NAT_MAPBLK) == 0) &&
		    (np->in_flags & IPN_AUTOPORTMAP)) {
			/*
			 * "ports auto" (without map-block)
			 */
			if ((l > 0) && (l % np->in_ppip == 0)) {
				if ((l > np->in_ppip) &&
				    np->in_nsrcmsk != 0xffffffff)
					np->in_snip++;
			}
			if (np->in_ppip != 0) {
				port = ntohs(sport);
				port += (l % np->in_ppip);
				port %= np->in_ppip;
				port += np->in_ppip *
					(ntohl(fin->fin_saddr) %
					 np->in_ippip);
				port += MAPBLK_MINPORT;
				port = htons(port);
			}

		} else if (((np->in_redir & NAT_MAPBLK) == 0) &&
			   (flags & IPN_TCPUDPICMP) && (np->in_spnext != 0)) {
			/*
			 * Standard port translation.  Select next port.
			 */
			port = htons(np->in_spnext++);

			if (np->in_spnext > np->in_spmax) {
				np->in_spnext = np->in_spmin;
				if (np->in_nsrcmsk != 0xffffffff)
					np->in_snip++;
			}
		}

		if (np->in_flags & IPN_SIPRANGE) {
			if (np->in_snip > ntohl(np->in_nsrcmsk))
				np->in_snip = ntohl(np->in_nsrcaddr);
		} else {
			if ((np->in_nsrcmsk != 0xffffffff) &&
			    ((np->in_snip + 1) & ntohl(np->in_nsrcmsk)) >
			    ntohl(np->in_nsrcaddr))
				np->in_snip = ntohl(np->in_nsrcaddr) + 1;
		}

		if ((port == 0) && (flags & (IPN_TCPUDPICMP|IPN_ICMPQUERY)))
			port = sport;

		/*
		 * Here we do a lookup of the connection as seen from
		 * the outside.  If an IP# pair already exists, try
		 * again.  So if you have A->B becomes C->B, you can
		 * also have D->E become C->E but not D->B causing
		 * another C->B.  Also take protocol and ports into
		 * account when determining whether a pre-existing
		 * NAT setup will cause an external conflict where
		 * this is appropriate.
		 */
		inb.s_addr = htonl(in.s_addr);
		sp = fin->fin_data[0];
		dp = fin->fin_data[1];
		fin->fin_data[0] = fin->fin_data[1];
		fin->fin_data[1] = ntohs(port);
		natl = ipf_nat_inlookup(fin, flags & ~(SI_WILDP|NAT_SEARCH),
				    (u_int)fin->fin_p, fin->fin_dst, inb);
		fin->fin_data[0] = sp;
		fin->fin_data[1] = dp;

		/*
		 * Has the search wrapped around and come back to the
		 * start ?
		 */
		if ((natl != NULL) &&
		    (np->in_spnext != 0) && (st_port == np->in_spnext) &&
		    (np->in_snip != 0) && (st_ip == np->in_snip)) {
			ATOMIC_INCL(ipf_nat_stats.ns_side[1].ns_wrap);
			return -1;
		}
		l++;
	} while (natl != NULL);

	/* Setup the NAT table */
	nat->nat_osrcip = fin->fin_src;
	nat->nat_nsrcaddr = htonl(in.s_addr);
	nat->nat_odstip = fin->fin_dst;
	nat->nat_ndstip = fin->fin_dst;
	if (nat->nat_hm == NULL)
		nat->nat_hm = ipf_nat_hostmap(np, fin->fin_src, fin->fin_dst,
					  nat->nat_nsrcip, 0);

	if (flags & IPN_TCPUDP) {
		nat->nat_osport = sport;
		nat->nat_nsport = port;	/* sport */
		nat->nat_odport = dport;
		nat->nat_ndport = dport;
		((tcphdr_t *)fin->fin_dp)->th_sport = port;
	} else if (flags & IPN_ICMPQUERY) {
		nat->nat_oicmpid = fin->fin_data[1];
		((icmphdr_t *)fin->fin_dp)->icmp_id = port;
		nat->nat_nicmpid = port;
	}
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_newrdr                                              */
/* Returns:     int - -1 == error, 0 == success (no move), 1 == success and */
/*                    allow rule to be moved if IPN_ROUNDR is set.          */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              nat(I) - pointer to NAT entry                               */
/*              ni(I)  - pointer to structure with misc. information needed */
/*                       to create new NAT entry.                           */
/*                                                                          */
/* ni.nai_ip is passed in uninitialised and must be set, in host byte order,*/
/* to the new IP address for the translation.                               */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_newrdr(fin, nat, ni)
	fr_info_t *fin;
	nat_t *nat;
	natinfo_t *ni;
{
	u_short nport, dport, sport;
	struct in_addr in, inb;
	u_short sp, dp;
	hostmap_t *hm;
	u_32_t flags;
	ipnat_t *np;
	nat_t *natl;
	int move;

	move = 1;
	hm = NULL;
	in.s_addr = 0;
	np = ni->nai_np;
	flags = ni->nai_flags;

	if (flags & IPN_ICMPQUERY) {
		dport = fin->fin_data[1];
		sport = 0;
	} else {
		sport = htons(fin->fin_data[0]);
		dport = htons(fin->fin_data[1]);
	}

	/* TRACE sport, dport */


	/*
	 * If the matching rule has IPN_STICKY set, then we want to have the
	 * same rule kick in as before.  Why would this happen?  If you have
	 * a collection of rdr rules with "round-robin sticky", the current
	 * packet might match a different one to the previous connection but
	 * we want the same destination to be used.
	 */
	if (((np->in_flags & (IPN_ROUNDR|IPN_SPLIT)) != 0) &&
	    ((np->in_flags & IPN_STICKY) != 0)) {
		hm = ipf_nat_hostmap(NULL, fin->fin_src, fin->fin_dst, in,
				     (u_32_t)dport);
		if (hm != NULL) {
			in.s_addr = ntohl(hm->hm_ndstip.s_addr);
			np = hm->hm_ipnat;
			ni->nai_np = np;
			move = 0;
		}
	}

	/*
	 * Otherwise, it's an inbound packet. Most likely, we don't
	 * want to rewrite source ports and source addresses. Instead,
	 * we want to rewrite to a fixed internal address and fixed
	 * internal port.
	 */
	if (np->in_flags & IPN_SPLIT) {
		in.s_addr = np->in_dnip;

		if ((np->in_flags & (IPN_ROUNDR|IPN_STICKY)) == IPN_STICKY) {
			hm = ipf_nat_hostmap(NULL, fin->fin_src, fin->fin_dst,
					     in, (u_32_t)dport);
			if (hm != NULL) {
				in.s_addr = hm->hm_ndstip.s_addr;
				move = 0;
			}
		}

		if (hm == NULL || hm->hm_ref == 1) {
			if (np->in_ndstaddr == htonl(in.s_addr)) {
				np->in_dnip = ntohl(np->in_ndstmsk);
				move = 0;
			} else {
				np->in_dnip = ntohl(np->in_ndstaddr);
			}
		}

	} else if ((np->in_ndstaddr == 0) && (np->in_ndstmsk == 0xffffffff)) {
		i6addr_t in6;

		/*
		 * 0/32 - use the interface's IP address.
		 */
		if (ipf_ifpaddr(fin->fin_v, FRI_NORMAL, fin->fin_ifp,
			       &in6, NULL) == -1) {
			ATOMIC_INCL(ipf_nat_stats.ns_side[0].ns_new_ifpaddr);
			return -1;
		}
		if (fin->fin_v == 4)
			in.s_addr = ntohl(in6.in4.s_addr);

	} else if ((np->in_ndstaddr == 0) && (np->in_ndstmsk== 0)) {
		/*
		 * 0/0 - use the original destination address/port.
		 */
		in.s_addr = ntohl(fin->fin_daddr);

	} else if (np->in_redir == NAT_BIMAP &&
		   np->in_ndstmsk == np->in_odstmsk) {
		/*
		 * map the address block in a 1:1 fashion
		 */
		in.s_addr = np->in_ndstaddr;
		in.s_addr |= fin->fin_daddr & ~np->in_ndstmsk;
		in.s_addr = ntohl(in.s_addr);
	} else {
		in.s_addr = ntohl(np->in_ndstaddr);
	}

	if ((np->in_dpnext == 0) || ((flags & NAT_NOTRULEPORT) != 0))
		nport = dport;
	else {
		/*
		 * Whilst not optimized for the case where
		 * pmin == pmax, the gain is not significant.
		 */
		if (((np->in_flags & IPN_FIXEDDPORT) == 0) &&
		    (np->in_odport != np->in_dtop)) {
			nport = ntohs(dport) - np->in_odport + np->in_dpmax;
			nport = htons(nport);
		} else {
			nport = htons(np->in_dpnext);
			np->in_dpnext++;
			if (np->in_dpnext > np->in_dpmax)
				np->in_dpnext = np->in_dpmin;
		}
	}

	/*
	 * When the redirect-to address is set to 0.0.0.0, just
	 * assume a blank `forwarding' of the packet.  We don't
	 * setup any translation for this either.
	 */
	if (in.s_addr == 0) {
		if (nport == dport) {
			ATOMIC_INCL(ipf_nat_stats.ns_side[0].ns_xlate_null);
			return -1;
		}
		in.s_addr = ntohl(fin->fin_daddr);
	}

	/*
	 * Check to see if this redirect mapping already exists and if
	 * it does, return "failure" (allowing it to be created will just
	 * cause one or both of these "connections" to stop working.)
	 */
	inb.s_addr = htonl(in.s_addr);
	sp = fin->fin_data[0];
	dp = fin->fin_data[1];
	fin->fin_data[1] = fin->fin_data[0];
	fin->fin_data[0] = ntohs(nport);
	natl = ipf_nat_outlookup(fin, flags & ~(SI_WILDP|NAT_SEARCH),
			     (u_int)fin->fin_p, inb, fin->fin_src);
	fin->fin_data[0] = sp;
	fin->fin_data[1] = dp;
	if (natl != NULL) {
		ATOMIC_INCL(ipf_nat_stats.ns_side[0].ns_xlate_exists);
		return -1;
	}

	nat->nat_ndstaddr = htonl(in.s_addr);
	nat->nat_odstip = fin->fin_dst;
	nat->nat_nsrcip = fin->fin_src;
	nat->nat_osrcip = fin->fin_src;
	if ((nat->nat_hm == NULL) && ((np->in_flags & IPN_STICKY) != 0))
		nat->nat_hm = ipf_nat_hostmap(np, fin->fin_src, fin->fin_dst,
					      in, (u_32_t)dport);

	if (flags & IPN_TCPUDP) {
		nat->nat_odport = dport;
		nat->nat_ndport = nport;
		nat->nat_osport = sport;
		nat->nat_nsport = sport;
		((tcphdr_t *)fin->fin_dp)->th_dport = nport;
	} else if (flags & IPN_ICMPQUERY) {
		nat->nat_oicmpid = fin->fin_data[1];
		((icmphdr_t *)fin->fin_dp)->icmp_id = nport;
		nat->nat_nicmpid = nport;
	}

	return move;
}

/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_add                                                 */
/* Returns:     nat_t* - NULL == failure to create new NAT structure,       */
/*                       else pointer to new NAT structure                  */
/* Parameters:  fin(I)       - pointer to packet information                */
/*              np(I)        - pointer to NAT rule                          */
/*              natsave(I)   - pointer to where to store NAT struct pointer */
/*              flags(I)     - flags describing the current packet          */
/*              direction(I) - direction of packet (in/out)                 */
/* Write Lock:  ipf_nat                                                     */
/*                                                                          */
/* Attempts to create a new NAT entry.  Does not actually change the packet */
/* in any way.                                                              */
/*                                                                          */
/* This fucntion is in three main parts: (1) deal with creating a new NAT   */
/* structure for a "MAP" rule (outgoing NAT translation); (2) deal with     */
/* creating a new NAT structure for a "RDR" rule (incoming NAT translation) */
/* and (3) building that structure and putting it into the NAT table(s).    */
/*                                                                          */
/* NOTE: natsave should NOT be used top point back to an ipstate_t struct   */
/*       as it can result in memory being corrupted.                        */
/* ------------------------------------------------------------------------ */
nat_t *
ipf_nat_add(fin, np, natsave, flags, direction)
	fr_info_t *fin;
	ipnat_t *np;
	nat_t **natsave;
	u_int flags;
	int direction;
{
	hostmap_t *hm = NULL;
	nat_t *nat, *natl;
	u_int nflags;
	natinfo_t ni;
	int move;
#if SOLARIS && defined(_KERNEL) && (SOLARIS2 >= 6) && defined(ICK_M_CTL_MAGIC)
	qpktinfo_t *qpi = fin->fin_qpi;
#endif

	if ((ipf_nat_stats.ns_active * 100 / ipf_nat_table_max) >
	    ipf_nat_table_wm_high) {
		ipf_nat_doflush = 1;
	}

	if (ipf_nat_stats.ns_active >= ipf_nat_table_max) {
		ipf_nat_stats.ns_side[fin->fin_out].ns_table_max++;
		return NULL;
	}

	move = 1;
	nflags = np->in_flags & flags;
	nflags &= NAT_FROMRULE;

	ni.nai_np = np;
	ni.nai_nflags = nflags;
	ni.nai_flags = flags;
	ni.nai_dport = 0;
	ni.nai_sport = 0;

	/* Give me a new nat */
	KMALLOC(nat, nat_t *);
	if (nat == NULL) {
		ipf_nat_stats.ns_side[fin->fin_out].ns_memfail++;
		/*
		 * Try to automatically tune the max # of entries in the
		 * table allowed to be less than what will cause kmem_alloc()
		 * to fail and try to eliminate panics due to out of memory
		 * conditions arising.
		 */
		if ((ipf_nat_table_max > ipf_nat_table_sz) &&
		    (ipf_nat_stats.ns_active > 100)) {
			ipf_nat_table_max = ipf_nat_stats.ns_active - 100;
			printf("table_max reduced to %d\n",
				ipf_nat_table_max);
		}
		return NULL;
	}

	if (flags & IPN_ICMPQUERY) {
		/*
		 * In the ICMP query NAT code, we translate the ICMP id fields
		 * to make them unique. This is indepedent of the ICMP type
		 * (e.g. in the unlikely event that a host sends an echo and
		 * an tstamp request with the same id, both packets will have
		 * their ip address/id field changed in the same way).
		 */
		/* The icmp_id field is used by the sender to identify the
		 * process making the icmp request. (the receiver justs
		 * copies it back in its response). So, it closely matches
		 * the concept of source port. We overlay sport, so we can
		 * maximally reuse the existing code.
		 */
		ni.nai_sport = fin->fin_data[1];
		ni.nai_dport = 0;
	}

	bzero((char *)nat, sizeof(*nat));
	nat->nat_flags = flags;
	nat->nat_redir = np->in_redir;
	nat->nat_dir = direction;
	nat->nat_pr[0] = fin->fin_p;
	nat->nat_pr[1] = fin->fin_p;

	if ((flags & NAT_SLAVE) == 0) {
		MUTEX_ENTER(&ipf_nat_new);
	}

	/*
	 * Search the current table for a match and create a new mapping
	 * if there is none found.
	 */
	if (np->in_redir & (NAT_ENCAP|NAT_DIVERTUDP)) {
		move = ipf_nat_newdivert(fin, nat, &ni);

	} else if (np->in_redir & NAT_REWRITE) {
		move = ipf_nat_newrewrite(fin, nat, &ni);

	} else if (direction == NAT_OUTBOUND) {
		/*
		 * We can now arrange to call this for the same connection
		 * because ipf_nat_new doesn't protect the code path into
		 * this function.
		 */
		natl = ipf_nat_outlookup(fin, nflags, (u_int)fin->fin_p,
				     fin->fin_src, fin->fin_dst);
		if (natl != NULL) {
			KFREE(nat);
			nat = natl;
			goto done;
		}

		move = ipf_nat_newmap(fin, nat, &ni);
	} else {
		/*
		 * NAT_INBOUND is used for redirects rules
		 */
		natl = ipf_nat_inlookup(fin, nflags, (u_int)fin->fin_p,
				    fin->fin_src, fin->fin_dst);
		if (natl != NULL) {
			KFREE(nat);
			nat = natl;
			goto done;
		}

		move = ipf_nat_newrdr(fin, nat, &ni);
	}
	if (move == -1)
		goto badnat;

	np = ni.nai_np;

	if ((move == 1) && (np->in_flags & IPN_ROUNDR)) {
		if ((np->in_redir & (NAT_REDIRECT|NAT_MAP)) == NAT_REDIRECT) {
			ipf_nat_delrdr(np);
			ipf_nat_addrdr(np);
		} else if ((np->in_redir & (NAT_REDIRECT|NAT_MAP)) == NAT_MAP) {
			ipf_nat_delnat(np);
			ipf_nat_addnat(np);
		}
	}

	if (ipf_nat_finalise(fin, nat, &ni, natsave, direction) == -1) {
		goto badnat;
	}

	if (flags & SI_WILDP)
		ipf_nat_stats.ns_wilds++;
	ipf_nat_stats.ns_proto[nat->nat_pr[0]]++;

	goto done;
badnat:
	ipf_nat_stats.ns_side[fin->fin_out].ns_badnatnew++;
	if ((hm = nat->nat_hm) != NULL)
		ipf_nat_hostmapdel(&hm);
	KFREE(nat);
	nat = NULL;
done:
	if ((flags & NAT_SLAVE) == 0) {
		MUTEX_EXIT(&ipf_nat_new);
	}
	return nat;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_finalise                                            */
/* Returns:     int - 0 == sucess, -1 == failure                            */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              nat(I) - pointer to NAT entry                               */
/*              ni(I)  - pointer to structure with misc. information needed */
/*                       to create new NAT entry.                           */
/* Write Lock:                                                       */
/*                                                                          */
/* This is the tail end of constructing a new NAT entry and is the same     */
/* for both IPv4 and IPv6.                                                  */
/* ------------------------------------------------------------------------ */
/*ARGSUSED*/
static int
ipf_nat_finalise(fin, nat, ni, natsave, direction)
	fr_info_t *fin;
	nat_t *nat;
	natinfo_t *ni;
	nat_t **natsave;
	int direction;
{
	u_32_t sum1, sum2, sumd;
	frentry_t *fr;
	ipnat_t *np;
	u_32_t flags;

	np = ni->nai_np;
	flags = ni->nai_flags;

	switch (fin->fin_p)
	{
	case IPPROTO_ICMP :
		sum1 = LONG_SUM(ntohs(nat->nat_osport));
		sum2 = LONG_SUM(ntohs(nat->nat_nsport));
		CALC_SUMD(sum1, sum2, sumd);
		nat->nat_sumd[0] = (sumd & 0xffff) + (sumd >> 16);

		break;

	default :
		sum1 = LONG_SUM(ntohl(nat->nat_osrcaddr) + \
				ntohs(nat->nat_osport));
		sum2 = LONG_SUM(ntohl(nat->nat_nsrcaddr) + \
				ntohs(nat->nat_nsport));
		CALC_SUMD(sum1, sum2, sumd);
		nat->nat_sumd[0] = (sumd & 0xffff) + (sumd >> 16);

		sum1 = LONG_SUM(ntohl(nat->nat_odstaddr) + \
				ntohs(nat->nat_odport));
		sum2 = LONG_SUM(ntohl(nat->nat_ndstaddr) + \
				ntohs(nat->nat_ndport));
		CALC_SUMD(sum1, sum2, sumd);
		nat->nat_sumd[0] += (sumd & 0xffff) + (sumd >> 16);
		break;
	}

#if SOLARIS && defined(_KERNEL) && (SOLARIS2 >= 6) && defined(ICK_M_CTL_MAGIC)
	if ((flags & IPN_TCP) && dohwcksum &&
	    (((ill_t *)qpi->qpi_ill)->ill_ick.ick_magic == ICK_M_CTL_MAGIC)) {
		if (direction == NAT_OUTBOUND)
			ni.nai_sum1 = LONG_SUM(in.s_addr);
		else
			ni.nai_sum1 = LONG_SUM(ntohl(fin->fin_saddr));
		ni.nai_sum1 += LONG_SUM(ntohl(fin->fin_daddr));
		ni.nai_sum1 += 30;
		ni.nai_sum1 = (ni.nai_sum1 & 0xffff) + (ni.nai_sum1 >> 16);
		nat->nat_sumd[1] = NAT_HW_CKSUM|(ni.nai_sum1 & 0xffff);
	} else
#endif
		nat->nat_sumd[1] = nat->nat_sumd[0];

	sum1 = LONG_SUM(ntohl(nat->nat_osrcaddr));
	sum2 = LONG_SUM(ntohl(nat->nat_nsrcaddr));
	CALC_SUMD(sum1, sum2, sumd);
	nat->nat_ipsumd = (sumd & 0xffff) + (sumd >> 16);

	sum1 = LONG_SUM(ntohl(nat->nat_odstaddr));
	sum2 = LONG_SUM(ntohl(nat->nat_ndstaddr));
	CALC_SUMD(sum1, sum2, sumd);
	nat->nat_ipsumd += (sumd & 0xffff) + (sumd >> 16);

	if (np->in_ifps[0] != NULL) {
		COPYIFNAME(np->in_ifps[0], nat->nat_ifnames[0]);
	}
	if (np->in_ifps[1] != NULL) {
		COPYIFNAME(np->in_ifps[1], nat->nat_ifnames[1]);
	}
#ifdef	IPFILTER_SYNC
	if ((nat->nat_flags & SI_CLONE) == 0)
		nat->nat_sync = ipf_sync_new(SMC_NAT, fin, nat);
#endif

	nat->nat_me = natsave;
	nat->nat_ifps[0] = np->in_ifps[0];

	if ((nat->nat_ifps[0] != NULL) && (nat->nat_ifps[0] != (void *)-1)) {
		nat->nat_mtu[0] = GETIFMTU(nat->nat_ifps[0]);
	}

	nat->nat_ifps[1] = np->in_ifps[1];
	if ((nat->nat_ifps[1] != NULL) && (nat->nat_ifps[1] != (void *)-1)) {
		nat->nat_mtu[1] = GETIFMTU(nat->nat_ifps[1]);
	}

	nat->nat_ptr = np;
	nat->nat_mssclamp = np->in_mssclamp;
	nat->nat_v = fin->fin_v;

	if ((np->in_apr != NULL) && ((ni->nai_flags & NAT_SLAVE) == 0))
		if (appr_new(fin, nat) == -1)
			return -1;

	if (ipf_nat_insert(nat, fin->fin_rev) == 0) {
		if (ipf_nat_logging)
			ipf_nat_log(nat, NL_NEW);
		np->in_use++;
		fr = fin->fin_fr;
		nat->nat_fr = fr;
		if (fr != NULL) {
			MUTEX_ENTER(&fr->fr_lock);
			fr->fr_ref++;
			MUTEX_EXIT(&fr->fr_lock);
		}
		return 0;
	}

	ATOMIC_INCL(ipf_nat_stats.ns_side[fin->fin_out].ns_unfinalised);
	/*
	 * nat_insert failed, so cleanup time...
	 */
	return -1;
}


/* ------------------------------------------------------------------------ */
/* Function:   ipf_nat_insert                                               */
/* Returns:    int - 0 == sucess, -1 == failure                             */
/* Parameters: nat(I) - pointer to NAT structure                            */
/*             rev(I) - flag indicating forward/reverse direction of packet */
/* Write Lock: ipf_nat                                                      */
/*                                                                          */
/* Insert a NAT entry into the hash tables for searching and add it to the  */
/* list of active NAT entries.  Adjust global counters when complete.       */
/* ------------------------------------------------------------------------ */
int
ipf_nat_insert(nat, rev)
	nat_t *nat;
	int rev;
{
	u_int hv1, hv2;
	nat_t **natp;

	/*
	 * Try and return an error as early as possible, so calculate the hash
	 * entry numbers first and then proceed.
	 */
	if ((nat->nat_flags & (SI_W_SPORT|SI_W_DPORT)) == 0) {
		hv1 = NAT_HASH_FN(nat->nat_osrcaddr, nat->nat_osport,
				  0xffffffff);
		hv1 = NAT_HASH_FN(nat->nat_odstaddr, hv1 + nat->nat_odport,
				  ipf_nat_table_sz);

		/*
		 * TRACE nat_osrcaddr, nat_osport, nat_odstaddr,
		 * nat_odport, hv1
		 */

		hv2 = NAT_HASH_FN(nat->nat_nsrcaddr, nat->nat_nsport,
				  0xffffffff);
		hv2 = NAT_HASH_FN(nat->nat_ndstaddr, hv2 + nat->nat_ndport,
				  ipf_nat_table_sz);
		/*
		 * TRACE nat_nsrcaddr, nat_nsport, nat_ndstaddr,
		 * nat_ndport, hv1
		 */
	} else {
		hv1 = NAT_HASH_FN(nat->nat_osrcaddr, 0, 0xffffffff);
		hv1 = NAT_HASH_FN(nat->nat_odstaddr, hv1, ipf_nat_table_sz);
		/* TRACE nat_osrcaddr, nat_odstaddr, hv1 */

		hv2 = NAT_HASH_FN(nat->nat_nsrcaddr, 0, 0xffffffff);
		hv2 = NAT_HASH_FN(nat->nat_ndstaddr, hv2, ipf_nat_table_sz);
		/* TRACE nat_nsrcaddr, nat_ndstaddr, hv2 */
	}

	if (ipf_nat_stats.ns_side[0].ns_bucketlen[hv1] >= ipf_nat_maxbucket) {
		ATOMIC_INCL(ipf_nat_stats.ns_side[0].ns_bucket_max);
		return -1;
	}

	if (ipf_nat_stats.ns_side[1].ns_bucketlen[hv2] >= ipf_nat_maxbucket) {
		ATOMIC_INCL(ipf_nat_stats.ns_side[1].ns_bucket_max);
		return -1;
	}

	if (nat->nat_dir == NAT_INBOUND || nat->nat_dir == NAT_ENCAPIN ||
	    nat->nat_dir == NAT_DIVERTIN) {
		u_int swap;

		swap = hv2;
		hv2 = hv1;
		hv1 = swap;
	}
	nat->nat_hv[0] = hv1;
	nat->nat_hv[1] = hv2;

	MUTEX_INIT(&nat->nat_lock, "nat entry lock");

	nat->nat_rev = rev;
	nat->nat_ref = 1;
	nat->nat_bytes[0] = 0;
	nat->nat_pkts[0] = 0;
	nat->nat_bytes[1] = 0;
	nat->nat_pkts[1] = 0;

	nat->nat_ifnames[0][LIFNAMSIZ - 1] = '\0';
	nat->nat_ifps[0] = ipf_resolvenic(nat->nat_ifnames[0], nat->nat_v);

	if (nat->nat_ifnames[1][0] != '\0') {
		nat->nat_ifnames[1][LIFNAMSIZ - 1] = '\0';
		nat->nat_ifps[1] = ipf_resolvenic(nat->nat_ifnames[1],
						 nat->nat_v);
	} else {
		ipnat_t *in = nat->nat_ptr;

		if (in->in_ifnames[1][1] != '\0' &&
		    in->in_ifnames[1][0] != '-' &&
		    in->in_ifnames[1][0] != '*') {
			(void) strncpy(nat->nat_ifnames[1],
				       nat->nat_ifnames[0], LIFNAMSIZ);
			nat->nat_ifnames[1][LIFNAMSIZ - 1] = '\0';
			nat->nat_ifps[1] = nat->nat_ifps[0];
		}
	}
	if ((nat->nat_ifps[0] != NULL) && (nat->nat_ifps[0] != (void *)-1)) {
		nat->nat_mtu[0] = GETIFMTU(nat->nat_ifps[0]);
	}
	if ((nat->nat_ifps[1] != NULL) && (nat->nat_ifps[1] != (void *)-1)) {
		nat->nat_mtu[1] = GETIFMTU(nat->nat_ifps[1]);
	}

	nat->nat_next = ipf_nat_instances;
	nat->nat_pnext = &ipf_nat_instances;
	if (ipf_nat_instances)
		ipf_nat_instances->nat_pnext = &nat->nat_next;
	ipf_nat_instances = nat;

	natp = &ipf_nat_table[0][hv1];
	if (*natp)
		(*natp)->nat_phnext[0] = &nat->nat_hnext[0];
	else
		ipf_nat_stats.ns_side[0].ns_inuse++;
	nat->nat_phnext[0] = natp;
	nat->nat_hnext[0] = *natp;
	*natp = nat;
	ipf_nat_stats.ns_side[0].ns_bucketlen[hv1]++;

	natp = &ipf_nat_table[1][hv2];
	if (*natp)
		(*natp)->nat_phnext[1] = &nat->nat_hnext[1];
	else
		ipf_nat_stats.ns_side[1].ns_inuse++;
	nat->nat_phnext[1] = natp;
	nat->nat_hnext[1] = *natp;
	*natp = nat;
	ipf_nat_stats.ns_side[1].ns_bucketlen[hv2]++;

	ipf_nat_setqueue(nat, rev);

	ipf_nat_stats.ns_added++;
	ipf_nat_stats.ns_active++;
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_icmperrorlookup                                     */
/* Returns:     nat_t* - point to matching NAT structure                    */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              dir(I) - direction of packet (in/out)                       */
/*                                                                          */
/* Check if the ICMP error message is related to an existing TCP, UDP or    */
/* ICMP query nat entry.  It is assumed that the packet is already of the   */
/* the required length.                                                     */
/* ------------------------------------------------------------------------ */
nat_t *
ipf_nat_icmperrorlookup(fin, dir)
	fr_info_t *fin;
	int dir;
{
	int flags = 0, type, minlen;
	icmphdr_t *icmp, *orgicmp;
	nat_stat_side_t *nside;
	tcphdr_t *tcp = NULL;
	u_short data[2];
	nat_t *nat;
	ip_t *oip;
	u_int p;

	icmp = fin->fin_dp;
	type = icmp->icmp_type;
	nside = &ipf_nat_stats.ns_side[fin->fin_out];
	/*
	 * Does it at least have the return (basic) IP header ?
	 * Only a basic IP header (no options) should be with an ICMP error
	 * header.  Also, if it's not an error type, then return.
	 */
	if ((fin->fin_hlen != sizeof(ip_t)) || !(fin->fin_flx & FI_ICMPERR)) {
		ATOMIC_INCL(nside->ns_icmp_basic);
		return NULL;
	}

	/*
	 * Check packet size
	 */
	oip = (ip_t *)((char *)fin->fin_dp + 8);
	minlen = IP_HL(oip) << 2;
	if ((minlen < sizeof(ip_t)) ||
	    (fin->fin_plen < ICMPERR_IPICMPHLEN + minlen)) {
		ATOMIC_INCL(nside->ns_icmp_size);
		return NULL;
	}

	/*
	 * Is the buffer big enough for all of it ?  It's the size of the IP
	 * header claimed in the encapsulated part which is of concern.  It
	 * may be too big to be in this buffer but not so big that it's
	 * outside the ICMP packet, leading to TCP deref's causing problems.
	 * This is possible because we don't know how big oip_hl is when we
	 * do the pullup early in ipf_check() and thus can't gaurantee it is
	 * all here now.
	 */
#ifdef  ipf_nat_KERNEL
	{
	mb_t *m;

	m = fin->fin_m;
# if defined(MENTAT)
	if ((char *)oip + fin->fin_dlen - ICMPERR_ICMPHLEN >
	    (char *)m->b_wptr) {
		ATOMIC_INCL(nside->ns_icmp_mbuf);
		return NULL;
	}
# else
	if ((char *)oip + fin->fin_dlen - ICMPERR_ICMPHLEN >
	    (char *)fin->fin_ip + M_LEN(m)) {
		ATOMIC_INCL(nside->ns_icmp_mbuf);
		return NULL;
	}
# endif
	}
#endif

	if (fin->fin_daddr != oip->ip_src.s_addr) {
		ATOMIC_INCL(nside->ns_icmp_address);
		return NULL;
	}

	p = oip->ip_p;
	if (p == IPPROTO_TCP)
		flags = IPN_TCP;
	else if (p == IPPROTO_UDP)
		flags = IPN_UDP;
	else if (p == IPPROTO_ICMP) {
		orgicmp = (icmphdr_t *)((char *)oip + (IP_HL(oip) << 2));

		/* see if this is related to an ICMP query */
		if (ipf_nat_icmpquerytype4(orgicmp->icmp_type)) {
			data[0] = fin->fin_data[0];
			data[1] = fin->fin_data[1];
			fin->fin_data[0] = 0;
			fin->fin_data[1] = orgicmp->icmp_id;

			flags = IPN_ICMPERR|IPN_ICMPQUERY;
			/*
			 * NOTE : dir refers to the direction of the original
			 *        ip packet. By definition the icmp error
			 *        message flows in the opposite direction.
			 */
			if (dir == NAT_INBOUND)
				nat = ipf_nat_inlookup(fin, flags, p,
						       oip->ip_dst,
						       oip->ip_src);
			else
				nat = ipf_nat_outlookup(fin, flags, p,
							oip->ip_dst,
							oip->ip_src);
			fin->fin_data[0] = data[0];
			fin->fin_data[1] = data[1];
			return nat;
		}
	}

	if (flags & IPN_TCPUDP) {
		minlen += 8;		/* + 64bits of data to get ports */
		/* TRACE (fin,minlen) */
		if (fin->fin_plen < ICMPERR_IPICMPHLEN + minlen) {
			ATOMIC_INCL(nside->ns_icmp_short);
			return NULL;
		}

		data[0] = fin->fin_data[0];
		data[1] = fin->fin_data[1];
		tcp = (tcphdr_t *)((char *)oip + (IP_HL(oip) << 2));
		fin->fin_data[0] = ntohs(tcp->th_dport);
		fin->fin_data[1] = ntohs(tcp->th_sport);

		if (dir == NAT_INBOUND) {
			nat = ipf_nat_inlookup(fin, flags, p, oip->ip_dst,
					   oip->ip_src);
		} else {
			nat = ipf_nat_outlookup(fin, flags, p, oip->ip_dst,
					    oip->ip_src);
		}
		fin->fin_data[0] = data[0];
		fin->fin_data[1] = data[1];
		return nat;
	}
	if (dir == NAT_INBOUND)
		nat = ipf_nat_inlookup(fin, 0, p, oip->ip_dst, oip->ip_src);
	else
		nat = ipf_nat_outlookup(fin, 0, p, oip->ip_dst, oip->ip_src);

	return nat;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_icmperror                                           */
/* Returns:     nat_t* - point to matching NAT structure                    */
/* Parameters:  fin(I)    - pointer to packet information                   */
/*              nflags(I) - NAT flags for this packet                       */
/*              dir(I)    - direction of packet (in/out)                    */
/*                                                                          */
/* Fix up an ICMP packet which is an error message for an existing NAT      */
/* session.  This will correct both packet header data and checksums.       */
/*                                                                          */
/* This should *ONLY* be used for incoming ICMP error packets to make sure  */
/* a NAT'd ICMP packet gets correctly recognised.                           */
/* ------------------------------------------------------------------------ */
nat_t *
ipf_nat_icmperror(fin, nflags, dir)
	fr_info_t *fin;
	u_int *nflags;
	int dir;
{
	u_32_t sum1, sum2, sumd, sumd2;
	struct in_addr a1, a2, a3, a4;
	int flags, dlen, odst;
	icmphdr_t *icmp;
	u_short *csump;
	tcphdr_t *tcp;
	nat_t *nat;
	ip_t *oip;
	void *dp;

	if ((fin->fin_flx & (FI_SHORT|FI_FRAGBODY))) {
		ATOMIC_INCL(ipf_nat_stats.ns_side[fin->fin_out].ns_icmp_short);
		return NULL;
	}

	/*
	 * ipf_nat_icmperrorlookup() will return NULL for `defective' packets.
	 */
	if ((fin->fin_v != 4) || !(nat = ipf_nat_icmperrorlookup(fin, dir))) {
		ATOMIC_INCL(ipf_nat_stats.ns_side[fin->fin_out].
			    ns_icmp_notfound);
		return NULL;
	}

	if (nat->nat_dir == NAT_ENCAPIN || nat->nat_dir == NAT_ENCAPOUT) {
		/*
		 * For ICMP replies to encapsulated packets, we need to
		 * rebuild the ICMP reply completely to match the original
		 * packet...
		 */
		if (ipf_nat_rebuildencapicmp(fin, nat) == 0)
			return nat;
		ATOMIC_INCL(ipf_nat_stats.ns_side[fin->fin_out].
			    ns_icmp_rebuild);
		return NULL;
	}

	tcp = NULL;
	csump = NULL;
	flags = 0;
	sumd2 = 0;
	*nflags = IPN_ICMPERR;
	icmp = fin->fin_dp;
	oip = (ip_t *)&icmp->icmp_ip;
	dp = (((char *)oip) + (IP_HL(oip) << 2));
	if (oip->ip_p == IPPROTO_TCP) {
		tcp = (tcphdr_t *)dp;
		csump = (u_short *)&tcp->th_sum;
		flags = IPN_TCP;
	} else if (oip->ip_p == IPPROTO_UDP) {
		udphdr_t *udp;

		udp = (udphdr_t *)dp;
		tcp = (tcphdr_t *)dp;
		csump = (u_short *)&udp->uh_sum;
		flags = IPN_UDP;
	} else if (oip->ip_p == IPPROTO_ICMP)
		flags = IPN_ICMPQUERY;
	dlen = fin->fin_plen - ((char *)dp - (char *)fin->fin_ip);

	/*
	 * Need to adjust ICMP header to include the real IP#'s and
	 * port #'s.  Only apply a checksum change relative to the
	 * IP address change as it will be modified again in ipf_nat_checkout
	 * for both address and port.  Two checksum changes are
	 * necessary for the two header address changes.  Be careful
	 * to only modify the checksum once for the port # and twice
	 * for the IP#.
	 */

	/*
	 * Step 1
	 * Fix the IP addresses in the offending IP packet. You also need
	 * to adjust the IP header checksum of that offending IP packet.
	 *
	 * Normally, you would expect that the ICMP checksum of the
	 * ICMP error message needs to be adjusted as well for the
	 * IP address change in oip.
	 * However, this is a NOP, because the ICMP checksum is
	 * calculated over the complete ICMP packet, which includes the
	 * changed oip IP addresses and oip->ip_sum. However, these
	 * two changes cancel each other out (if the delta for
	 * the IP address is x, then the delta for ip_sum is minus x),
	 * so no change in the icmp_cksum is necessary.
	 *
	 * Inbound ICMP
	 * ------------
	 * MAP rule, SRC=a,DST=b -> SRC=c,DST=b
	 * - response to outgoing packet (a,b)=>(c,b) (OIP_SRC=c,OIP_DST=b)
	 * - OIP_SRC(c)=nat_newsrcip,          OIP_DST(b)=nat_newdstip
	 *=> OIP_SRC(c)=nat_oldsrcip,          OIP_DST(b)=nat_olddstip
	 *
	 * RDR rule, SRC=a,DST=b -> SRC=a,DST=c
	 * - response to outgoing packet (c,a)=>(b,a) (OIP_SRC=b,OIP_DST=a)
	 * - OIP_SRC(b)=nat_olddstip,          OIP_DST(a)=nat_oldsrcip
	 *=> OIP_SRC(b)=nat_newdstip,          OIP_DST(a)=nat_newsrcip
	 *
	 * REWRITE out rule, SRC=a,DST=b -> SRC=c,DST=d
	 * - response to outgoing packet (a,b)=>(c,d) (OIP_SRC=c,OIP_DST=d)
	 * - OIP_SRC(c)=nat_newsrcip,          OIP_DST(d)=nat_newdstip
	 *=> OIP_SRC(c)=nat_oldsrcip,          OIP_DST(d)=nat_olddstip
	 *
	 * REWRITE in rule, SRC=a,DST=b -> SRC=c,DST=d
	 * - response to outgoing packet (d,c)=>(b,a) (OIP_SRC=b,OIP_DST=a)
	 * - OIP_SRC(b)=nat_olddstip,          OIP_DST(a)=nat_oldsrcip
	 *=> OIP_SRC(b)=nat_newdstip,          OIP_DST(a)=nat_newsrcip
	 *
	 * Outbound ICMP
	 * -------------
	 * MAP rule, SRC=a,DST=b -> SRC=c,DST=b
	 * - response to incoming packet (b,c)=>(b,a) (OIP_SRC=b,OIP_DST=a)
	 * - OIP_SRC(b)=nat_olddstip,          OIP_DST(a)=nat_oldsrcip
	 *=> OIP_SRC(b)=nat_newdstip,          OIP_DST(a)=nat_newsrcip
	 *
	 * RDR rule, SRC=a,DST=b -> SRC=a,DST=c
	 * - response to incoming packet (a,b)=>(a,c) (OIP_SRC=a,OIP_DST=c)
	 * - OIP_SRC(a)=nat_newsrcip,          OIP_DST(c)=nat_newdstip
	 *=> OIP_SRC(a)=nat_oldsrcip,          OIP_DST(c)=nat_olddstip
	 *
	 * REWRITE out rule, SRC=a,DST=b -> SRC=c,DST=d
	 * - response to incoming packet (d,c)=>(b,a) (OIP_SRC=c,OIP_DST=d)
	 * - OIP_SRC(c)=nat_olddstip,          OIP_DST(d)=nat_oldsrcip
	 *=> OIP_SRC(b)=nat_newdstip,          OIP_DST(a)=nat_newsrcip
	 *
	 * REWRITE in rule, SRC=a,DST=b -> SRC=c,DST=d
	 * - response to incoming packet (a,b)=>(c,d) (OIP_SRC=b,OIP_DST=a)
	 * - OIP_SRC(b)=nat_newsrcip,          OIP_DST(a)=nat_newdstip
	 *=> OIP_SRC(a)=nat_oldsrcip,          OIP_DST(c)=nat_olddstip
	 */

	if (((fin->fin_out == 0) && ((nat->nat_redir & NAT_MAP) != 0)) ||
	    ((fin->fin_out == 1) && ((nat->nat_redir & NAT_REDIRECT) != 0))) {
		a1.s_addr = ntohl(nat->nat_osrcaddr);
		a4.s_addr = ntohl(oip->ip_src.s_addr);
		a3.s_addr = ntohl(nat->nat_odstaddr);
		a2.s_addr = ntohl(oip->ip_dst.s_addr);
		oip->ip_src.s_addr = htonl(a1.s_addr);
		oip->ip_dst.s_addr = htonl(a3.s_addr);
		odst = 1;
	} else {
		a1.s_addr = ntohl(nat->nat_ndstaddr);
		a2.s_addr = ntohl(oip->ip_dst.s_addr);
		a3.s_addr = ntohl(nat->nat_nsrcaddr);
		a4.s_addr = ntohl(oip->ip_src.s_addr);
		oip->ip_dst.s_addr = htonl(a3.s_addr);
		oip->ip_src.s_addr = htonl(a1.s_addr);
		odst = 0;
	}
	sumd = 0;
	if ((a3.s_addr != a2.s_addr) || (a1.s_addr != a4.s_addr)) {
		if (a3.s_addr > a2.s_addr)
			sumd = a2.s_addr - a3.s_addr - 1;
		else
			sumd = a2.s_addr - a3.s_addr;
		if (a1.s_addr > a4.s_addr)
			sumd += a4.s_addr - a1.s_addr - 1;
		else
			sumd += a4.s_addr - a1.s_addr;
		sumd = ~sumd;

		ipf_fix_datacksum(&oip->ip_sum, sumd);
	}

	sumd2 = sumd;
	sum1 = 0;
	sum2 = 0;

	/*
	 * Fix UDP pseudo header checksum to compensate for the
	 * IP address change.
	 */
	if (((flags & IPN_TCPUDP) != 0) && (dlen >= 4)) {
		u_32_t sum3, sum4;
		/*
		 * Step 2 :
		 * For offending TCP/UDP IP packets, translate the ports as
		 * well, based on the NAT specification. Of course such
		 * a change may be reflected in the ICMP checksum as well.
		 *
		 * Since the port fields are part of the TCP/UDP checksum
		 * of the offending IP packet, you need to adjust that checksum
		 * as well... except that the change in the port numbers should
		 * be offset by the checksum change.  However, the TCP/UDP
		 * checksum will also need to change if there has been an
		 * IP address change.
		 */
		if (odst == 1) {
			sum1 = ntohs(nat->nat_osport);
			sum4 = ntohs(tcp->th_sport);
			sum3 = ntohs(nat->nat_odport);
			sum2 = ntohs(tcp->th_dport);

			tcp->th_sport = htons(sum1);
			tcp->th_dport = htons(sum3);
		} else {
			sum1 = ntohs(nat->nat_ndport);
			sum2 = ntohs(tcp->th_dport);
			sum3 = ntohs(nat->nat_nsport);
			sum4 = ntohs(tcp->th_sport);

			tcp->th_dport = htons(sum3);
			tcp->th_sport = htons(sum1);
		}
		sumd += sum1 - sum4;
		sumd += sum3 - sum2;

		if (sumd != 0 || sumd2 != 0) {
			/*
			 * At this point, sumd is the delta to apply to the
			 * TCP/UDP header, given the changes in both the IP
			 * address and the ports and sumd2 is the delta to
			 * apply to the ICMP header, given the IP address
			 * change delta that may need to be applied to the
			 * TCP/UDP checksum instead.
			 *
			 * If we will both the IP and TCP/UDP checksums
			 * then the ICMP checksum changes by the address
			 * delta applied to the TCP/UDP checksum.  If we
			 * do not change the TCP/UDP checksum them we
			 * apply the delta in ports to the ICMP checksum.
			 */
			if (oip->ip_p == IPPROTO_UDP) {
				if ((dlen >= 8) && (*csump != 0)) {
					ipf_fix_datacksum(csump, sumd);
				} else {
					sumd2 = sum4 - sum1;
					if (sum1 > sum4)
						sumd2--;
					sumd2 += sum2 - sum3;
					if (sum3 > sum2)
						sumd2--;
				}
			} else if (oip->ip_p == IPPROTO_TCP) {
				if (dlen >= 18) {
					ipf_fix_datacksum(csump, sumd);
				} else {
					sumd2 = sum4 - sum1;
					if (sum1 > sum4)
						sumd2--;
					sumd2 += sum2 - sum3;
					if (sum3 > sum2)
						sumd2--;
				}
			}
			if (sumd2 != 0) {
				sumd2 = (sumd2 & 0xffff) + (sumd2 >> 16);
				sumd2 = (sumd2 & 0xffff) + (sumd2 >> 16);
				sumd2 = (sumd2 & 0xffff) + (sumd2 >> 16);
				ipf_fix_incksum(fin, &icmp->icmp_cksum, sumd2);
			}
		}
	} else if (((flags & IPN_ICMPQUERY) != 0) && (dlen >= 8)) {
		icmphdr_t *orgicmp;

		/*
		 * XXX - what if this is bogus hl and we go off the end ?
		 * In this case, ipf_nat_icmperrorlookup() will have
		 * returned NULL.
		 */
		orgicmp = (icmphdr_t *)dp;

		if (odst == 1) {
			if (orgicmp->icmp_id != nat->nat_osport) {

				/*
				 * Fix ICMP checksum (of the offening ICMP
				 * query packet) to compensate the change
				 * in the ICMP id of the offending ICMP
				 * packet.
				 *
				 * Since you modify orgicmp->icmp_id with
				 * a delta (say x) and you compensate that
				 * in origicmp->icmp_cksum with a delta
				 * minus x, you don't have to adjust the
				 * overall icmp->icmp_cksum
				 */
				sum1 = ntohs(orgicmp->icmp_id);
				sum2 = ntohs(nat->nat_osport);
				CALC_SUMD(sum1, sum2, sumd);
				orgicmp->icmp_id = nat->nat_oicmpid;
				ipf_fix_datacksum(&orgicmp->icmp_cksum, sumd);
			}
		} /* nat_dir == NAT_INBOUND is impossible for icmp queries */
	}
	return nat;
}


/*
 *       MAP-IN    MAP-OUT   RDR-IN   RDR-OUT
 * osrc    X       == src    == src      X
 * odst    X       == dst    == dst      X
 * nsrc  == dst      X         X      == dst
 * ndst  == src      X         X      == src
 * MAP = NAT_OUTBOUND, RDR = NAT_INBOUND
 */
/*
 * NB: these lookups don't lock access to the list, it assumed that it has
 * already been done!
 */
/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_inlookup                                            */
/* Returns:     nat_t* - NULL == no match,                                  */
/*                       else pointer to matching NAT entry                 */
/* Parameters:  fin(I)    - pointer to packet information                   */
/*              flags(I)  - NAT flags for this packet                       */
/*              p(I)      - protocol for this packet                        */
/*              src(I)    - source IP address                               */
/*              mapdst(I) - destination IP address                          */
/*                                                                          */
/* Lookup a nat entry based on the mapped destination ip address/port and   */
/* real source address/port.  We use this lookup when receiving a packet,   */
/* we're looking for a table entry, based on the destination address.       */
/*                                                                          */
/* NOTE: THE PACKET BEING CHECKED (IF FOUND) HAS A MAPPING ALREADY.         */
/*                                                                          */
/* NOTE: IT IS ASSUMED THAT  IS ONLY HELD WITH A READ LOCK WHEN             */
/*       THIS FUNCTION IS CALLED WITH NAT_SEARCH SET IN nflags.             */
/*                                                                          */
/* flags   -> relevant are IPN_UDP/IPN_TCP/IPN_ICMPQUERY that indicate if   */
/*            the packet is of said protocol                                */
/* ------------------------------------------------------------------------ */
nat_t *
ipf_nat_inlookup(fin, flags, p, src, mapdst)
	fr_info_t *fin;
	u_int flags, p;
	struct in_addr src , mapdst;
{
	u_short sport, dport;
	grehdr_t *gre;
	ipnat_t *ipn;
	u_int sflags;
	nat_t *nat;
	int nflags;
	u_32_t dst;
	void *ifp;
	u_int hv;

	ifp = fin->fin_ifp;
	sport = 0;
	dport = 0;
	gre = NULL;
	dst = mapdst.s_addr;
	sflags = flags & NAT_TCPUDPICMP;

	switch (p)
	{
	case IPPROTO_TCP :
	case IPPROTO_UDP :
		sport = htons(fin->fin_data[0]);
		dport = htons(fin->fin_data[1]);
		break;
	case IPPROTO_ICMP :
		if (flags & IPN_ICMPERR)
			sport = fin->fin_data[1];
		else
			dport = fin->fin_data[1];
		break;
	default :
		break;
	}


	if ((flags & SI_WILDP) != 0)
		goto find_in_wild_ports;

	hv = NAT_HASH_FN(dst, dport, 0xffffffff);
	hv = NAT_HASH_FN(src.s_addr, hv + sport, ipf_nat_table_sz);
	nat = ipf_nat_table[1][hv];
	/* TRACE dst, dport, src, sport, hv, nat */

	for (; nat; nat = nat->nat_hnext[1]) {
		if (nat->nat_ifps[0] != NULL) {
			if ((ifp != NULL) && (ifp != nat->nat_ifps[0]))
				continue;
		}

		if ((p != 0) && (nat->nat_pr[0] != p))
			continue;

		switch (nat->nat_dir)
		{
		case NAT_INBOUND :
			if (nat->nat_osrcaddr != src.s_addr ||
			    nat->nat_odstaddr != dst)
				continue;
			if ((nat->nat_flags & IPN_TCPUDP) != 0) {
				if (nat->nat_osport != sport)
					continue;
				if (nat->nat_odport != dport)
					continue;

			} else if (p == IPPROTO_ICMP) {
				if (nat->nat_osport != dport) {
					continue;
				}
			}
			break;
		case NAT_OUTBOUND :
			if (nat->nat_ndstaddr != src.s_addr ||
			    nat->nat_nsrcaddr != dst)
				continue;
			if ((nat->nat_flags & IPN_TCPUDP) != 0) {
				if (nat->nat_ndport != sport)
					continue;
				if (nat->nat_nsport != dport)
					continue;

			} else if (p == IPPROTO_ICMP) {
				if (nat->nat_osport != dport) {
					continue;
				}
			}
			break;
		}


		if ((nat->nat_flags & IPN_TCPUDP) != 0) {
			ipn = nat->nat_ptr;
			if ((ipn != NULL) && (nat->nat_aps != NULL))
				if (appr_match(fin, nat) != 0)
					continue;
		}
		if (ifp != NULL) {
			nat->nat_ifps[0] = ifp;
			nat->nat_mtu[0] = GETIFMTU(ifp);
		}
		return nat;
	}

	/*
	 * So if we didn't find it but there are wildcard members in the hash
	 * table, go back and look for them.  We do this search and update here
	 * because it is modifying the NAT table and we want to do this only
	 * for the first packet that matches.  The exception, of course, is
	 * for "dummy" (FI_IGNORE) lookups.
	 */
find_in_wild_ports:
	if (!(flags & NAT_TCPUDP) || !(flags & NAT_SEARCH)) {
		ATOMIC_INCL(ipf_nat_stats.ns_side[0].ns_lookup_miss);
		return NULL;
	}
	if (ipf_nat_stats.ns_wilds == 0) {
		ATOMIC_INCL(ipf_nat_stats.ns_side[0].ns_lookup_nowild);
		return NULL;
	}

	RWLOCK_EXIT(&ipf_nat);

	hv = NAT_HASH_FN(dst, 0, 0xffffffff);
	hv = NAT_HASH_FN(src.s_addr, hv, ipf_nat_table_sz);
	WRITE_ENTER(&ipf_nat);

	nat = ipf_nat_table[1][hv];
	/* TRACE dst, src, hv, nat */
	for (; nat; nat = nat->nat_hnext[1]) {
		if (nat->nat_ifps[0] != NULL) {
			if ((ifp != NULL) && (ifp != nat->nat_ifps[0]))
				continue;
		}

		if (nat->nat_pr[0] != fin->fin_p)
			continue;

		switch (nat->nat_dir)
		{
		case NAT_INBOUND :
			if (nat->nat_osrcaddr != src.s_addr ||
			    nat->nat_odstaddr != dst)
				continue;
			break;
		case NAT_OUTBOUND :
			if (nat->nat_ndstaddr != src.s_addr ||
			    nat->nat_nsrcaddr != dst)
				continue;
			break;
		}

		nflags = nat->nat_flags;
		if (!(nflags & (NAT_TCPUDP|SI_WILDP)))
			continue;

		if (ipf_nat_wildok(nat, (int)sport, (int)dport, nflags,
			       NAT_INBOUND) == 1) {
			if ((fin->fin_flx & FI_IGNORE) != 0)
				break;
			if ((nflags & SI_CLONE) != 0) {
				nat = ipf_nat_clone(fin, nat);
				if (nat == NULL)
					break;
			} else {
				MUTEX_ENTER(&ipf_nat_new);
				ipf_nat_stats.ns_wilds--;
				MUTEX_EXIT(&ipf_nat_new);
			}

			if (nat->nat_dir == NAT_INBOUND) {
				if (nat->nat_osport == 0) {
					nat->nat_osport = sport;
					nat->nat_nsport = sport;
				}
				if (nat->nat_odport == 0) {
					nat->nat_odport = dport;
					nat->nat_ndport = dport;
				}
			} else {
				if (nat->nat_osport == 0) {
					nat->nat_osport = dport;
					nat->nat_nsport = dport;
				}
				if (nat->nat_odport == 0) {
					nat->nat_odport = sport;
					nat->nat_ndport = sport;
				}
			}
			if (ifp != NULL) {
				nat->nat_ifps[0] = ifp;
				nat->nat_mtu[0] = GETIFMTU(ifp);
			}
			nat->nat_flags &= ~(SI_W_DPORT|SI_W_SPORT);
			ipf_nat_tabmove(nat);
			break;
		}
	}

	MUTEX_DOWNGRADE(&ipf_nat);

	if (nat == NULL) {
		ATOMIC_INCL(ipf_nat_stats.ns_side[0].ns_lookup_miss);
	}
	return nat;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_tabmove                                             */
/* Returns:     Nil                                                         */
/* Parameters:  nat(I) - pointer to NAT structure                           */
/* Write Lock:                                                       */
/*                                                                          */
/* This function is only called for TCP/UDP NAT table entries where the     */
/* original was placed in the table without hashing on the ports and we now */
/* want to include hashing on port numbers.                                 */
/* ------------------------------------------------------------------------ */
static void
ipf_nat_tabmove(nat)
	nat_t *nat;
{
	nat_t **natp;
	u_int hv0, hv1;

	if (nat->nat_flags & SI_CLONE)
		return;

	/*
	 * Remove the NAT entry from the old location
	 */
	if (nat->nat_hnext[0])
		nat->nat_hnext[0]->nat_phnext[0] = nat->nat_phnext[0];
	*nat->nat_phnext[0] = nat->nat_hnext[0];
	ipf_nat_stats.ns_side[0].ns_bucketlen[nat->nat_hv[0]]--;

	if (nat->nat_hnext[1])
		nat->nat_hnext[1]->nat_phnext[1] = nat->nat_phnext[1];
	*nat->nat_phnext[1] = nat->nat_hnext[1];
	ipf_nat_stats.ns_side[1].ns_bucketlen[nat->nat_hv[1]]--;

	/*
	 * Add into the NAT table in the new position
	 */
	hv0 = NAT_HASH_FN(nat->nat_osrcaddr, nat->nat_osport, 0xffffffff);
	hv0 = NAT_HASH_FN(nat->nat_odstaddr, hv0 + nat->nat_odport,
			  ipf_nat_table_sz);
	hv1 = NAT_HASH_FN(nat->nat_nsrcaddr, nat->nat_nsport, 0xffffffff);
	hv1 = NAT_HASH_FN(nat->nat_ndstaddr, hv1 + nat->nat_ndport,
			  ipf_nat_table_sz);

	if (nat->nat_dir == NAT_INBOUND || nat->nat_dir == NAT_ENCAPIN ||
	    nat->nat_dir == NAT_DIVERTIN) {
		u_int swap;

		swap = hv0;
		hv0 = hv1;
		hv1 = swap;
	}

	/* TRACE nat_osrcaddr, nat_osport, nat_odstaddr, nat_odport, hv0 */
	/* TRACE nat_nsrcaddr, nat_nsport, nat_ndstaddr, nat_ndport, hv1 */

	nat->nat_hv[0] = hv0;
	natp = &ipf_nat_table[0][hv0];
	if (*natp)
		(*natp)->nat_phnext[0] = &nat->nat_hnext[0];
	nat->nat_phnext[0] = natp;
	nat->nat_hnext[0] = *natp;
	*natp = nat;
	ipf_nat_stats.ns_side[0].ns_bucketlen[hv0]++;

	nat->nat_hv[1] = hv1;
	natp = &ipf_nat_table[1][hv1];
	if (*natp)
		(*natp)->nat_phnext[1] = &nat->nat_hnext[1];
	nat->nat_phnext[1] = natp;
	nat->nat_hnext[1] = *natp;
	*natp = nat;
	ipf_nat_stats.ns_side[1].ns_bucketlen[hv1]++;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_outlookup                                           */
/* Returns:     nat_t* - NULL == no match,                                  */
/*                       else pointer to matching NAT entry                 */
/* Parameters:  fin(I)   - pointer to packet information                    */
/*              flags(I) - NAT flags for this packet                        */
/*              p(I)     - protocol for this packet                         */
/*              src(I)   - source IP address                                */
/*              dst(I)   - destination IP address                           */
/*              rw(I)    - 1 == write lock on  held, 0 == read lock.        */
/*                                                                          */
/* Lookup a nat entry based on the source 'real' ip address/port and        */
/* destination address/port.  We use this lookup when sending a packet out, */
/* we're looking for a table entry, based on the source address.            */
/*                                                                          */
/* NOTE: THE PACKET BEING CHECKED (IF FOUND) HAS A MAPPING ALREADY.         */
/*                                                                          */
/* NOTE: IT IS ASSUMED THAT  IS ONLY HELD WITH A READ LOCK WHEN             */
/*       THIS FUNCTION IS CALLED WITH NAT_SEARCH SET IN nflags.             */
/*                                                                          */
/* flags   -> relevant are IPN_UDP/IPN_TCP/IPN_ICMPQUERY that indicate if   */
/*            the packet is of said protocol                                */
/* ------------------------------------------------------------------------ */
nat_t *
ipf_nat_outlookup(fin, flags, p, src, dst)
	fr_info_t *fin;
	u_int flags, p;
	struct in_addr src , dst;
{
	u_short sport, dport;
	u_int sflags;
	ipnat_t *ipn;
	nat_t *nat;
	void *ifp;
	u_int hv;

	ifp = fin->fin_ifp;
	sflags = flags & IPN_TCPUDPICMP;
	sport = 0;
	dport = 0;

	switch (p)
	{
	case IPPROTO_TCP :
	case IPPROTO_UDP :
		sport = htons(fin->fin_data[0]);
		dport = htons(fin->fin_data[1]);
		break;
	case IPPROTO_ICMP :
		if (flags & IPN_ICMPERR)
			sport = fin->fin_data[1];
		else
			dport = fin->fin_data[1];
		break;
	default :
		break;
	}

	if ((flags & SI_WILDP) != 0)
		goto find_out_wild_ports;

	hv = NAT_HASH_FN(src.s_addr, sport, 0xffffffff);
	hv = NAT_HASH_FN(dst.s_addr, hv + dport, ipf_nat_table_sz);
	nat = ipf_nat_table[0][hv];

	/* TRACE src, sport, dst, dport, hv, nat */

	for (; nat; nat = nat->nat_hnext[0]) {
		if (nat->nat_ifps[1] != NULL) {
			if ((ifp != NULL) && (ifp != nat->nat_ifps[1]))
				continue;
		}

		if ((p != 0) && (nat->nat_pr[1] != p))
			continue;

		switch (nat->nat_dir)
		{
		case NAT_INBOUND :
			if (nat->nat_ndstaddr != src.s_addr ||
			    nat->nat_nsrcaddr != dst.s_addr)
				continue;

			if ((nat->nat_flags & IPN_TCPUDP) != 0) {
				if (nat->nat_ndport != sport)
					continue;
				if (nat->nat_nsport != dport)
					continue;

			} else if (p == IPPROTO_ICMP) {
				if (nat->nat_osport != dport) {
					continue;
				}
			}
			break;
		case NAT_OUTBOUND :
			if (nat->nat_osrcaddr != src.s_addr ||
			    nat->nat_odstaddr != dst.s_addr)
				continue;

			if ((nat->nat_flags & IPN_TCPUDP) != 0) {
				if (nat->nat_odport != dport)
					continue;
				if (nat->nat_osport != sport)
					continue;

			} else if (p == IPPROTO_ICMP) {
				if (nat->nat_osport != dport) {
					continue;
				}
			}
			break;
		}

		ipn = nat->nat_ptr;
		if ((ipn != NULL) && (nat->nat_aps != NULL))
			if (appr_match(fin, nat) != 0)
				continue;

		if (ifp != NULL) {
			nat->nat_ifps[1] = ifp;
			nat->nat_mtu[1] = GETIFMTU(ifp);
		}
		return nat;
	}

	/*
	 * So if we didn't find it but there are wildcard members in the hash
	 * table, go back and look for them.  We do this search and update here
	 * because it is modifying the NAT table and we want to do this only
	 * for the first packet that matches.  The exception, of course, is
	 * for "dummy" (FI_IGNORE) lookups.
	 */
find_out_wild_ports:
	if (!(flags & NAT_TCPUDP) || !(flags & NAT_SEARCH)) {
		ATOMIC_INCL(ipf_nat_stats.ns_side[1].ns_lookup_miss);
		return NULL;
	}
	if (ipf_nat_stats.ns_wilds == 0) {
		ATOMIC_INCL(ipf_nat_stats.ns_side[1].ns_lookup_nowild);
		return NULL;
	}

	RWLOCK_EXIT(&ipf_nat);

	hv = NAT_HASH_FN(src.s_addr, 0, 0xffffffff);
	hv = NAT_HASH_FN(dst.s_addr, hv, ipf_nat_table_sz);

	WRITE_ENTER(&ipf_nat);

	nat = ipf_nat_table[0][hv];
	for (; nat; nat = nat->nat_hnext[0]) {
		if (nat->nat_ifps[1] != NULL) {
			if ((ifp != NULL) && (ifp != nat->nat_ifps[1]))
				continue;
		}

		if (nat->nat_pr[1] != fin->fin_p)
			continue;

		switch (nat->nat_dir)
		{
		case NAT_INBOUND :
			if (nat->nat_ndstaddr != src.s_addr ||
			    nat->nat_nsrcaddr != dst.s_addr)
				continue;
			break;
		case NAT_OUTBOUND :
			if (nat->nat_osrcaddr != src.s_addr ||
			    nat->nat_odstaddr != dst.s_addr)
				continue;
			break;
		}

		if (!(nat->nat_flags & (NAT_TCPUDP|SI_WILDP)))
			continue;

		if (ipf_nat_wildok(nat, (int)sport, (int)dport, nat->nat_flags,
			       NAT_OUTBOUND) == 1) {
			if ((fin->fin_flx & FI_IGNORE) != 0)
				break;
			if ((nat->nat_flags & SI_CLONE) != 0) {
				nat = ipf_nat_clone(fin, nat);
				if (nat == NULL)
					break;
			} else {
				MUTEX_ENTER(&ipf_nat_new);
				ipf_nat_stats.ns_wilds--;
				MUTEX_EXIT(&ipf_nat_new);
			}

			if (nat->nat_dir == NAT_OUTBOUND) {
				if (nat->nat_osport == 0) {
					nat->nat_osport = sport;
					nat->nat_nsport = sport;
				}
				if (nat->nat_odport == 0) {
					nat->nat_odport = dport;
					nat->nat_ndport = dport;
				}
			} else {
				if (nat->nat_osport == 0) {
					nat->nat_osport = dport;
					nat->nat_nsport = dport;
				}
				if (nat->nat_odport == 0) {
					nat->nat_odport = sport;
					nat->nat_ndport = sport;
				}
			}
			if (ifp != NULL) {
				nat->nat_ifps[1] = ifp;
				nat->nat_mtu[1] = GETIFMTU(ifp);
			}
			nat->nat_flags &= ~(SI_W_DPORT|SI_W_SPORT);
			ipf_nat_tabmove(nat);
			break;
		}
	}

	MUTEX_DOWNGRADE(&ipf_nat);

	if (nat == NULL) {
		ATOMIC_INCL(ipf_nat_stats.ns_side[1].ns_lookup_miss);
	}
	return nat;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_lookupredir                                         */
/* Returns:     nat_t* - NULL == no match,                                  */
/*                       else pointer to matching NAT entry                 */
/* Parameters:  np(I) - pointer to description of packet to find NAT table  */
/*                      entry for.                                          */
/*                                                                          */
/* Lookup the NAT tables to search for a matching redirect                  */
/* The contents of natlookup_t should imitate those found in a packet that  */
/* would be translated - ie a packet coming in for RDR or going out for MAP.*/
/* We can do the lookup in one of two ways, imitating an inbound or         */
/* outbound  packet.  By default we assume outbound, unless IPN_IN is set.  */
/* For IN, the fields are set as follows:                                   */
/*     nl_real* = source information                                        */
/*     nl_out* = destination information (translated)                       */
/* For an out packet, the fields are set like this:                         */
/*     nl_in* = source information (untranslated)                           */
/*     nl_out* = destination information (translated)                       */
/* ------------------------------------------------------------------------ */
nat_t *
ipf_nat_lookupredir(np)
	natlookup_t *np;
{
	fr_info_t fi;
	nat_t *nat;

	bzero((char *)&fi, sizeof(fi));
	if (np->nl_flags & IPN_IN) {
		fi.fin_data[0] = ntohs(np->nl_realport);
		fi.fin_data[1] = ntohs(np->nl_outport);
	} else {
		fi.fin_data[0] = ntohs(np->nl_inport);
		fi.fin_data[1] = ntohs(np->nl_outport);
	}
	if (np->nl_flags & IPN_TCP)
		fi.fin_p = IPPROTO_TCP;
	else if (np->nl_flags & IPN_UDP)
		fi.fin_p = IPPROTO_UDP;
	else if (np->nl_flags & (IPN_ICMPERR|IPN_ICMPQUERY))
		fi.fin_p = IPPROTO_ICMP;

	/*
	 * We can do two sorts of lookups:
	 * - IPN_IN: we have the `real' and `out' address, look for `in'.
	 * - default: we have the `in' and `out' address, look for `real'.
	 */
	if (np->nl_flags & IPN_IN) {
		if ((nat = ipf_nat_inlookup(&fi, np->nl_flags, fi.fin_p,
					np->nl_realip, np->nl_outip))) {
			np->nl_inip = nat->nat_odstip;
			np->nl_inport = nat->nat_odport;
		}
	} else {
		/*
		 * If nl_inip is non null, this is a lookup based on the real
		 * ip address. Else, we use the fake.
		 */
		if ((nat = ipf_nat_outlookup(&fi, np->nl_flags, fi.fin_p,
					 np->nl_inip, np->nl_outip))) {

			if ((np->nl_flags & IPN_FINDFORWARD) != 0) {
				fr_info_t fin;
				bzero((char *)&fin, sizeof(fin));
				fin.fin_p = nat->nat_pr[0];
				fin.fin_data[0] = ntohs(nat->nat_ndport);
				fin.fin_data[1] = ntohs(nat->nat_nsport);
				if (ipf_nat_inlookup(&fin, np->nl_flags,
						     fin.fin_p, nat->nat_ndstip,
						     nat->nat_nsrcip) != NULL) {
					np->nl_flags &= ~IPN_FINDFORWARD;
				}
			}

			np->nl_realip = nat->nat_ndstip;
			np->nl_realport = nat->nat_ndport;
		}
 	}

	return nat;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_match_v4                                            */
/* Returns:     int - 0 == no match, 1 == match                             */
/* Parameters:  fin(I)   - pointer to packet information                    */
/*              np(I)    - pointer to NAT rule                              */
/*                                                                          */
/* Pull the matching of a packet against a NAT rule out of that complex     */
/* loop inside ipf_nat_checkin() and lay it out properly in its own function. */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_match_v4(fin, np)
	fr_info_t *fin;
	ipnat_t *np;
{
	frtuc_t *ft;
	int match;

	if ((fin->fin_p == IPPROTO_ENCAP) && (np->in_redir & NAT_ENCAP))
		return ipf_nat_matchencap(fin, np);

	match = 0;
	switch (np->in_osrcatype)
	{
	case FRI_NORMAL :
		match = ((fin->fin_saddr & np->in_osrcmsk) != np->in_osrcaddr);
		break;
#ifdef IPFILTER_LOOKUP
	case FRI_LOOKUP :
		match = (*np->in_osrcfunc)(np->in_osrcptr, np->in_v,
					   &fin->fin_saddr);
		break;
#endif
	}
	match ^= ((np->in_flags & IPN_NOTSRC) != 0);
	if (match)
		return 0;

	match = 0;
	switch (np->in_odstatype)
	{
	case FRI_NORMAL :
		match = ((fin->fin_daddr & np->in_odstmsk) != np->in_odstaddr);
		break;
#ifdef IPFILTER_LOOKUP
	case FRI_LOOKUP :
		match = (*np->in_odstfunc)(np->in_odstptr, fin->fin_v,
					   &fin->fin_daddr);
		break;
#endif
	}

	match ^= ((np->in_flags & IPN_NOTDST) != 0);
	if (match)
		return 0;

	ft = &np->in_tuc;
	if (!(fin->fin_flx & FI_TCPUDP) ||
	    (fin->fin_flx & (FI_SHORT|FI_FRAGBODY))) {
		if (ft->ftu_scmp || ft->ftu_dcmp)
			return 0;
		return 1;
	}

	return ipf_tcpudpchk(&fin->fin_fi, ft);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_update                                              */
/* Returns:     Nil                                                         */
/* Parameters:  nat(I)    - pointer to NAT structure                        */
/*              np(I)     - pointer to NAT rule                             */
/*                                                                          */
/* Updates the lifetime of a NAT table entry for non-TCP packets.  Must be  */
/* called with fin_rev updated - i.e. after calling ipf_nat_proto().        */
/* ------------------------------------------------------------------------ */
void
ipf_nat_update(fin, nat, np)
	fr_info_t *fin;
	nat_t *nat;
	ipnat_t *np;
{
	ipftq_t *ifq, *ifq2;
	ipftqent_t *tqe;

	MUTEX_ENTER(&nat->nat_lock);
	tqe = &nat->nat_tqe;
	ifq = tqe->tqe_ifq;

	/*
	 * We allow over-riding of NAT timeouts from NAT rules, even for
	 * TCP, however, if it is TCP and there is no rule timeout set,
	 * then do not update the timeout here.
	 */
	if (np != NULL)
		ifq2 = np->in_tqehead[fin->fin_rev];
	else
		ifq2 = NULL;

	if (nat->nat_pr[0] == IPPROTO_TCP && ifq2 == NULL) {
		(void) ipf_tcp_age(&nat->nat_tqe, fin, ipf_nat_tqb, 0, 2);
	} else {
		if (ifq2 == NULL) {
			if (nat->nat_pr[0] == IPPROTO_UDP)
				ifq2 = &ipf_nat_udptq;
			else if (nat->nat_pr[0] == IPPROTO_ICMP)
				ifq2 = &ipf_nat_icmptq;
			else
				ifq2 = &ipf_nat_iptq;
		}

		ipf_movequeue(tqe, ifq, ifq2);
	}
	MUTEX_EXIT(&nat->nat_lock);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_ipfout                                              */
/* Returns:     frentry_t* - NULL (packet may have been translated, let it  */
/*                           pass), &ipfnatblock - block/drop the packet.   */
/* Parameters:  fin(I)   - pointer to packet information                    */
/*              passp(I) - point to filtering result flags                  */
/*                                                                          */
/* This is purely and simply a wrapper around ipf_nat_checkout for the sole */
/* reason of being able to activate NAT from an ipf rule using "call-now".  */
/* ------------------------------------------------------------------------ */
frentry_t *
ipf_nat_ipfout(fin, passp)
	fr_info_t *fin;
	u_32_t *passp;
{
	frentry_t *fr = fin->fin_fr;

	switch (ipf_nat_checkout(fin, passp))
	{
	case -1 :
		fin->fin_reason = 13;
		fr = &ipfnatblock;
		MUTEX_ENTER(&fr->fr_lock);
		fr->fr_ref++;
		MUTEX_EXIT(&fr->fr_lock);
		return fr;

	case 0 :
		break;

	case 1 :
		/*
		 * Returing NULL causes this rule to be "ignored" but
		 * it has actually had an influence on the packet so we
		 * increment counters for it.
		 */
		MUTEX_ENTER(&fr->fr_lock);
		fr->fr_bytes += (U_QUAD_T)fin->fin_plen;
		fr->fr_hits++;
		MUTEX_EXIT(&fr->fr_lock);
		break;
	}

	return NULL;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_checkout                                            */
/* Returns:     int - -1 == packet failed NAT checks so block it,           */
/*                     0 == no packet translation occurred,                 */
/*                     1 == packet was successfully translated.             */
/* Parameters:  fin(I)   - pointer to packet information                    */
/*              passp(I) - pointer to filtering result flags                */
/*                                                                          */
/* Check to see if an outcoming packet should be changed.  ICMP packets are */
/* first checked to see if they match an existing entry (if an error),      */
/* otherwise a search of the current NAT table is made.  If neither results */
/* in a match then a search for a matching NAT rule is made.  Create a new  */
/* NAT entry if a we matched a NAT rule.  Lastly, actually change the       */
/* packet header(s) as required.                                            */
/* ------------------------------------------------------------------------ */
int
ipf_nat_checkout(fin, passp)
	fr_info_t *fin;
	u_32_t *passp;
{
	struct ifnet *ifp, *sifp;
	icmphdr_t *icmp = NULL;
	tcphdr_t *tcp = NULL;
	int rval, natfailed;
	ipnat_t *np = NULL;
	u_int nflags = 0;
	u_32_t ipa, iph;
	int natadd = 1;
	frentry_t *fr;
	nat_t *nat;

	if (ipf_nat_stats.ns_rules == 0 || ipf_nat_lock != 0)
		return 0;

	natfailed = 0;
	fr = fin->fin_fr;
	sifp = fin->fin_ifp;
	if (fr != NULL) {
		ifp = fr->fr_tifs[fin->fin_rev].fd_ifp;
		if ((ifp != NULL) && (ifp != (void *)-1))
			fin->fin_ifp = ifp;
	}
	ifp = fin->fin_ifp;

	if (!(fin->fin_flx & FI_SHORT) && (fin->fin_off == 0)) {
		switch (fin->fin_p)
		{
		case IPPROTO_TCP :
			nflags = IPN_TCP;
			break;
		case IPPROTO_UDP :
			nflags = IPN_UDP;
			break;
		case IPPROTO_ICMP :
			icmp = fin->fin_dp;

			/*
			 * This is an incoming packet, so the destination is
			 * the icmp_id and the source port equals 0
			 */
			if ((fin->fin_flx & FI_ICMPQUERY) != 0)
				nflags = IPN_ICMPQUERY;
			break;
		default :
			break;
		}

		if ((nflags & IPN_TCPUDP))
			tcp = fin->fin_dp;
	}

	ipa = fin->fin_saddr;

	READ_ENTER(&ipf_nat);

	if ((fin->fin_p == IPPROTO_ICMP) && !(nflags & IPN_ICMPQUERY) &&
	    (nat = ipf_nat_icmperror(fin, &nflags, NAT_OUTBOUND)))
		/*EMPTY*/;
	else if ((fin->fin_flx & FI_FRAG) && (nat = ipf_frag_natknown(fin)))
		natadd = 0;
	else if ((nat = ipf_nat_outlookup(fin, nflags|NAT_SEARCH,
				      (u_int)fin->fin_p, fin->fin_src,
				      fin->fin_dst))) {
		nflags = nat->nat_flags;
	} else {
		u_32_t hv, msk, nmsk;

		/*
		 * If there is no current entry in the nat table for this IP#,
		 * create one for it (if there is a matching rule).
		 */
		RWLOCK_EXIT(&ipf_nat);
		msk = 0xffffffff;
		nmsk = ipf_nat_map_masks;
		WRITE_ENTER(&ipf_nat);
maskloop:
		iph = ipa & htonl(msk);
		hv = NAT_HASH_FN(iph, 0, ipf_nat_maprules_sz);
		for (np = ipf_nat_map_rules[hv]; np; np = np->in_mnext)
		{
			if ((np->in_ifps[1] && (np->in_ifps[1] != ifp)))
				continue;
			if (np->in_v != fin->fin_v)
				continue;
			if (np->in_pr[1] && (np->in_pr[1] != fin->fin_p))
				continue;
			if ((np->in_flags & IPN_RF) &&
			    !(np->in_flags & nflags))
				continue;
			if (np->in_flags & IPN_FILTER) {
				switch (ipf_nat_match_v4(fin, np))
				{
				case 0 :
					continue;
				case -1 :
					rval = -1;
					goto outmatchfail;
				case 1 :
				default :
					break;
				}
			} else if ((ipa & np->in_osrcaddr) != np->in_osrcaddr)
				continue;

			if ((fr != NULL) &&
			    !ipf_matchtag(&np->in_tag, &fr->fr_nattag))
				continue;

			if (*np->in_plabel != '\0') {
				if (((np->in_flags & IPN_FILTER) == 0) &&
				    (np->in_odport != fin->fin_data[1]))
					continue;
				if (appr_ok(fin, tcp, np) == 0)
					continue;
			}

			if (np->in_flags & IPN_NO) {
				np->in_hits++;
				break;
			}

			if ((nat = ipf_nat_add(fin, np, NULL, nflags,
					   NAT_OUTBOUND))) {
				np->in_hits++;
				break;
			} else
				natfailed = -1;
		}
		if ((np == NULL) && (nmsk != 0)) {
			while (nmsk) {
				msk <<= 1;
				if (nmsk & 0x80000000)
					break;
				nmsk <<= 1;
			}
			if (nmsk != 0) {
				nmsk <<= 1;
				goto maskloop;
			}
		}
		MUTEX_DOWNGRADE(&ipf_nat);
	}

	if (nat != NULL) {
		rval = ipf_nat_out(fin, nat, natadd, nflags);
		if (rval == 1) {
			MUTEX_ENTER(&nat->nat_lock);
			nat->nat_ref++;
			MUTEX_EXIT(&nat->nat_lock);
			nat->nat_touched = ipf_ticks;
			fin->fin_nat = nat;
		}
	} else
		rval = natfailed;
outmatchfail:
	RWLOCK_EXIT(&ipf_nat);

	switch (rval)
	{
	case -1 :
		if (passp != NULL) {
			ATOMIC_INCL(ipf_nat_stats.ns_side[1].ns_drop);
			*passp = FR_BLOCK;
			fin->fin_reason = 11;
		}
		fin->fin_flx |= FI_BADNAT;
		ATOMIC_INCL(ipf_nat_stats.ns_side[1].ns_badnat);
		break;
	case 0 :
		ATOMIC_INCL(ipf_nat_stats.ns_side[1].ns_ignored);
		break;
	case 1 :
		ATOMIC_INCL(ipf_nat_stats.ns_side[1].ns_translated);
		break;
	}
	fin->fin_ifp = sifp;
	return rval;
}

/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_out                                                 */
/* Returns:     int - -1 == packet failed NAT checks so block it,           */
/*                     1 == packet was successfully translated.             */
/* Parameters:  fin(I)    - pointer to packet information                   */
/*              nat(I)    - pointer to NAT structure                        */
/*              natadd(I) - flag indicating if it is safe to add frag cache */
/*              nflags(I) - NAT flags set for this packet                   */
/*                                                                          */
/* Translate a packet coming "out" on an interface.                         */
/* ------------------------------------------------------------------------ */
int
ipf_nat_out(fin, nat, natadd, nflags)
	fr_info_t *fin;
	nat_t *nat;
	int natadd;
	u_32_t nflags;
{
	icmphdr_t *icmp;
	u_short *csump;
	tcphdr_t *tcp;
	ipnat_t *np;
	int skip;
	int i;

	tcp = NULL;
	icmp = NULL;
	csump = NULL;
	np = nat->nat_ptr;

	if ((natadd != 0) && (fin->fin_flx & FI_FRAG) && (np != NULL))
		(void) ipf_frag_natnew(fin, 0, nat);

	MUTEX_ENTER(&nat->nat_lock);
	nat->nat_bytes[1] += fin->fin_plen;
	nat->nat_pkts[1]++;
	MUTEX_EXIT(&nat->nat_lock);

	/*
	 * Fix up checksums, not by recalculating them, but
	 * simply computing adjustments.
	 * This is only done for STREAMS based IP implementations where the
	 * checksum has already been calculated by IP.  In all other cases,
	 * IPFilter is called before the checksum needs calculating so there
	 * is no call to modify whatever is in the header now.
	 */
	if (fin->fin_v == 4) {
		if (nflags == IPN_ICMPERR) {
			u_32_t s1, s2, sumd, msumd;

			s1 = LONG_SUM(ntohl(fin->fin_saddr));
			if (nat->nat_dir == NAT_OUTBOUND) {
				s2 = LONG_SUM(ntohl(nat->nat_nsrcaddr));
			} else {
				s2 = LONG_SUM(ntohl(nat->nat_odstaddr));
			}
			CALC_SUMD(s1, s2, sumd);
			msumd = sumd;

			s1 = LONG_SUM(ntohl(fin->fin_daddr));
			if (nat->nat_dir == NAT_OUTBOUND) {
				s2 = LONG_SUM(ntohl(nat->nat_ndstaddr));
			} else {
				s2 = LONG_SUM(ntohl(nat->nat_osrcaddr));
			}
			CALC_SUMD(s1, s2, sumd);
			msumd += sumd;

			ipf_fix_outcksum(fin, &fin->fin_ip->ip_sum, msumd);
		}
#if !defined(_KERNEL) || defined(MENTAT) || defined(__sgi) || \
    defined(linux) || defined(BRIDGE_IPF)
		else {
			/*
			 * Strictly speaking, this isn't necessary on BSD
			 * kernels because they do checksum calculation after
			 * this code has run BUT if ipfilter is being used
			 * to do NAT as a bridge, that code doesn't exist.
			 */
			switch (nat->nat_dir)
			{
			case NAT_OUTBOUND :
				ipf_fix_outcksum(fin, &fin->fin_ip->ip_sum,
					     nat->nat_ipsumd);
				break;

			case NAT_INBOUND :
				ipf_fix_incksum(fin, &fin->fin_ip->ip_sum,
					    nat->nat_ipsumd);
				break;

			default :
				break;
			}
		}
#endif
	}

	/*
	 * Address assignment is after the checksum modification because
	 * we are using the address in the packet for determining the
	 * correct checksum offset (the ICMP error could be coming from
	 * anyone...)
	 */
	switch (nat->nat_dir)
	{
	case NAT_OUTBOUND :
		fin->fin_ip->ip_src = nat->nat_nsrcip;
		fin->fin_saddr = nat->nat_nsrcaddr;
		fin->fin_ip->ip_dst = nat->nat_ndstip;
		fin->fin_daddr = nat->nat_ndstaddr;
		break;

	case NAT_INBOUND :
		fin->fin_ip->ip_src = nat->nat_odstip;
		fin->fin_saddr = nat->nat_ndstaddr;
		fin->fin_ip->ip_dst = nat->nat_osrcip;
		fin->fin_daddr = nat->nat_nsrcaddr;
		break;

	case NAT_ENCAPIN :
		fin->fin_flx |= FI_ENCAP;
	case NAT_DIVERTIN :
	    {
		mb_t *m;

		skip = ipf_nat_decap(fin, nat);
		if (skip <= 0) {
			ATOMIC_INCL(ipf_nat_stats.ns_side[1].ns_decap_fail);
			return -1;
		}

		m = fin->fin_m;

#if defined(MENTAT) && defined(_KERNEL)
		m->b_rptr += skip;
#else
		m->m_data += skip;
		m->m_len -= skip;

# ifdef M_PKTHDR
		if (m->m_flags & M_PKTHDR)
			m->m_pkthdr.len -= skip;
# endif
#endif

		ipf_nat_update(fin, nat, np);
		nflags &= ~IPN_TCPUDPICMP;
		fin->fin_flx |= FI_NATED;
		if (np != NULL && np->in_tag.ipt_num[0] != 0)
			fin->fin_nattag = &np->in_tag;
		return 1;
		/* NOTREACHED */
	    }

	case NAT_ENCAPOUT :
	    {
		u_32_t s1, s2, sumd;
		ip_t *ip;
		mb_t *m;

		if (ipf_nat_encapok(fin, nat) == -1)
			return -1;

		m = M_DUPLICATE(np->in_divmp);
		if (m == NULL) {
			ATOMIC_INCL(ipf_nat_stats.ns_side[1].ns_encap_dup);
			return -1;
		}

		ip = MTOD(m, ip_t *);
		/* TRACE (fin,ip) */
		ip->ip_off = (fin->fin_ip->ip_off & htons(IP_DF));
		ip->ip_id = htons(ipf_nextipid(fin));
		ip->ip_len = htons(fin->fin_plen + 20);
		s1 = 0;
		/*
		 * We subtract 20 here because ip_len has already been set
		 * to this value when the template checksum is created.
		 */
		s2 = ntohs(ip->ip_id) + ntohs(ip->ip_len) - 20;
		s2 += ntohs(ip->ip_off) & IP_DF;
		/* TRACE (s1,s2,ip) */
		CALC_SUMD(s1, s2, sumd);
		/* TRACE (sumd) */

#if !defined(_KERNEL) || defined(MENTAT) || defined(__sgi) || \
    defined(linux) || defined(BRIDGE_IPF)
		ipf_fix_outcksum(fin, &ip->ip_sum, sumd);
#endif
		/* TRACE (ip) */

		PREP_MB_T(fin, m);

		fin->fin_ip = ip;
		fin->fin_plen += 20;	/* UDP + new IPv4 hdr */
		fin->fin_dlen += 20;	/* UDP + old IPv4 hdr */
		fin->fin_flx |= FI_ENCAP;

		nflags &= ~IPN_TCPUDPICMP;

		break;
	    }
	case NAT_DIVERTOUT :
	    {
		u_32_t s1, s2, sumd;
		udphdr_t *uh;
		ip_t *ip;
		mb_t *m;

		m = M_DUPLICATE(np->in_divmp);
		if (m == NULL) {
			ATOMIC_INCL(ipf_nat_stats.ns_side[1].ns_divert_dup);
			return -1;
		}

		ip = MTOD(m, ip_t *);
		ip->ip_id = htons(ipf_nextipid(fin));

		s1 = ip->ip_len;
		ip->ip_len = ntohs(ip->ip_len);
		ip->ip_len += fin->fin_plen;
		ip->ip_len = htons(ip->ip_len);

		uh = (udphdr_t *)(ip + 1);
		uh->uh_ulen += fin->fin_plen;
		uh->uh_ulen = htons(uh->uh_ulen);

		s2 = ntohs(ip->ip_id) + ntohs(ip->ip_len);
		CALC_SUMD(s1, s2, sumd);

#if !defined(_KERNEL) || defined(MENTAT) || defined(__sgi) || \
    defined(linux) || defined(BRIDGE_IPF)
		ipf_fix_incksum(fin, &ip->ip_sum, sumd);
#endif

		PREP_MB_T(fin, m);

		fin->fin_ip = ip;
		fin->fin_plen += 28;	/* UDP + new IPv4 hdr */
		fin->fin_dlen += 28;	/* UDP + old IPv4 hdr */

		nflags &= ~IPN_TCPUDPICMP;

		break;
	    }

	default :
		break;
	}

	if (!(fin->fin_flx & FI_SHORT) && (fin->fin_off == 0)) {
		if ((nat->nat_nsport != 0) && (nflags & IPN_TCPUDP)) {
			tcp = fin->fin_dp;

			switch (nat->nat_dir)
			{
			case NAT_OUTBOUND :
				tcp->th_sport = nat->nat_nsport;
				fin->fin_data[0] = ntohs(nat->nat_nsport);
				tcp->th_dport = nat->nat_ndport;
				fin->fin_data[0] = ntohs(nat->nat_ndport);
				break;

			case NAT_INBOUND :
				tcp->th_sport = nat->nat_odport;
				fin->fin_data[0] = ntohs(nat->nat_odport);
				tcp->th_dport = nat->nat_osport;
				fin->fin_data[0] = ntohs(nat->nat_osport);
				break;
			}
		}

		if ((nat->nat_nsport != 0) && (nflags & IPN_ICMPQUERY)) {
			icmp = fin->fin_dp;
			icmp->icmp_id = nat->nat_nicmpid;
		}

		csump = ipf_nat_proto(fin, nat, nflags);
	}

	ipf_nat_update(fin, nat, np);

	/*
	 * The above comments do not hold for layer 4 (or higher) checksums...
	 */
	if (csump != NULL) {
		if (nat->nat_dir == NAT_OUTBOUND)
			ipf_fix_outcksum(fin, csump, nat->nat_sumd[1]);
		else
			ipf_fix_incksum(fin, csump, nat->nat_sumd[1]);
	}
#ifdef	IPFILTER_SYNC
	ipf_sync_update(SMC_NAT, fin, nat->nat_sync);
#endif
	/* ------------------------------------------------------------- */
	/* A few quick notes:						 */
	/*	Following are test conditions prior to calling the 	 */
	/*	appr_check routine.					 */
	/*								 */
	/* 	A NULL tcp indicates a non TCP/UDP packet.  When dealing */
	/*	with a redirect rule, we attempt to match the packet's	 */
	/*	source port against in_dport, otherwise	we'd compare the */
	/*	packet's destination.			 		 */
	/* ------------------------------------------------------------- */
	if ((np != NULL) && (np->in_apr != NULL)) {
		i = appr_check(fin, nat);
		if (i == 0)
			i = 1;
		else if (i == -1) {
			ATOMIC_INCL(ipf_nat_stats.ns_side[1].ns_appr_fail);
		}
	} else {
		i = 1;
	}
	fin->fin_flx |= FI_NATED;
	return i;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_ipfin                                               */
/* Returns:     frentry_t* - NULL (packet may have been translated, let it  */
/*                           pass), &ipfnatblock - block/drop the packet.   */
/* Parameters:  fin(I)   - pointer to packet information                    */
/*              passp(I) - point to filtering result flags                  */
/*                                                                          */
/* This is purely and simply a wrapper around ipf_nat_checkin for the sole  */
/* reason of being able to activate NAT from an ipf rule using "call-now".  */
/* ------------------------------------------------------------------------ */
frentry_t *
ipf_nat_ipfin(fin, passp)
	fr_info_t *fin;
	u_32_t *passp;
{
	frentry_t *fr = fin->fin_fr;

	switch (ipf_nat_checkin(fin, passp))
	{
	case -1 :
		fin->fin_reason = 13;
		fr = &ipfnatblock;
		MUTEX_ENTER(&fr->fr_lock);
		fr->fr_ref++;
		MUTEX_EXIT(&fr->fr_lock);
		return fr;

	case 0 :
		return NULL;

	case 1 :
		/*
		 * Returing NULL causes this rule to be "ignored" but
		 * it has actually had an influence on the packet so we
		 * increment counters for it.
		 */
		MUTEX_ENTER(&fr->fr_lock);
		fr->fr_bytes += (U_QUAD_T)fin->fin_plen;
		fr->fr_hits++;
		MUTEX_EXIT(&fr->fr_lock);
		return NULL;
	}

	return NULL;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_checkin                                             */
/* Returns:     int - -1 == packet failed NAT checks so block it,           */
/*                     0 == no packet translation occurred,                 */
/*                     1 == packet was successfully translated.             */
/* Parameters:  fin(I)   - pointer to packet information                    */
/*              passp(I) - pointer to filtering result flags                */
/*                                                                          */
/* Check to see if an incoming packet should be changed.  ICMP packets are  */
/* first checked to see if they match an existing entry (if an error),      */
/* otherwise a search of the current NAT table is made.  If neither results */
/* in a match then a search for a matching NAT rule is made.  Create a new  */
/* NAT entry if a we matched a NAT rule.  Lastly, actually change the       */
/* packet header(s) as required.                                            */
/* ------------------------------------------------------------------------ */
int
ipf_nat_checkin(fin, passp)
	fr_info_t *fin;
	u_32_t *passp;
{
	u_int nflags, natadd;
	int rval, natfailed;
	struct ifnet *ifp;
	struct in_addr in;
	icmphdr_t *icmp;
	tcphdr_t *tcp;
	u_short dport;
	ipnat_t *np;
	nat_t *nat;
	u_32_t iph;

	if (ipf_nat_stats.ns_rules == 0 || ipf_nat_lock != 0)
		return 0;

	tcp = NULL;
	icmp = NULL;
	dport = 0;
	natadd = 1;
	nflags = 0;
	natfailed = 0;
	ifp = fin->fin_ifp;

	if (!(fin->fin_flx & FI_SHORT) && (fin->fin_off == 0)) {
		switch (fin->fin_p)
		{
		case IPPROTO_TCP :
			nflags = IPN_TCP;
			break;
		case IPPROTO_UDP :
			nflags = IPN_UDP;
			break;
		case IPPROTO_ICMP :
			icmp = fin->fin_dp;

			/*
			 * This is an incoming packet, so the destination is
			 * the icmp_id and the source port equals 0
			 */
			if ((fin->fin_flx & FI_ICMPQUERY) != 0) {
				nflags = IPN_ICMPQUERY;
				dport = icmp->icmp_id;
			} break;
		default :
			break;
		}

		if ((nflags & IPN_TCPUDP)) {
			tcp = fin->fin_dp;
			dport = fin->fin_data[1];
		}
	}

	in = fin->fin_dst;

	READ_ENTER(&ipf_nat);

	if ((fin->fin_p == IPPROTO_ICMP) && !(nflags & IPN_ICMPQUERY) &&
	    (nat = ipf_nat_icmperror(fin, &nflags, NAT_INBOUND)))
		/*EMPTY*/;
	else if ((fin->fin_flx & FI_FRAG) && (nat = ipf_frag_natknown(fin)))
		natadd = 0;
	else if ((nat = ipf_nat_inlookup(fin, nflags|NAT_SEARCH,
					 (u_int)fin->fin_p,
					 fin->fin_src, in))) {
		nflags = nat->nat_flags;
	} else {
		u_32_t hv, msk, rmsk;

		RWLOCK_EXIT(&ipf_nat);
		rmsk = ipf_nat_rdr_masks;
		msk = 0xffffffff;
		WRITE_ENTER(&ipf_nat);
		/*
		 * If there is no current entry in the nat table for this IP#,
		 * create one for it (if there is a matching rule).
		 */
maskloop:
		iph = in.s_addr & htonl(msk);
		hv = NAT_HASH_FN(iph, 0, ipf_nat_rdrrules_sz);
		/* TRACE (iph,msk,rmsk,hv,ipf_nat_rdrrules_sz) */
		for (np = ipf_nat_rdr_rules[hv]; np; np = np->in_rnext) {
			if (np->in_ifps[0] && (np->in_ifps[0] != ifp))
				continue;
			if (np->in_v != fin->fin_v)
				continue;
			if (np->in_pr[0] && (np->in_pr[0] != fin->fin_p))
				continue;
			if ((np->in_flags & IPN_RF) && !(np->in_flags & nflags))
				continue;
			if (np->in_flags & IPN_FILTER) {
				switch (ipf_nat_match_v4(fin, np))
				{
				case 0 :
					continue;
				case -1 :
					rval = -1;
					goto inmatchfail;
				case 1 :
				default :
					break;
				}
			} else {
				if ((in.s_addr & np->in_odstmsk) !=
				    np->in_odstaddr)
					continue;
				if (np->in_odport &&
				    ((np->in_dtop < dport) ||
				     (dport < np->in_odport)))
					continue;
			}

			if (*np->in_plabel != '\0') {
				if (!appr_ok(fin, tcp, np)) {
					continue;
				}
			}

			if (np->in_flags & IPN_NO) {
				np->in_hits++;
				break;
			}

			nat = ipf_nat_add(fin, np, NULL, nflags, NAT_INBOUND);
			if (nat != NULL) {
				np->in_hits++;
				break;
			} else
				natfailed = -1;
		}

		if ((np == NULL) && (rmsk != 0)) {
			while (rmsk) {
				msk <<= 1;
				if (rmsk & 0x80000000)
					break;
				rmsk <<= 1;
			}
			if (rmsk != 0) {
				rmsk <<= 1;
				goto maskloop;
			}
		}
		MUTEX_DOWNGRADE(&ipf_nat);
	}
	if (nat != NULL) {
		rval = ipf_nat_in(fin, nat, natadd, nflags);
		if (rval == 1) {
			MUTEX_ENTER(&nat->nat_lock);
			nat->nat_ref++;
			MUTEX_EXIT(&nat->nat_lock);
			nat->nat_touched = ipf_ticks;
			fin->fin_nat = nat;
		}
	} else
		rval = natfailed;
inmatchfail:
	RWLOCK_EXIT(&ipf_nat);

	switch (rval)
	{
	case -1 :
		if (passp != NULL) {
			ATOMIC_INCL(ipf_nat_stats.ns_side[0].ns_drop);
			*passp = FR_BLOCK;
			fin->fin_reason = 12;
		}
		fin->fin_flx |= FI_BADNAT;
		ATOMIC_INCL(ipf_nat_stats.ns_side[0].ns_badnat);
		break;
	case 0 :
		ATOMIC_INCL(ipf_nat_stats.ns_side[0].ns_ignored);
		break;
	case 1 :
		ATOMIC_INCL(ipf_nat_stats.ns_side[0].ns_translated);
		break;
	}
	return rval;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_in                                                  */
/* Returns:     int - -1 == packet failed NAT checks so block it,           */
/*                     1 == packet was successfully translated.             */
/* Parameters:  fin(I)    - pointer to packet information                   */
/*              nat(I)    - pointer to NAT structure                        */
/*              natadd(I) - flag indicating if it is safe to add frag cache */
/*              nflags(I) - NAT flags set for this packet                   */
/* Locks Held:   (READ)                                              */
/*                                                                          */
/* Translate a packet coming "in" on an interface.                          */
/* ------------------------------------------------------------------------ */
int
ipf_nat_in(fin, nat, natadd, nflags)
	fr_info_t *fin;
	nat_t *nat;
	int natadd;
	u_32_t nflags;
{
	u_32_t sumd, ipsumd, sum1, sum2;
	icmphdr_t *icmp;
	u_short *csump;
	tcphdr_t *tcp;
	ipnat_t *np;
	int skip;
	int i;

	tcp = NULL;
	csump = NULL;
	np = nat->nat_ptr;
	fin->fin_fr = nat->nat_fr;

	if (np != NULL) {
		if ((natadd != 0) && (fin->fin_flx & FI_FRAG))
			(void) ipf_frag_natnew(fin, 0, nat);

	/* ------------------------------------------------------------- */
	/* A few quick notes:						 */
	/*	Following are test conditions prior to calling the 	 */
	/*	appr_check routine.					 */
	/*								 */
	/* 	A NULL tcp indicates a non TCP/UDP packet.  When dealing */
	/*	with a map rule, we attempt to match the packet's	 */
	/*	source port against in_dport, otherwise	we'd compare the */
	/*	packet's destination.			 		 */
	/* ------------------------------------------------------------- */
		if (np->in_apr != NULL) {
			i = appr_check(fin, nat);
			if (i == -1) {
				ATOMIC_INCL(ipf_nat_stats.ns_side[0].
					     ns_appr_fail);
				return -1;
			}
		}
	}

#ifdef	IPFILTER_SYNC
	ipf_sync_update(SMC_NAT, fin, nat->nat_sync);
#endif

	MUTEX_ENTER(&nat->nat_lock);
	nat->nat_bytes[0] += fin->fin_plen;
	nat->nat_pkts[0]++;
	MUTEX_EXIT(&nat->nat_lock);

	ipsumd = nat->nat_ipsumd;
	/*
	 * Fix up checksums, not by recalculating them, but
	 * simply computing adjustments.
	 * Why only do this for some platforms on inbound packets ?
	 * Because for those that it is done, IP processing is yet to happen
	 * and so the IPv4 header checksum has not yet been evaluated.
	 * Perhaps it should always be done for the benefit of things like
	 * fast forwarding (so that it doesn't need to be recomputed) but with
	 * header checksum offloading, perhaps it is a moot point.
	 */

	switch (nat->nat_dir)
	{
	case NAT_INBOUND :
		if ((fin->fin_flx & FI_ICMPERR) == 0) {
			fin->fin_ip->ip_src = nat->nat_nsrcip;
			fin->fin_saddr = nat->nat_nsrcaddr;
		} else {
			sum1 = nat->nat_osrcaddr;
			sum2 = nat->nat_nsrcaddr;
			CALC_SUMD(sum1, sum2, sumd);
			ipsumd -= sumd;
		}
		fin->fin_ip->ip_dst = nat->nat_ndstip;
		fin->fin_daddr = nat->nat_ndstaddr;
#if !defined(_KERNEL) || defined(MENTAT) || defined(__sgi) || \
     defined(__osf__) || defined(linux)
		ipf_fix_outcksum(fin, &fin->fin_ip->ip_sum, ipsumd);
#endif
		break;

	case NAT_OUTBOUND :
		if ((fin->fin_flx & FI_ICMPERR) == 0) {
			fin->fin_ip->ip_src = nat->nat_odstip;
			fin->fin_saddr = nat->nat_odstaddr;
		} else {
			sum1 = nat->nat_odstaddr;
			sum2 = nat->nat_ndstaddr;
			CALC_SUMD(sum1, sum2, sumd);
			ipsumd -= sumd;
		}
		fin->fin_ip->ip_dst = nat->nat_osrcip;
		fin->fin_daddr = nat->nat_osrcaddr;
#if !defined(_KERNEL) || defined(MENTAT) || defined(__sgi) || \
     defined(__osf__) || defined(linux)
		ipf_fix_incksum(fin, &fin->fin_ip->ip_sum, ipsumd);
#endif
		break;

	case NAT_ENCAPIN :
	    {
		ip_t *ip;
		mb_t *m;

		/*
		 * XXX
		 * This is not necessarily true.  What we need to know here
		 * is the MTU of the interface out which the packets will go
		 * and this won't be nat_ifps[1] because that is where we
		 * send packets after stripping off stuff - what's needed
		 * here is the MTU of the interface for the route to the
		 * destination of the outer header.
		 */
		if (ipf_nat_encapok(fin, nat) == -1)
			return -1;

		m = M_DUPLICATE(np->in_divmp);
		if (m == NULL) {
			ATOMIC_INCL(ipf_nat_stats.ns_side[0].ns_encap_dup);
			return -1;
		}

		ip = MTOD(m, ip_t *);
		ip->ip_id = htons(ipf_nextipid(fin));
		sum1 = ntohs(ip->ip_len);
		ip->ip_len = htons(fin->fin_plen + 20);
		sum2 = ntohs(ip->ip_id) + ntohs(ip->ip_len);
		CALC_SUMD(sum1, sum2, sumd);

#if !defined(_KERNEL) || defined(MENTAT) || defined(__sgi) || \
     defined(__osf__) || defined(linux)
		ipf_fix_outcksum(fin, &ip->ip_sum, sumd);
#endif

		PREP_MB_T(fin, m);

		fin->fin_ip = ip;
		fin->fin_plen += 20;	/* UDP + new IPv4 hdr */
		fin->fin_dlen += 20;	/* UDP + old IPv4 hdr */
		fin->fin_flx |= FI_ENCAP;

		nflags &= ~IPN_TCPUDPICMP;

		break;
	    }

	case NAT_DIVERTIN :
	    {
		udphdr_t *uh;
		ip_t *ip;
		mb_t *m;

		m = M_DUPLICATE(np->in_divmp);
		if (m == NULL) {
			ATOMIC_INCL(ipf_nat_stats.ns_side[0].ns_divert_dup);
			return -1;
		}

		ip = MTOD(m, ip_t *);
		ip->ip_id = htons(ipf_nextipid(fin));
		sum1 = ntohs(ip->ip_len);
		ip->ip_len = ntohs(ip->ip_len);
		ip->ip_len += fin->fin_plen;
		ip->ip_len = htons(ip->ip_len);

		uh = (udphdr_t *)(ip + 1);
		uh->uh_ulen += fin->fin_plen;
		uh->uh_ulen = htons(uh->uh_ulen);

		sum2 = ntohs(ip->ip_id) + ntohs(ip->ip_len);
		sum2 += ntohs(ip->ip_off) & IP_DF;
		CALC_SUMD(sum1, sum2, sumd);

#if !defined(_KERNEL) || defined(MENTAT) || defined(__sgi) || \
     defined(__osf__) || defined(linux)
		ipf_fix_outcksum(fin, &ip->ip_sum, sumd);
#endif
		PREP_MB_T(fin, m);

		fin->fin_ip = ip;
		fin->fin_plen += 28;	/* UDP + new IPv4 hdr */
		fin->fin_dlen += 28;	/* UDP + old IPv4 hdr */

		nflags &= ~IPN_TCPUDPICMP;

		break;
	    }

	case NAT_ENCAPOUT :
		fin->fin_flx |= FI_ENCAP;
	case NAT_DIVERTOUT :
	    {
		mb_t *m;

		skip = ipf_nat_decap(fin, nat);
		if (skip <= 0) {
			ATOMIC_INCL(ipf_nat_stats.ns_side[0].ns_decap_fail);
			return -1;
		}

		m = fin->fin_m;

#if defined(MENTAT) && defined(_KERNEL)
		m->b_rptr += skip;
#else
		m->m_data += skip;
		m->m_len -= skip;

# ifdef M_PKTHDR
		if (m->m_flags & M_PKTHDR)
			m->m_pkthdr.len -= skip;
# endif
#endif

		ipf_nat_update(fin, nat, np);
		nflags &= ~IPN_TCPUDPICMP;
		fin->fin_flx |= FI_NATED;
		if (np != NULL && np->in_tag.ipt_num[0] != 0)
			fin->fin_nattag = &np->in_tag;
		return 1;
		/* NOTREACHED */
	    }
	}
	if (nflags & IPN_TCPUDP)
		tcp = fin->fin_dp;

	if (!(fin->fin_flx & FI_SHORT) && (fin->fin_off == 0)) {
		if ((nat->nat_odport != 0) && (nflags & IPN_TCPUDP)) {
			switch (nat->nat_dir)
			{
			case NAT_INBOUND :
				tcp->th_sport = nat->nat_nsport;
				fin->fin_data[0] = ntohs(nat->nat_nsport);
				tcp->th_dport = nat->nat_ndport;
				fin->fin_data[1] = ntohs(nat->nat_ndport);
				break;

			case NAT_OUTBOUND :
				tcp->th_sport = nat->nat_odport;
				fin->fin_data[0] = ntohs(nat->nat_odport);
				tcp->th_dport = nat->nat_osport;
				fin->fin_data[1] = ntohs(nat->nat_osport);
				break;
			}
		}


		if ((nat->nat_odport != 0) && (nflags & IPN_ICMPQUERY)) {
			icmp = fin->fin_dp;

			icmp->icmp_id = nat->nat_nicmpid;
		}

		csump = ipf_nat_proto(fin, nat, nflags);
	}

	ipf_nat_update(fin, nat, np);

	/*
	 * The above comments do not hold for layer 4 (or higher) checksums...
	 */
	if (csump != NULL) {
		if (nat->nat_dir == NAT_OUTBOUND)
			ipf_fix_incksum(fin, csump, nat->nat_sumd[0]);
		else
			ipf_fix_outcksum(fin, csump, nat->nat_sumd[0]);
	}
	fin->fin_flx |= FI_NATED;
	if (np != NULL && np->in_tag.ipt_num[0] != 0)
		fin->fin_nattag = &np->in_tag;
	return 1;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_proto                                               */
/* Returns:     u_short* - pointer to transport header checksum to update,  */
/*                         NULL if the transport protocol is not recognised */
/*                         as needing a checksum update.                    */
/* Parameters:  fin(I)    - pointer to packet information                   */
/*              nat(I)    - pointer to NAT structure                        */
/*              nflags(I) - NAT flags set for this packet                   */
/*                                                                          */
/* Return the pointer to the checksum field for each protocol so understood.*/
/* If support for making other changes to a protocol header is required,    */
/* that is not strictly 'address' translation, such as clamping the MSS in  */
/* TCP down to a specific value, then do it from here.                      */
/* ------------------------------------------------------------------------ */
u_short *
ipf_nat_proto(fin, nat, nflags)
	fr_info_t *fin;
	nat_t *nat;
	u_int nflags;
{
	icmphdr_t *icmp;
	u_short *csump;
	tcphdr_t *tcp;
	udphdr_t *udp;

	csump = NULL;
	if (fin->fin_out == 0) {
		fin->fin_rev = (nat->nat_dir & NAT_OUTBOUND);
	} else {
		fin->fin_rev = ((nat->nat_dir & NAT_OUTBOUND) == 0);
	}

	switch (fin->fin_p)
	{
	case IPPROTO_TCP :
		tcp = fin->fin_dp;

		if ((nflags & IPN_TCP) != 0)
			csump = &tcp->th_sum;

		/*
		 * Do a MSS CLAMPING on a SYN packet,
		 * only deal IPv4 for now.
		 */
		if ((nat->nat_mssclamp != 0) && (tcp->th_flags & TH_SYN) != 0)
			ipf_nat_mssclamp(tcp, nat->nat_mssclamp, fin, csump);

		break;

	case IPPROTO_UDP :
		udp = fin->fin_dp;

		if ((nflags & IPN_UDP) != 0) {
			if (udp->uh_sum != 0)
				csump = &udp->uh_sum;
		}
		break;

	case IPPROTO_ICMP :
		icmp = fin->fin_dp;

		if ((nflags & IPN_ICMPQUERY) != 0) {
			if (icmp->icmp_cksum != 0)
				csump = &icmp->icmp_cksum;
		}
		break;
	}
	return csump;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_unload                                              */
/* Returns:     Nil                                                         */
/* Parameters:  Nil                                                         */
/*                                                                          */
/* Free all memory used by NAT structures allocated at runtime.             */
/* ------------------------------------------------------------------------ */
void
ipf_nat_unload()
{
	ipftq_t *ifq, *ifqnext;

	(void) ipf_nat_clearlist();
	(void) ipf_nat_flushtable();

	/*
	 * Proxy timeout queues are not cleaned here because although they
	 * exist on the NAT list, appr_unload is called after unload
	 * and the proxies actually are responsible for them being created.
	 * Should the proxy timeouts have their own list?  There's no real
	 * justification as this is the only complication.
	 */
	for (ifq = ipf_nat_utqe; ifq != NULL; ifq = ifqnext) {
		ifqnext = ifq->ifq_next;
		if (((ifq->ifq_flags & IFQF_PROXY) == 0) &&
		    (ipf_deletetimeoutqueue(ifq) == 0))
			ipf_freetimeoutqueue(ifq);
	}

	if (ipf_nat_table[0] != NULL) {
		KFREES(ipf_nat_table[0], sizeof(nat_t *) * ipf_nat_table_sz);
		ipf_nat_table[0] = NULL;
	}
	if (ipf_nat_table[1] != NULL) {
		KFREES(ipf_nat_table[1], sizeof(nat_t *) * ipf_nat_table_sz);
		ipf_nat_table[1] = NULL;
	}
	if (ipf_nat_map_rules != NULL) {
		KFREES(ipf_nat_map_rules,
		       sizeof(ipnat_t *) * ipf_nat_maprules_sz);
		ipf_nat_map_rules = NULL;
	}
	if (ipf_nat_rdr_rules != NULL) {
		KFREES(ipf_nat_rdr_rules,
		       sizeof(ipnat_t *) * ipf_nat_rdrrules_sz);
		ipf_nat_rdr_rules = NULL;
	}
	if (ipf_hm_maptable != NULL) {
		KFREES(ipf_hm_maptable,
		       sizeof(hostmap_t *) * ipf_nat_hostmap_sz);
		ipf_hm_maptable = NULL;
	}
	if (ipf_nat_stats.ns_side[0].ns_bucketlen != NULL) {
		KFREES(ipf_nat_stats.ns_side[0].ns_bucketlen,
		       sizeof(u_int *) * ipf_nat_table_sz);
		ipf_nat_stats.ns_side[0].ns_bucketlen = NULL;
	}
	if (ipf_nat_stats.ns_side[1].ns_bucketlen != NULL) {
		KFREES(ipf_nat_stats.ns_side[1].ns_bucketlen,
		       sizeof(u_int *) * ipf_nat_table_sz);
		ipf_nat_stats.ns_side[1].ns_bucketlen = NULL;
	}

	if (ipf_nat_maxbucket_reset == 1)
		ipf_nat_maxbucket = 0;

	if (ipf_nat_inited == 1) {
		ipf_nat_inited = 0;
		ipf_sttab_destroy(ipf_nat_tqb);

		RW_DESTROY(&ipf_natfrag);
		RW_DESTROY(&ipf_nat);

		MUTEX_DESTROY(&ipf_nat_new);
		MUTEX_DESTROY(&ipf_natio);

		MUTEX_DESTROY(&ipf_nat_udptq.ifq_lock);
		MUTEX_DESTROY(&ipf_nat_icmptq.ifq_lock);
		MUTEX_DESTROY(&ipf_nat_iptq.ifq_lock);
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_expire                                              */
/* Returns:     Nil                                                         */
/* Parameters:  Nil                                                         */
/*                                                                          */
/* Check all of the timeout queues for entries at the top which need to be  */
/* expired.                                                                 */
/* ------------------------------------------------------------------------ */
void
ipf_nat_expire()
{
	ipftq_t *ifq, *ifqnext;
	ipftqent_t *tqe, *tqn;
	int i;
	SPL_INT(s);

	SPL_NET(s);
	WRITE_ENTER(&ipf_nat);
	for (ifq = ipf_nat_tqb, i = 0; ifq != NULL; ifq = ifq->ifq_next) {
		for (tqn = ifq->ifq_head; ((tqe = tqn) != NULL); i++) {
			if (tqe->tqe_die > ipf_ticks)
				break;
			tqn = tqe->tqe_next;
			ipf_nat_delete(tqe->tqe_parent, NL_EXPIRE);
		}
	}

	for (ifq = ipf_nat_utqe; ifq != NULL; ifq = ifqnext) {
		ifqnext = ifq->ifq_next;

		for (tqn = ifq->ifq_head; ((tqe = tqn) != NULL); i++) {
			if (tqe->tqe_die > ipf_ticks)
				break;
			tqn = tqe->tqe_next;
			ipf_nat_delete(tqe->tqe_parent, NL_EXPIRE);
		}
	}

	for (ifq = ipf_nat_utqe; ifq != NULL; ifq = ifqnext) {
		ifqnext = ifq->ifq_next;

		if (((ifq->ifq_flags & IFQF_DELETE) != 0) &&
		    (ifq->ifq_ref == 0)) {
			ipf_freetimeoutqueue(ifq);
		}
	}

	if (ipf_nat_doflush != 0) {
		ipf_nat_extraflush(2);
		ipf_nat_doflush = 0;
	}

	RWLOCK_EXIT(&ipf_nat);
	SPL_X(s);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_sync                                                */
/* Returns:     Nil                                                         */
/* Parameters:  ifp(I) - pointer to network interface                       */
/*                                                                          */
/* Walk through all of the currently active NAT sessions, looking for those */
/* which need to have their translated address updated.                     */
/* ------------------------------------------------------------------------ */
void
ipf_nat_sync(ifp)
	void *ifp;
{
	u_32_t sum1, sum2, sumd;
	i6addr_t in;
	ipnat_t *n;
	nat_t *nat;
	void *ifp2;
	int idx;
	SPL_INT(s);

	if (ipf_running <= 0)
		return;

	/*
	 * Change IP addresses for NAT sessions for any protocol except TCP
	 * since it will break the TCP connection anyway.  The only rules
	 * which will get changed are those which are "map ... -> 0/32",
	 * where the rule specifies the address is taken from the interface.
	 */
	SPL_NET(s);
	WRITE_ENTER(&ipf_nat);

	if (ipf_running <= 0) {
		RWLOCK_EXIT(&ipf_nat);
		return;
	}

	for (nat = ipf_nat_instances; nat; nat = nat->nat_next) {
		if ((nat->nat_flags & IPN_TCP) != 0)
			continue;

		n = nat->nat_ptr;
		if (n != NULL) {
			if (n->in_redir & NAT_MAP) {
				if ((n->in_nsrcaddr != 0) ||
				    (n->in_nsrcmsk != 0xffffffff))
					continue;
			} else if (n->in_redir & NAT_REDIRECT) {
				if ((n->in_ndstaddr != 0) ||
				    (n->in_ndstmsk != 0xffffffff))
					continue;
			}
		}

		if (((ifp == NULL) || (ifp == nat->nat_ifps[0]) ||
		     (ifp == nat->nat_ifps[1]))) {
			nat->nat_ifps[0] = GETIFP(nat->nat_ifnames[0],
						  nat->nat_v);
			if ((nat->nat_ifps[0] != NULL) &&
			    (nat->nat_ifps[0] != (void *)-1)) {
				nat->nat_mtu[0] = GETIFMTU(nat->nat_ifps[0]);
			}
			if (nat->nat_ifnames[1][0] != '\0') {
				nat->nat_ifps[1] = GETIFP(nat->nat_ifnames[1],
							  nat->nat_v);
			} else {
				nat->nat_ifps[1] = nat->nat_ifps[0];
			}
			if ((nat->nat_ifps[1] != NULL) &&
			    (nat->nat_ifps[1] != (void *)-1)) {
				nat->nat_mtu[1] = GETIFMTU(nat->nat_ifps[1]);
			}
			ifp2 = nat->nat_ifps[0];
			if (ifp2 == NULL)
				continue;

			/*
			 * Change the map-to address to be the same as the
			 * new one.
			 */
			sum1 = NATFSUM(nat, nat_nsrc6);
			if (ipf_ifpaddr(nat->nat_v, FRI_NORMAL, ifp2,
				       &in, NULL) != -1) {
				if (nat->nat_v == 4)
					nat->nat_nsrcip = in.in4;
			}
			sum2 = NATFSUM(nat, nat_nsrc6);

			if (sum1 == sum2)
				continue;
			/*
			 * Readjust the checksum adjustment to take into
			 * account the new IP#.
			 */
			CALC_SUMD(sum1, sum2, sumd);
			/* XXX - dont change for TCP when solaris does
			 * hardware checksumming.
			 */
			sumd += nat->nat_sumd[0];
			nat->nat_sumd[0] = (sumd & 0xffff) + (sumd >> 16);
			nat->nat_sumd[1] = nat->nat_sumd[0];
		}
	}

	for (n = ipf_nat_list; (n != NULL); n = n->in_next) {
		if ((ifp == NULL) || (n->in_ifps[0] == ifp))
			n->in_ifps[0] = ipf_resolvenic(n->in_ifnames[0],
						      n->in_v);
		if ((ifp == NULL) || (n->in_ifps[1] == ifp))
			n->in_ifps[1] = ipf_resolvenic(n->in_ifnames[1],
						      n->in_v);

		if (n->in_redir & NAT_REDIRECT)
			idx = 1;
		else
			idx = 0;

		if (((ifp == NULL) || (n->in_ifps[idx] == ifp)) &&
		    (n->in_ifps[idx] != NULL &&
		     n->in_ifps[idx] != (void *)-1)) {

			ipf_nat_nextaddrinit(&n->in_osrc, 0, n->in_ifps[idx]);
			ipf_nat_nextaddrinit(&n->in_odst, 0, n->in_ifps[idx]);
			ipf_nat_nextaddrinit(&n->in_nsrc, 0, n->in_ifps[idx]);
			ipf_nat_nextaddrinit(&n->in_ndst, 0, n->in_ifps[idx]);
		}
	}
	RWLOCK_EXIT(&ipf_nat);
	SPL_X(s);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_icmpquerytype4                                      */
/* Returns:     int - 1 == success, 0 == failure                            */
/* Parameters:  icmptype(I) - ICMP type number                              */
/*                                                                          */
/* Tests to see if the ICMP type number passed is a query/response type or  */
/* not.                                                                     */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_icmpquerytype4(icmptype)
	int icmptype;
{

	/*
	 * For the ICMP query NAT code, it is essential that both the query
	 * and the reply match on the NAT rule. Because the NAT structure
	 * does not keep track of the icmptype, and a single NAT structure
	 * is used for all icmp types with the same src, dest and id, we
	 * simply define the replies as queries as well. The funny thing is,
	 * altough it seems silly to call a reply a query, this is exactly
	 * as it is defined in the IPv4 specification
	 */

	switch (icmptype)
	{

	case ICMP_ECHOREPLY:
	case ICMP_ECHO:
	/* route aedvertisement/solliciation is currently unsupported: */
	/* it would require rewriting the ICMP data section            */
	case ICMP_TSTAMP:
	case ICMP_TSTAMPREPLY:
	case ICMP_IREQ:
	case ICMP_IREQREPLY:
	case ICMP_MASKREQ:
	case ICMP_MASKREPLY:
		return 1;
	default:
		return 0;
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    nat_log                                                     */
/* Returns:     Nil                                                         */
/* Parameters:  nat(I)    - pointer to NAT structure                        */
/*              action(I) - action related to NAT structure being performed */
/*                                                                          */
/* Creates a NAT log entry.                                                 */
/* ------------------------------------------------------------------------ */
void
ipf_nat_log(nat, action)
	struct nat *nat;
	u_int action;
{
#ifdef	IPFILTER_LOG
# ifndef LARGE_NAT
	struct ipnat *np;
	int rulen;
# endif
	struct natlog natl;
	void *items[1];
	size_t sizes[1];
	int types[1];

	bcopy((char *)&nat->nat_osrc6, (char *)&natl.nl_osrcip,
	      sizeof(natl.nl_osrcip));
	bcopy((char *)&nat->nat_nsrc6, (char *)&natl.nl_nsrcip,
	      sizeof(natl.nl_nsrcip));
	bcopy((char *)&nat->nat_odst6, (char *)&natl.nl_odstip,
	      sizeof(natl.nl_odstip));
	bcopy((char *)&nat->nat_ndst6, (char *)&natl.nl_ndstip,
	      sizeof(natl.nl_ndstip));

	natl.nl_bytes[0] = nat->nat_bytes[0];
	natl.nl_bytes[1] = nat->nat_bytes[1];
	natl.nl_pkts[0] = nat->nat_pkts[0];
	natl.nl_pkts[1] = nat->nat_pkts[1];
	natl.nl_odstport = nat->nat_odport;
	natl.nl_osrcport = nat->nat_osport;
	natl.nl_nsrcport = nat->nat_nsport;
	natl.nl_ndstport = nat->nat_ndport;
	natl.nl_p = nat->nat_pr[0];
	natl.nl_v = nat->nat_v;
	natl.nl_type = nat->nat_redir;
	natl.nl_action = action;
	natl.nl_rule = -1;

	bcopy(nat->nat_ifnames[0], natl.nl_ifnames[0],
	      sizeof(nat->nat_ifnames[0]));
	bcopy(nat->nat_ifnames[1], natl.nl_ifnames[1],
	      sizeof(nat->nat_ifnames[1]));

# ifndef LARGE_NAT
	if (nat->nat_ptr != NULL) {
		for (rulen = 0, np = ipf_nat_list; np != NULL;
		     np = np->in_next, rulen++)
			if (np == nat->nat_ptr) {
				natl.nl_rule = rulen;
				break;
			}
	}
# endif
	items[0] = &natl;
	sizes[0] = sizeof(natl);
	types[0] = 0;

	if (ipf_log_items(IPL_LOGNAT, NULL, items, sizes, types, 1) == 0)
		ipf_nat_stats.ns_side[0].ns_log++;
	else
		ipf_nat_stats.ns_side[1].ns_log++;
#endif
}


#if defined(__OpenBSD__)
/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_ifdetach                                            */
/* Returns:     Nil                                                         */
/* Parameters:  ifp(I) - pointer to network interface                       */
/*                                                                          */
/* Compatibility interface for OpenBSD to trigger the correct updating of   */
/* interface references within IPFilter.                                    */
/* ------------------------------------------------------------------------ */
void
ipf_nat_ifdetach(ifp)
	void *ifp;
{
	ipf_sync(ifp);
	return;
}
#endif


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_rulederef                                           */
/* Returns:     Nil                                                         */
/* Parameters:  isp(I) - pointer to pointer to NAT rule                     */
/* Write Locks: ipf_nat                                                     */
/*                                                                          */
/* ------------------------------------------------------------------------ */
void
ipf_nat_rulederef(inp)
	ipnat_t **inp;
{
	ipnat_t *in;

	in = *inp;
	*inp = NULL;
	in->in_space++;
	in->in_use--;
	if (in->in_use == 0 && (in->in_flags & IPN_DELETE)) {
		if (in->in_apr)
			appr_free(in->in_apr);
		ipf_nat_stats.ns_rules--;
		KFREE(in);
#if SOLARIS
		if (ipf_nat_stats.ns_rules)
			pfil_delayed_copy = 1;
#endif
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_deref                                               */
/* Returns:     Nil                                                         */
/* Parameters:  isp(I) - pointer to pointer to NAT table entry              */
/*                                                                          */
/* Decrement the reference counter for this NAT table entry and free it if  */
/* there are no more things using it.                                       */
/*                                                                          */
/* IF nat_ref == 1 when this function is called, then we have an orphan nat */
/* structure *because* it only gets called on paths _after_ nat_ref has been*/
/* incremented.  If nat_ref == 1 then we shouldn't decrement it here        */
/* because nat_delete() will do that and send nat_ref to -1.                */
/*                                                                          */
/* Holding the lock on nat_lock is required to serialise nat_delete() being */
/* called from a NAT flush ioctl with a deref happening because of a packet.*/
/* ------------------------------------------------------------------------ */
void
ipf_nat_deref(natp)
	nat_t **natp;
{
	nat_t *nat;

	nat = *natp;
	*natp = NULL;

	MUTEX_ENTER(&nat->nat_lock);
	if (nat->nat_ref > 1) {
		nat->nat_ref--;
		MUTEX_EXIT(&nat->nat_lock);
		return;
	}
	MUTEX_EXIT(&nat->nat_lock);

	WRITE_ENTER(&ipf_nat);
	ipf_nat_delete(nat, NL_EXPIRE);
	RWLOCK_EXIT(&ipf_nat);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_clone                                               */
/* Returns:     ipstate_t* - NULL == cloning failed,                        */
/*                           else pointer to new state structure            */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              is(I)  - pointer to master state structure                  */
/* Write Lock:  ipf_nat                                                     */
/*                                                                          */
/* Create a "duplcate" state table entry from the master.                   */
/* ------------------------------------------------------------------------ */
static nat_t *
ipf_nat_clone(fin, nat)
	fr_info_t *fin;
	nat_t *nat;
{
	frentry_t *fr;
	nat_t *clone;
	ipnat_t *np;

	KMALLOC(clone, nat_t *);
	if (clone == NULL) {
		ipf_nat_stats.ns_side[fin->fin_out].ns_clone_nomem++;
		return NULL;
	}
	bcopy((char *)nat, (char *)clone, sizeof(*clone));

	MUTEX_NUKE(&clone->nat_lock);

        clone->nat_aps = NULL;
	/*
	 * Initialize all these so that ipf_nat_delete() doesn't cause a crash.
	 */
	clone->nat_tqe.tqe_pnext = NULL;
	clone->nat_tqe.tqe_next = NULL;
	clone->nat_tqe.tqe_ifq = NULL;
	clone->nat_tqe.tqe_parent = clone;

	clone->nat_flags &= ~SI_CLONE;
	clone->nat_flags |= SI_CLONED;

	if (clone->nat_hm)
		clone->nat_hm->hm_ref++;

	if (ipf_nat_insert(clone, fin->fin_rev) == -1) {
		KFREE(clone);
		ipf_nat_stats.ns_side[fin->fin_out].ns_insert_fail++;
		return NULL;
	}
	np = clone->nat_ptr;
	if (np != NULL) {
		if (ipf_nat_logging)
			ipf_nat_log(clone, NL_CLONE);
		np->in_use++;
	}
	fr = clone->nat_fr;
	if (fr != NULL) {
		MUTEX_ENTER(&fr->fr_lock);
		fr->fr_ref++;
		MUTEX_EXIT(&fr->fr_lock);
	}


	/*
	 * Because the clone is created outside the normal loop of things and
	 * TCP has special needs in terms of state, initialise the timeout
	 * state of the new NAT from here.
	 */
	if (clone->nat_pr[0] == IPPROTO_TCP) {
		(void) ipf_tcp_age(&clone->nat_tqe, fin, ipf_nat_tqb,
				  clone->nat_flags, 2);
	}
#ifdef	IPFILTER_SYNC
	clone->nat_sync = ipf_sync_new(SMC_NAT, fin, clone);
#endif
	if (ipf_nat_logging)
		ipf_nat_log(clone, NL_CLONE);
	return clone;
}


/* ------------------------------------------------------------------------ */
/* Function:   ipf_nat_wildok                                               */
/* Returns:    int - 1 == packet's ports match wildcards                    */
/*                   0 == packet's ports don't match wildcards              */
/* Parameters: nat(I)   - NAT entry                                         */
/*             sport(I) - source port                                       */
/*             dport(I) - destination port                                  */
/*             flags(I) - wildcard flags                                    */
/*             dir(I)   - packet direction                                  */
/*                                                                          */
/* Use NAT entry and packet direction to determine which combination of     */
/* wildcard flags should be used.                                           */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_wildok(nat, sport, dport, flags, dir)
	nat_t *nat;
	int sport, dport, flags, dir;
{
	/*
	 * When called by       dir is set to
	 * nat_inlookup         NAT_INBOUND (0)
	 * nat_outlookup        NAT_OUTBOUND (1)
	 *
	 * We simply combine the packet's direction in dir with the original
	 * "intended" direction of that NAT entry in nat->nat_dir to decide
	 * which combination of wildcard flags to allow.
	 */
	switch ((dir << 1) | nat->nat_dir)
	{
	case 3: /* outbound packet / outbound entry */
		if (((nat->nat_osport == sport) ||
		    (flags & SI_W_SPORT)) &&
		    ((nat->nat_odport == dport) ||
		    (flags & SI_W_DPORT)))
			return 1;
		break;
	case 2: /* outbound packet / inbound entry */
		if (((nat->nat_osport == dport) ||
		    (flags & SI_W_SPORT)) &&
		    ((nat->nat_odport == sport) ||
		    (flags & SI_W_DPORT)))
			return 1;
		break;
	case 1: /* inbound packet / outbound entry */
		if (((nat->nat_osport == dport) ||
		    (flags & SI_W_SPORT)) &&
		    ((nat->nat_odport == sport) ||
		    (flags & SI_W_DPORT)))
			return 1;
		break;
	case 0: /* inbound packet / inbound entry */
		if (((nat->nat_osport == sport) ||
		    (flags & SI_W_SPORT)) &&
		    ((nat->nat_odport == dport) ||
		    (flags & SI_W_DPORT)))
			return 1;
		break;
	default:
		break;
	}

	return(0);
}


/* ------------------------------------------------------------------------ */
/* Function:    nat_mssclamp                                                */
/* Returns:     Nil                                                         */
/* Parameters:  tcp(I)    - pointer to TCP header                           */
/*              maxmss(I) - value to clamp the TCP MSS to                   */
/*              fin(I)    - pointer to packet information                   */
/*              csump(I)  - pointer to TCP checksum                         */
/*                                                                          */
/* Check for MSS option and clamp it if necessary.  If found and changed,   */
/* then the TCP header checksum will be updated to reflect the change in    */
/* the MSS.                                                                 */
/* ------------------------------------------------------------------------ */
static void
ipf_nat_mssclamp(tcp, maxmss, fin, csump)
	tcphdr_t *tcp;
	u_32_t maxmss;
	fr_info_t *fin;
	u_short *csump;
{
	u_char *cp, *ep, opt;
	int hlen, advance;
	u_32_t mss, sumd;

	hlen = TCP_OFF(tcp) << 2;
	if (hlen > sizeof(*tcp)) {
		cp = (u_char *)tcp + sizeof(*tcp);
		ep = (u_char *)tcp + hlen;

		while (cp < ep) {
			opt = cp[0];
			if (opt == TCPOPT_EOL)
				break;
			else if (opt == TCPOPT_NOP) {
				cp++;
				continue;
			}

			if (cp + 1 >= ep)
				break;
			advance = cp[1];
			if ((cp + advance > ep) || (advance <= 0))
				break;
			switch (opt)
			{
			case TCPOPT_MAXSEG:
				if (advance != 4)
					break;
				mss = cp[2] * 256 + cp[3];
				if (mss > maxmss) {
					cp[2] = maxmss / 256;
					cp[3] = maxmss & 0xff;
					CALC_SUMD(mss, maxmss, sumd);
					ipf_fix_outcksum(fin, csump, sumd);
				}
				break;
			default:
				/* ignore unknown options */
				break;
			}

			cp += advance;
		}
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_setqueue                                            */
/* Returns:     Nil                                                         */
/* Parameters:  nat(I)- pointer to NAT structure                            */
/*              rev(I) - forward(0) or reverse(1) direction                 */
/* Locks:       ipf_nat (read or write)                                     */
/*                                                                          */
/* Put the NAT entry on its default queue entry, using rev as a helped in   */
/* determining which queue it should be placed on.                          */
/* ------------------------------------------------------------------------ */
void
ipf_nat_setqueue(nat, rev)
	nat_t *nat;
	int rev;
{
	ipftq_t *oifq, *nifq;

	if (nat->nat_ptr != NULL)
		nifq = nat->nat_ptr->in_tqehead[rev];
	else
		nifq = NULL;

	if (nifq == NULL) {
		switch (nat->nat_pr[0])
		{
		case IPPROTO_UDP :
			nifq = &ipf_nat_udptq;
			break;
		case IPPROTO_ICMP :
			nifq = &ipf_nat_icmptq;
			break;
		case IPPROTO_TCP :
			nifq = ipf_nat_tqb + nat->nat_tqe.tqe_state[rev];
			break;
		default :
			nifq = &ipf_nat_iptq;
			break;
		}
	}

	oifq = nat->nat_tqe.tqe_ifq;
	/*
	 * If it's currently on a timeout queue, move it from one queue to
	 * another, else put it on the end of the newly determined queue.
	 */
	if (oifq != NULL)
		ipf_movequeue(&nat->nat_tqe, oifq, nifq);
	else
		ipf_queueappend(&nat->nat_tqe, nifq, nat);
	return;
}


/* ------------------------------------------------------------------------ */
/* Function:    nat_getnext                                                 */
/* Returns:     int - 0 == ok, else error                                   */
/* Parameters:  t(I)   - pointer to ipftoken structure                      */
/*              itp(I) - pointer to ipfgeniter_t structure                  */
/*                                                                          */
/* Fetch the next nat/ipnat structure pointer from the linked list and      */
/* copy it out to the storage space pointed to by itp_data.  The next item  */
/* in the list to look at is put back in the ipftoken struture.             */
/* If we call ipf_freetoken, the accompanying pointer is set to NULL because*/
/* ipf_freetoken will call a deref function for us and we dont want to call */
/* that twice (second time would be in the second switch statement below.   */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_getnext(t, itp)
	ipftoken_t *t;
	ipfgeniter_t *itp;
{
	hostmap_t *hm, *nexthm = NULL, zerohm;
	ipnat_t *ipn, *nextipnat = NULL, zeroipn;
	nat_t *nat, *nextnat = NULL, zeronat;
	int error = 0, count;
	ipftoken_t *freet;
	char *dst;

	freet = NULL;
	count = itp->igi_nitems;
	if (count < 1)
		return ENOSPC;

	READ_ENTER(&ipf_nat);

	switch (itp->igi_type)
	{
	case IPFGENITER_HOSTMAP :
		hm = t->ipt_data;
		if (hm == NULL) {
			nexthm = ipf_hm_maplist;
		} else {
			nexthm = hm->hm_next;
		}
		break;

	case IPFGENITER_IPNAT :
		ipn = t->ipt_data;
		if (ipn == NULL) {
			nextipnat = ipf_nat_list;
		} else {
			nextipnat = ipn->in_next;
		}
		break;

	case IPFGENITER_NAT :
		nat = t->ipt_data;
		if (nat == NULL) {
			nextnat = ipf_nat_instances;
		} else {
			nextnat = nat->nat_next;
		}
		break;
	default :
		RWLOCK_EXIT(&ipf_nat);
		ipf_interror = 60055;
		return EINVAL;
	}

	dst = itp->igi_data;
	for (;;) {
		switch (itp->igi_type)
		{
		case IPFGENITER_HOSTMAP :
			if (nexthm != NULL) {
				if (nexthm->hm_next == NULL) {
					freet = t;
					count = 1;
				}
				if (count == 1) {
					ATOMIC_INC32(nexthm->hm_ref);
				}
			} else {
				bzero(&zerohm, sizeof(zerohm));
				nexthm = &zerohm;
				count = 1;
			}
			break;

		case IPFGENITER_IPNAT :
			if (nextipnat != NULL) {
				if (nextipnat->in_next == NULL) {
					freet = t;
					count = 1;
				}
				if (count == 1) {
					MUTEX_ENTER(&nextipnat->in_lock);
					nextipnat->in_use++;
					MUTEX_EXIT(&nextipnat->in_lock);
				}
			} else {
				bzero(&zeroipn, sizeof(zeroipn));
				nextipnat = &zeroipn;
				count = 1;
			}
			break;

		case IPFGENITER_NAT :
			if (nextnat != NULL) {
				if (nextnat->nat_next == NULL) {
					count = 1;
					freet = t;
				}
				if (count == 1) {
					MUTEX_ENTER(&nextnat->nat_lock);
					nextnat->nat_ref++;
					MUTEX_EXIT(&nextnat->nat_lock);
				}
			} else {
				bzero(&zeronat, sizeof(zeronat));
				nextnat = &zeronat;
				count = 1;
			}
			break;
		default :
			break;
		}
		RWLOCK_EXIT(&ipf_nat);

		if (freet != NULL) {
			ipf_freetoken(freet);
		}

		switch (itp->igi_type)
		{
		case IPFGENITER_HOSTMAP :
			error = COPYOUT(nexthm, dst, sizeof(*nexthm));
			if (error != 0) {
				ipf_interror = 60049;
				error = EFAULT;
			} else {
				dst += sizeof(*nexthm);
			}
			if (freet == NULL) {
				t->ipt_data = nexthm;
				hm = nexthm;
				nexthm = hm->hm_next;
			}
			break;

		case IPFGENITER_IPNAT :
			error = COPYOUT(nextipnat, dst, sizeof(*nextipnat));
			if (error != 0) {
				ipf_interror = 60050;
				error = EFAULT;
			} else {
				dst += sizeof(*nextipnat);
			}
			if (freet == NULL) {
				t->ipt_data = nextipnat;
				ipn = nextipnat;
				nextipnat = ipn->in_next;
			}
			break;

		case IPFGENITER_NAT :
			error = COPYOUT(nextnat, dst, sizeof(*nextnat));
			if (error != 0) {
				ipf_interror = 60051;
				error = EFAULT;
			} else {
				dst += sizeof(*nextnat);
			}
			if (freet == NULL) {
				t->ipt_data = nextnat;
				nat = nextnat;
				nextnat = nat->nat_next;
			}
			break;
		}

		if ((count == 1) || (error != 0))
			break;

		READ_ENTER(&ipf_nat);
	}

	return error;
}


/* ------------------------------------------------------------------------ */
/* Function:    nat_extraflush                                              */
/* Returns:     int - 0 == success, -1 == failure                           */
/* Parameters:  which(I) - how to flush the active NAT table                */
/* Write Locks: ipf_nat                                                     */
/*                                                                          */
/* Flush nat tables.  Three actions currently defined:                      */
/* which == 0 : flush all nat table entries                                 */
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
ipf_nat_extraflush(which)
	int which;
{
	ipftq_t *ifq, *ifqnext;
	nat_t *nat, **natp;
	ipftqent_t *tqn;
	int removed;
	SPL_INT(s);

	removed = 0;

	SPL_NET(s);
	switch (which)
	{
	case 0 :
		ipf_nat_stats.ns_flush_all++;
		/*
		 * Style 0 flush removes everything...
		 */
		for (natp = &ipf_nat_instances; ((nat = *natp) != NULL); ) {
			ipf_nat_delete(nat, NL_FLUSH);
			removed++;
		}
		break;

	case 1 :
		ipf_nat_stats.ns_flush_closing++;
		/*
		 * Since we're only interested in things that are closing,
		 * we can start with the appropriate timeout queue.
		 */
		for (ifq = ipf_nat_tqb + IPF_TCPS_CLOSE_WAIT; ifq != NULL;
		     ifq = ifq->ifq_next) {

			for (tqn = ifq->ifq_head; tqn != NULL; ) {
				nat = tqn->tqe_parent;
				tqn = tqn->tqe_next;
				if (nat->nat_pr[0] != IPPROTO_TCP ||
				    nat->nat_pr[1] != IPPROTO_TCP)
					break;
				ipf_nat_delete(nat, NL_EXPIRE);
				removed++;
			}
		}

		/*
		 * Also need to look through the user defined queues.
		 */
		for (ifq = ipf_nat_utqe; ifq != NULL; ifq = ifqnext) {
			ifqnext = ifq->ifq_next;
			for (tqn = ifq->ifq_head; tqn != NULL; ) {
				nat = tqn->tqe_parent;
				tqn = tqn->tqe_next;
				if (nat->nat_pr[0] != IPPROTO_TCP ||
				    nat->nat_pr[1] != IPPROTO_TCP)
					continue;

				if ((nat->nat_tcpstate[0] >
				     IPF_TCPS_ESTABLISHED) &&
				    (nat->nat_tcpstate[1] >
				     IPF_TCPS_ESTABLISHED)) {
					ipf_nat_delete(nat, NL_EXPIRE);
					removed++;
				}
			}
		}
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
		ipf_nat_stats.ns_flush_state++;
		tqn = ipf_nat_tqb[which].ifq_head;
		while (tqn != NULL) {
			nat = tqn->tqe_parent;
			tqn = tqn->tqe_next;
			ipf_nat_delete(nat, NL_FLUSH);
			removed++;
		}
		break;

	default :
		if (which < 30)
			break;

		ipf_nat_stats.ns_flush_timeout++;
		/*
		 * Take a large arbitrary number to mean the number of seconds
		 * for which which consider to be the maximum value we'll allow
		 * the expiration to be.
		 */
		which = IPF_TTLVAL(which);
		for (natp = &ipf_nat_instances; ((nat = *natp) != NULL); ) {
			if (ipf_ticks - nat->nat_touched > which) {
				ipf_nat_delete(nat, NL_FLUSH);
				removed++;
			} else
				natp = &nat->nat_next;
		}
		break;
	}

	if (which != 2) {
		SPL_X(s);
		return removed;
	}

	ipf_nat_stats.ns_flush_queue++;

	/*
	 * Asked to remove inactive entries because the table is full, try
	 * again, 3 times, if first attempt failed with a different criteria
	 * each time.  The order tried in must be in decreasing age.
	 * Another alternative is to implement random drop and drop N entries
	 * at random until N have been freed up.
	 */
	if (ipf_ticks - ipf_nat_last_force_flush > IPF_TTLVAL(5)) {
		ipf_nat_last_force_flush = ipf_ticks;

		removed = ipf_queueflush(ipf_nat_flush_entry, ipf_nat_tqb,
					 ipf_nat_utqe, &ipf_nat_stats.ns_active,
					 ipf_nat_table_sz,
					 ipf_nat_table_wm_low);
	}

	SPL_X(s);
	return removed;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_flush_entry                                         */
/* Returns:     0 - always succeeds                                         */
/* Parameters:  entry(I) - pointer to NAT entry                             */
/* Write Locks: ipf_nat                                                     */
/*                                                                          */
/* This function is a stepping stone between ipf_queueflush() and           */
/* nat_dlete().  It is used so we can provide a uniform interface via the   */
/* ipf_queueflush() function.  Since the nat_delete() function returns void */
/* we translate that to mean it always succeeds in deleting something.      */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_flush_entry(entry)
	void *entry;
{
	ipf_nat_delete(entry, NL_FLUSH);
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_iterator                                            */
/* Returns:     int - 0 == ok, else error                                   */
/* Parameters:  token(I) - pointer to ipftoken structure                    */
/*              itp(I) - pointer to ipfgeniter_t structure                  */
/*                                                                          */
/* This function acts as a handler for the SIOCGENITER ioctls that use a    */
/* generic structure to iterate through a list.  There are three different  */
/* linked lists of NAT related information to go through: NAT rules, active */
/* NAT mappings and the NAT fragment cache.                                 */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_iterator(token, itp)
	ipftoken_t *token;
	ipfgeniter_t *itp;
{
	int error;

	if (itp->igi_data == NULL) {
		ipf_interror = 60052;
		return EFAULT;
	}

	token->ipt_subtype = itp->igi_type;

	switch (itp->igi_type)
	{
	case IPFGENITER_HOSTMAP :
	case IPFGENITER_IPNAT :
	case IPFGENITER_NAT :
		error = ipf_nat_getnext(token, itp);
		break;

	case IPFGENITER_NATFRAG :
#ifdef USE_MUTEXES
		error = ipf_frag_next(token, itp, &ipfr_natlist,
				    &ipfr_nattail, &ipf_natfrag);
#else
		error = ipf_frag_next(token, itp, &ipfr_natlist, &ipfr_nattail);
#endif
		break;
	default :
		ipf_interror = 60053;
		error = EINVAL;
		break;
	}

	return error;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_setpending                                          */
/* Returns:     Nil                                                         */
/* Parameters:  nat(I) - pointer to NAT structure                           */
/* Locks:       ipf_nat (read or write)                                     */
/*                                                                          */
/* Put the NAT entry on to the pending queue - this queue has a very short  */
/* lifetime where items are put that can't be deleted straight away because */
/* of locking issues but we want to delete them ASAP, anyway.  In calling   */
/* this function, it is assumed that the owner (if there is one, as shown   */
/* by nat_me) is no longer interested in it.                                */
/* ------------------------------------------------------------------------ */
void
ipf_nat_setpending(nat)
	nat_t *nat;
{
	ipftq_t *oifq;

	oifq = nat->nat_tqe.tqe_ifq;
	if (oifq != NULL)
		ipf_movequeue(&nat->nat_tqe, oifq, &ipf_nat_pending);
	else
		ipf_queueappend(&nat->nat_tqe, &ipf_nat_pending, nat);

	if (nat->nat_me != NULL) {
		*nat->nat_me = NULL;
		nat->nat_me = NULL;
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    nat_newrewrite                                              */
/* Returns:     int - -1 == error, 0 == success (no move), 1 == success and */
/*                    allow rule to be moved if IPN_ROUNDR is set.          */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              nat(I) - pointer to NAT entry                               */
/*              ni(I)  - pointer to structure with misc. information needed */
/*                       to create new NAT entry.                           */
/* Write Lock:  ipf_nat                                                     */
/*                                                                          */
/* This function is responsible for setting up an active NAT session where  */
/* we are changing both the source and destination parameters at the same   */
/* time.  The loop in here works differently to elsewhere - each iteration  */
/* is responsible for changing a single parameter that can be incremented.  */
/* So one pass may increase the source IP#, next source port, next dest. IP#*/
/* and the last destination port for a total of 4 iterations to try each.   */
/* This is done to try and exhaustively use the translation space available.*/
/* ------------------------------------------------------------------------ */
static int
ipf_nat_newrewrite(fin, nat, nai)
	fr_info_t *fin;
	nat_t *nat;
	natinfo_t *nai;
{
	int src_search = 1;
	int dst_search = 1;
	fr_info_t frnat;
	u_32_t flags;
	u_short swap;
	ipnat_t *np;
	nat_t *natl;
	int l = 0;
	int changed;

	natl = NULL;
	changed = -1;
	np = nai->nai_np;
	flags = nai->nai_flags;
	bcopy((char *)fin, (char *)&frnat, sizeof(*fin));
	frnat.fin_state = NULL;

	nat->nat_hm = NULL;

	do {
		changed = -1;
		/* TRACE (l, src_search, dst_search, np) */

		if ((src_search == 0) && (np->in_spnext == 0) &&
		    (dst_search == 0) && (np->in_dpnext == 0)) {
			if (l > 0)
				return -1;
		}

		/*
		 * Find a new source address
		 */
		if (ipf_nat_nextaddr(fin, &np->in_nsrc, &frnat.fin_saddr,
				 &frnat.fin_saddr) == -1) {
			return -1;
		}

		if ((np->in_nsrcaddr == 0) && (np->in_nsrcmsk == 0xffffffff)) {
			src_search = 0;
			if (np->in_stepnext == 0)
				np->in_stepnext = 1;

		} else if ((np->in_nsrcaddr == 0) && (np->in_nsrcmsk == 0)) {
			src_search = 0;
			if (np->in_stepnext == 0)
				np->in_stepnext = 1;

		} else if (np->in_nsrcmsk == 0xffffffff) {
			src_search = 0;
			if (np->in_stepnext == 0)
				np->in_stepnext = 1;

		} else if (np->in_nsrcmsk != 0xffffffff) {
			if (np->in_stepnext == 0 && changed == -1) {
				np->in_snip++;
				np->in_stepnext++;
				changed = 0;
			}
		}

		if ((flags & IPN_TCPUDPICMP) != 0) {
			if (np->in_spnext != 0)
				frnat.fin_data[0] = np->in_spnext;

			/*
			 * Standard port translation.  Select next port.
			 */
			if ((flags & IPN_FIXEDSPORT) != 0) {
				np->in_stepnext = 2;
			} else if ((np->in_stepnext == 1) &&
				   (changed == -1) && (natl != NULL)) {
				np->in_spnext++;
				np->in_stepnext++;
				changed = 1;
				if (np->in_spnext > np->in_spmax)
					np->in_spnext = np->in_spmin;
			}
		} else {
			np->in_stepnext = 2;
		}
		np->in_stepnext &= 0x3;

		/*
		 * Find a new destination address
		 */
		/* TRACE (fin, np, l, frnat) */

		if (ipf_nat_nextaddr(fin, &np->in_ndst, &frnat.fin_daddr,
				 &frnat.fin_daddr) == -1)
			return -1;

		if ((np->in_ndstaddr == 0) && (np->in_ndstmsk == 0xffffffff)) {
			dst_search = 0;
			if (np->in_stepnext == 2)
				np->in_stepnext = 3;

		} else if ((np->in_ndstaddr == 0) && (np->in_ndstmsk == 0)) {
			dst_search = 0;
			if (np->in_stepnext == 2)
				np->in_stepnext = 3;

		} else if (np->in_ndstmsk == 0xffffffff) {
			dst_search = 0;
			if (np->in_stepnext == 2)
				np->in_stepnext = 3;

		} else if (np->in_ndstmsk != 0xffffffff) {
			if ((np->in_stepnext == 2) && (changed == -1) &&
			    (natl != NULL)) {
				changed = 2;
				np->in_stepnext++;
				np->in_dnip++;
			}
		}

		if ((flags & IPN_TCPUDPICMP) != 0) {
			if (np->in_dpnext != 0)
				frnat.fin_data[1] = np->in_dpnext;

			/*
			 * Standard port translation.  Select next port.
			 */
			if ((flags & IPN_FIXEDDPORT) != 0) {
				np->in_stepnext = 0;
			} else if (np->in_stepnext == 3 && changed == -1) {
				np->in_dpnext++;
				np->in_stepnext++;
				changed = 3;
				if (np->in_dpnext > np->in_dpmax)
					np->in_dpnext = np->in_dpmin;
			}
		} else {
			if (np->in_stepnext == 3)
				np->in_stepnext = 0;
		}

		/* TRACE (frnat) */

		/*
		 * Here we do a lookup of the connection as seen from
		 * the outside.  If an IP# pair already exists, try
		 * again.  So if you have A->B becomes C->B, you can
		 * also have D->E become C->E but not D->B causing
		 * another C->B.  Also take protocol and ports into
		 * account when determining whether a pre-existing
		 * NAT setup will cause an external conflict where
		 * this is appropriate.
		 *
		 * fin_data[] is swapped around because we are doing a
		 * lookup of the packet is if it were moving in the opposite
		 * direction of the one we are working with now.
		 */
		if (flags & IPN_TCPUDP) {
			swap = frnat.fin_data[0];
			frnat.fin_data[0] = frnat.fin_data[1];
			frnat.fin_data[1] = swap;
		}
		if (fin->fin_out == 1) {
			natl = ipf_nat_inlookup(&frnat,
					    flags & ~(SI_WILDP|NAT_SEARCH),
					    (u_int)frnat.fin_p, frnat.fin_dst,
					    frnat.fin_src);

		} else {
			natl = ipf_nat_outlookup(&frnat,
					     flags & ~(SI_WILDP|NAT_SEARCH),
					     (u_int)frnat.fin_p, frnat.fin_dst,
					     frnat.fin_src);
		}
		if (flags & IPN_TCPUDP) {
			swap = frnat.fin_data[0];
			frnat.fin_data[0] = frnat.fin_data[1];
			frnat.fin_data[1] = swap;
		}

		/* TRACE natl, in_stepnext, l */

		if ((natl != NULL) && (l > 8))	/* XXX 8 is arbitrary */
			return -1;

		np->in_stepnext &= 0x3;

		l++;
		changed = -1;
	} while (natl != NULL);
	nat->nat_osrcip = fin->fin_src;
	nat->nat_odstip = fin->fin_dst;
	nat->nat_nsrcip = frnat.fin_src;
	nat->nat_ndstip = frnat.fin_dst;

	if ((flags & IPN_TCPUDPICMP) != 0) {
		nat->nat_osport = htons(fin->fin_data[0]);
		nat->nat_odport = htons(fin->fin_data[1]);
		nat->nat_nsport = htons(frnat.fin_data[0]);
		nat->nat_ndport = htons(frnat.fin_data[1]);
	}

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    nat_newdivert                                               */
/* Returns:     int - -1 == error, 0 == success                             */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              nat(I) - pointer to NAT entry                               */
/*              ni(I)  - pointer to structure with misc. information needed */
/*                       to create new NAT entry.                           */
/* Write Lock:  ipf_nat                                                     */
/*                                                                          */
/* Create a new NAT encap/divert session as defined by the NAT rule.  This  */
/* is somewhat different to other NAT session creation routines because we  */
/* do not iterate through either port numbers or IP addresses, searching    */
/* for a unique mapping, however, a complimentary duplicate check is made.  */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_newdivert(fin, nat, nai)
	fr_info_t *fin;
	nat_t *nat;
	natinfo_t *nai;
{
	fr_info_t frnat;
	ipnat_t *np;
	nat_t *natl;
	int p;

	np = nai->nai_np;
	bcopy((char *)fin, (char *)&frnat, sizeof(*fin));

	nat->nat_pr[0] = 0;
	nat->nat_osrcaddr = fin->fin_saddr;
	nat->nat_odstaddr = fin->fin_daddr;
	nat->nat_osport = htons(fin->fin_data[0]);
	nat->nat_odport = htons(fin->fin_data[1]);
	frnat.fin_saddr = htonl(np->in_snip);
	frnat.fin_daddr = htonl(np->in_dnip);

	if (np->in_redir & NAT_DIVERTUDP) {
		frnat.fin_data[0] = np->in_spnext;
		frnat.fin_data[1] = np->in_dpnext;
		frnat.fin_flx |= FI_TCPUDP;
		p = IPPROTO_UDP;
	} else {
		frnat.fin_flx &= ~FI_TCPUDP;
		p = IPPROTO_ENCAP;
	}

	if (fin->fin_out == 1) {
		natl = ipf_nat_inlookup(&frnat, 0, p,
				    frnat.fin_dst, frnat.fin_src);

	} else {
		natl = ipf_nat_outlookup(&frnat, 0, p,
				     frnat.fin_dst, frnat.fin_src);
	}

	if (natl != NULL) {
		ATOMIC_INCL(ipf_nat_stats.ns_side[fin->fin_out].
			    ns_divert_exist);
		return -1;
	}

	nat->nat_nsrcaddr = frnat.fin_saddr;
	nat->nat_ndstaddr = frnat.fin_daddr;
	if (np->in_redir & NAT_DIVERTUDP) {
		nat->nat_nsport = htons(frnat.fin_data[0]);
		nat->nat_ndport = htons(frnat.fin_data[1]);
	}
	nat->nat_pr[fin->fin_out] = fin->fin_p;
	nat->nat_pr[1 - fin->fin_out] = p;

	if (np->in_redir & NAT_ENCAP) {
		if (np->in_redir & NAT_REDIRECT)
			nat->nat_dir = NAT_ENCAPIN;
		else
			nat->nat_dir = NAT_ENCAPOUT;
	} else {
		if (np->in_redir & NAT_REDIRECT)
			nat->nat_dir = NAT_DIVERTIN;
		else
			nat->nat_dir = NAT_DIVERTOUT;
	}

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    nat_builddivertmp                                           */
/* Returns:     int - -1 == error, 0 == success                             */
/* Parameters:  np(I) - pointer to a NAT rule                               */
/*                                                                          */
/* For encap/divert rules, a skeleton packet representing what will be      */
/* prepended to the real packet is created.  Even though we don't have the  */
/* full packet here, a checksum is calculated that we update later when we  */
/* fill in the final details.  At present a 0 checksum for UDP is being set */
/* here because it is expected that divert will be used for localhost.      */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_builddivertmp(np)
	ipnat_t *np;
{
	udphdr_t *uh;
	size_t len;
	ip_t *ip;

	if ((np->in_redir & NAT_DIVERTUDP) != 0)
		len = sizeof(ip_t) + sizeof(udphdr_t);
	else
		len = sizeof(ip_t);

	ALLOC_MB_T(np->in_divmp, len);
	if (np->in_divmp == NULL) {
		ATOMIC_INCL(ipf_nat_stats.ns_divert_build);
		return -1;
	}

	/*
	 * First, the header to get the packet diverted to the new destination
	 */
	ip = MTOD(np->in_divmp, ip_t *);
	IP_V_A(ip, 4);
	IP_HL_A(ip, 5);
	ip->ip_tos = 0;
	if ((np->in_redir & NAT_DIVERTUDP) != 0)
		ip->ip_p = IPPROTO_UDP;
	else
		ip->ip_p = IPPROTO_ENCAP;
	ip->ip_ttl = 255;
	ip->ip_off = 0;
	ip->ip_sum = 0;
	ip->ip_len = htons(len);
	ip->ip_id = 0;
	ip->ip_src.s_addr = htonl(np->in_snip);
	ip->ip_dst.s_addr = htonl(np->in_dnip);
	ip->ip_sum = ipf_cksum((u_short *)ip, sizeof(*ip));

	if (np->in_redir & NAT_DIVERTUDP) {
		uh = (udphdr_t *)(ip + 1);
		uh->uh_sum = 0;
		uh->uh_ulen = 8;
		uh->uh_sport = htons(np->in_spnext);
		uh->uh_dport = htons(np->in_dpnext);
	}

	return 0;
}


#define	MINDECAP	(sizeof(ip_t) + sizeof(udphdr_t) + sizeof(ip_t))

/* ------------------------------------------------------------------------ */
/* Function:    nat_decap                                                   */
/* Returns:     int - -1 == error, 0 == success                             */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              nat(I) - pointer to current NAT session                     */
/*                                                                          */
/* This function is responsible for undoing a packet's encapsulation in the */
/* reverse of an encap/divert rule.  After removing the outer encapsulation */
/* it is necessary to call ipf_makefrip() again so that the contents of 'fin'*/
/* match the "new" packet as it may still be used by IPFilter elsewhere.    */
/* We use "dir" here as the basis for some of the expectations about the    */
/* outer header.  If we return an error, the goal is to leave the original  */
/* packet information undisturbed - this falls short at the end where we'd  */
/* need to back a backup copy of "fin" - expensive.                         */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_decap(fin, nat)
	fr_info_t *fin;
	nat_t *nat;
{
	char *hdr;
	int hlen;
	int skip;
	mb_t *m;

	if ((fin->fin_flx & FI_ICMPERR) != 0) {
		/*
		 * ICMP packets don't get decapsulated, instead what we need
		 * to do is change the ICMP reply from including (in the data
		 * portion for errors) the encapsulated packet that we sent
		 * out to something that resembles the original packet prior
		 * to encapsulation.  This isn't done here - all we're doing
		 * here is changing the outer address to ensure that it gets
		 * targetted back to the correct system.
		 */

		if (nat->nat_dir & NAT_OUTBOUND) {
			u_32_t sum1, sum2, sumd;

			sum1 = ntohl(fin->fin_daddr);
			sum2 = ntohl(nat->nat_osrcaddr);
			CALC_SUMD(sum1, sum2, sumd);
			fin->fin_ip->ip_dst = nat->nat_osrcip;
			fin->fin_daddr = nat->nat_osrcaddr;
#if !defined(_KERNEL) || defined(MENTAT) || defined(__sgi) || \
defined(__osf__) || defined(linux)
			ipf_fix_outcksum(fin, &fin->fin_ip->ip_sum, sumd);
#endif
		}
		return 0;
	}

	m = fin->fin_m;
	skip = fin->fin_hlen;

	switch (nat->nat_dir)
	{
	case NAT_DIVERTIN :
	case NAT_DIVERTOUT :
		if (fin->fin_plen < MINDECAP)
			return -1;
		skip += sizeof(udphdr_t);
		break;

	case NAT_ENCAPIN :
	case NAT_ENCAPOUT :
		if (fin->fin_plen < (skip + sizeof(ip_t)))
			return -1;
		break;
	default :
		return -1;
		/* NOTREACHED */
	}

	/*
	 * The aim here is to keep the original packet details in "fin" for
	 * as long as possible so that returning with an error is for the
	 * original packet and there is little undoing work to do.
	 */
	if (M_LEN(m) < skip + sizeof(ip_t)) {
		if (ipf_pr_pullup(fin, skip + sizeof(ip_t)) == -1)
			return -1;
	}

	hdr = MTOD(fin->fin_m, char *);
	fin->fin_ip = (ip_t *)(hdr + skip);
	hlen = IP_HL(fin->fin_ip) << 2;

	if (ipf_pr_pullup(fin, skip + hlen) == -1) {
		ATOMIC_INCL(ipf_nat_stats.ns_side[fin->fin_out].
			    ns_decap_pullup);
		return -1;
	}

	fin->fin_hlen = hlen;
	fin->fin_dlen -= skip;
	fin->fin_plen -= skip;
	fin->fin_ipoff += skip;

	if (ipf_makefrip(hlen, (ip_t *)hdr, fin) == -1) {
		ATOMIC_INCL(ipf_nat_stats.ns_side[fin->fin_out].ns_decap_bad);
		return -1;
	}

	return skip;
}


/* ------------------------------------------------------------------------ */
/* Function:    nat_matchencap                                              */
/* Returns:     int - -1 == packet error, 1 == success, 0 = no match        */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              np(I) - pointer to a NAT rule                               */
/*                                                                          */
/* To properly compare a packet travelling in the reverse direction to an   */
/* encap rule, it needs to be pseudo-decapsulated so we can check if a      */
/* reply to it would be encapsulated.  In doing this, we have to be careful */
/* so as not to actually do any decapsulation nor affect any of the current */
/* stored parameters in "fin" so that we can continue processing it else-   */
/* where if it doesn't match.                                               */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_matchencap(fin, np)
	fr_info_t *fin;
	ipnat_t *np;
{
	int hlen, match, skip;
	u_short *ports;
	frtuc_t *ft;
	fr_ip_t fi;
	char *hdr;
	ip_t *ip;
	mb_t *m;

	/*
	 * This function is only for matching packets that are appearing from
	 * the reverse direction against "encap" rules.
	 */
	if (fin->fin_out == 1) {
		if ((np->in_redir & NAT_REDIRECT) == 0)
			return 0;
	} else {
		if ((np->in_redir & NAT_MAP) == 0)
			return 0;
	}
	if (np->in_pr[fin->fin_out] != fin->fin_p)
		return 0;

	/*
	 * The aim here is to keep the original packet details in "fin" for
	 * as long as possible so that returning with an error is for the
	 * original packet and there is little undoing work to do.
	 */
	m = fin->fin_m;
	skip = fin->fin_hlen;
	if (M_LEN(m) < skip + sizeof(ip_t)) {
		if (ipf_pr_pullup(fin, sizeof(ip_t)) == -1) {
			ATOMIC_INCL(ipf_nat_stats.ns_side[fin->fin_out].
				    ns_encap_pullup);
			return -1;
		}
	}

	hdr = MTOD(fin->fin_m, char *);
	ip = (ip_t *)(hdr + skip);
	hlen = IP_HL(ip) << 2;

	if (ipf_pr_pullup(fin, hlen) == -1) {
		ATOMIC_INCL(ipf_nat_stats.ns_side[fin->fin_out].
			    ns_encap_pullup);
		return -1;
	}

	match = 1;

	/*
	 * Now we should have the entire innder header, so match up the
	 * address fields - easy enough.  Reverse matching of source and
	 * destination because this is purportedly a "reply" to an encap rule.
	 */
	switch (np->in_osrcatype)
	{
	case FRI_NORMAL :
		match = ((ip->ip_dst.s_addr & np->in_osrcmsk)
			 != np->in_osrcaddr);
		break;
#ifdef IPFILTER_LOOKUP
	case FRI_LOOKUP :
		match = (*np->in_nsrcfunc)(np->in_osrcptr, np->in_v,
					   &ip->ip_dst.s_addr);
		break;
#endif
	}
	if (match)
		return 0;

	switch (np->in_odstatype)
	{
	case FRI_NORMAL :
		match = ((ip->ip_src.s_addr & np->in_odstmsk)
			 != np->in_odstaddr);
		break;
#ifdef IPFILTER_LOOKUP
	case FRI_LOOKUP :
		match = (*np->in_nsrcfunc)(np->in_odstptr, np->in_v,
					   &ip->ip_src.s_addr);
		break;
#endif
	}
	if (match)
		return 0;

	ft = &np->in_tuc;

	switch (ip->ip_p)
	{
	case IPPROTO_TCP :
	case IPPROTO_UDP :
		/*
		 * Only need to fetch port numbers for NAT
		 */
		if (ipf_pr_pullup(fin, hlen + 4) == -1) {
			ipf_nat_stats.ns_side[fin->fin_out].ns_encap_pullup++;
			return -1;
		}

		ports = (u_short *)((char *)ip + hlen);

		fi.fi_tcpf = 0;
		/*
		 * And again, because we're simulating a reply, put the port
		 * numbers in the revese place to where they are now.
		 */
		fi.fi_ports[0] = ntohs(ports[1]);
		fi.fi_ports[1] = ntohs(ports[0]);
		return ipf_tcpudpchk(&fi, ft);

		/* NOTREACHED */

	default :
		if (ft->ftu_scmp || ft->ftu_dcmp)
			return 0;
		break;
	}

	return 1;
}


/* ------------------------------------------------------------------------ */
/* Function:    nat_nextaddr                                                */
/* Returns:     int - -1 == bad input (no new address),                     */
/*                     0 == success and dst has new address                 */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              na(I)  - how to generate new address                        */
/*              old(I) - original address being replaced                    */
/*              dst(O) - where to put the new address                       */
/* Write Lock:  ipf_nat                                                     */
/*                                                                          */
/* This function uses the contents of the "na" structure, in combination    */
/* with "old" to produce a new address to store in "dst".  Not all of the   */
/* possible uses of "na" will result in a new address.                      */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_nextaddr(fin, na, old, dst)
	fr_info_t *fin;
	nat_addr_t *na;
	u_32_t *old, *dst;
{
	u_32_t min, max, new;
	i6addr_t newip;
	int range;

	new = 0;
	min = na->na_addr[0].in4.s_addr;

	switch (na->na_atype)
	{
	case FRI_RANGE :
		max = na->na_addr[1].in4.s_addr;
		break;

	case FRI_NETMASKED :
	case FRI_DYNAMIC :
	case FRI_NORMAL :
		/*
		 * Compute the maximum address by adding the inverse of the
		 * netmask to the minimum address.
		 */
		max = ~na->na_addr[1].in4.s_addr;
		max |= min;
		break;

	case FRI_BROADCAST :
	case FRI_PEERADDR :
	case FRI_NETWORK :
	case FRI_LOOKUP :
	default :
		return -1;
	}

	switch (na->na_function)
	{
	case NA_RANDOM :
		range = ntohl(max) - ntohl(min);
		new = ipf_random(range);
		new += ntohl(min);
		new = htonl(new);
		break;

	case NA_NORMAL :
		/*
		 * 0/0 as the new address means leave it alone.
		 */
		if (na->na_addr[0].in4.s_addr == 0 &&
		    na->na_addr[1].in4.s_addr == 0) {
			new = *old;

		/*
		 * 0/32 means get the interface's address
		 */
		} else if (na->na_addr[0].in4.s_addr == 0 &&
			   na->na_addr[1].in4.s_addr == 0xffffffff) {
			if (ipf_ifpaddr(fin->fin_v, na->na_atype,
				       fin->fin_ifp, &newip, NULL) == -1) {
				ipf_nat_stats.ns_side[fin->fin_out].
					      ns_ifpaddrfail++;
				return -1;
			}
			new = newip.in4.s_addr;
		} else {
			new = htonl(na->na_nextip);
		}
		break;

	case NA_HASHMD5 :
	    {
		u_char hash[16];
		MD5_CTX ctx;

		range = ntohl(max) - ntohl(min);
		MD5Init(&ctx);
		MD5Update(&ctx, (u_char *)dst, 4);
		MD5Final(hash, &ctx);
		new = 0;
		if (range > 0xffffff)
			new = hash[0];
		new <<= 8;
		if (range > 0xffff)
			new |= hash[1];
		new <<= 8;
		if (range > 0xff)
			new |= hash[2];
		new <<= 8;
		new |= hash[3];
		new %= range;
		new += ntohl(min);
		new = htonl(new);
		break;
	    }
	default :
		ipf_nat_stats.ns_side[fin->fin_out].ns_badnextaddr++;
		return -1;
	}

	*dst = new;

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    nat_nextaddrinit                                            */
/* Returns:     int - 0 == success, else error number                       */
/* Parameters:  na(I)      - NAT address information for generating new addr*/
/*              initial(I) - flag indicating if it is the first call for    */
/*                           this "na" structure.                           */
/*              ifp(I)     - network interface to derive address            */
/*                           information from.                              */
/*                                                                          */
/* This function is expected to be called in two scenarious: when a new NAT */
/* rule is loaded into the kernel and when the list of NAT rules is sync'd  */
/* up with the valid network interfaces (possibly due to them changing.)    */
/* To distinguish between these, the "initial" parameter is used.  If it is */
/* 1 then this indicates the rule has just been reloaded and 0 for when we  */
/* are updating information.  This difference is important because in       */
/* instances where we are not updating address information associated with  */
/* a network interface, we don't want to disturb what the "next" address to */
/* come out of ipf_nat_nextaddr() will be.                                  */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_nextaddrinit(na, initial, ifp)
	nat_addr_t *na;
	int initial;
	void *ifp;
{
	switch (na->na_atype)
	{
#ifdef	IPFILTER_LOOKUP
	case FRI_LOOKUP :
		if (na->na_ptr == NULL) {
			na->na_ptr = ipf_resolvelookup(IPL_LOGNAT,
						      na->na_type,
						      na->na_num,
						      &na->na_func);
		}
		if (na->na_ptr == NULL) {
			ipf_interror = 60056;
			return ESRCH;
		}
		break;
#endif
	case FRI_DYNAMIC :
	case FRI_BROADCAST :
	case FRI_NETWORK :
	case FRI_NETMASKED :
	case FRI_PEERADDR :
		if (ifp != NULL)
			(void )ipf_ifpaddr(4, na->na_atype, ifp,
					  &na->na_addr[0], &na->na_addr[1]);
		break;

	case FRI_SPLIT :
	case FRI_RANGE :
		if (initial)
			na->na_nextip = ntohl(na->na_addr[0].in4.s_addr);
		break;

	case FRI_NONE :
		na->na_addr[0].in4.s_addr &= na->na_addr[1].in4.s_addr;
		return 0;

	case FRI_NORMAL :
		na->na_addr[0].in4.s_addr &= na->na_addr[1].in4.s_addr;
		break;

	default :
		ipf_interror = 60054;
		return EINVAL;
	}

	if (initial && (na->na_atype == FRI_NORMAL)) {
		if (na->na_addr[0].in4.s_addr == 0) {
			if ((na->na_addr[1].in4.s_addr == 0xffffffff) ||
			    (na->na_addr[1].in4.s_addr == 0)) {
				return 0;
			}
		}

		if (na->na_addr[1].in4.s_addr == 0xffffffff) {
			na->na_nextip = ntohl(na->na_addr[0].in4.s_addr);
		} else {
			na->na_nextip = ntohl(na->na_addr[0].in4.s_addr) + 1;
		}
	}

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    nat_encapok                                                 */
/* Returns:     int - -1 == MTU not big enough, 0 == ok to send packet      */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              nat(I) - pointer to current NAT session                     */
/*                                                                          */
/* The purpose of this function is to determine whether or not a packet can */
/* be sent out of a network interface after it has been encapsulated, before*/
/* the actual encapsulation happens.  If it cannot - because the "Don't     */
/* fragment" bit has been set - then generate an ICMP error message back to */
/* the origin of the packet, informing it that the packet is too big and    */
/* what the actual MTU out for the connection is.                           */
/*                                                                          */
/* At present the only question this would leave for strange behaviour is   */
/* with local connections that will go out an encapsulation as sending of   */
/* ICMP messages to local destinations isn't considered robust.             */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_encapok(fin, nat)
	fr_info_t *fin;
	nat_t *nat;
{
	void *sifp;
	ipnat_t *n;
	int extra;
	int mtu;

	if (!(fin->fin_ip->ip_off & htons(IP_DF)))
		return 0;

	n = nat->nat_ptr;

	if (n->in_redir & NAT_ENCAP) {
		extra = sizeof(ip_t);

	} else {
		return 0;
	}

	mtu = GETIFMTU(nat->nat_ifps[1]);

	if (fin->fin_plen + extra < mtu)
		return 0;

	sifp = fin->fin_ifp;
	fin->fin_ifp = NULL;
	fin->fin_icode = ICMP_UNREACH_NEEDFRAG;
	fin->fin_mtu = mtu - extra;

	(void) ipf_send_icmp_err(ICMP_UNREACH, fin, 1);

	fin->fin_mtu = 0;

	return -1;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_rebuildencapicmp                                    */
/* Returns:     int - -1 == error, 0 == success                             */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              nat(I) - pointer to current NAT session                     */
/*                                                                          */
/* For ICMP replies received in response to packets we've encapsulated on   */
/* the way out, we need to replace all of the addressing fields found in    */
/* the data section of the ICMP header.  The ICMP packet is going to        */
/* contain the the IP packet we sent out (IPENCAP) plus at least 64 bits of */
/* the original IP packet - not something that will be of use to the origin */
/* of the offending packet.                                                 */
/* ------------------------------------------------------------------------ */
static nat_t *
ipf_nat_rebuildencapicmp(fin, nat)
	fr_info_t *fin;
	nat_t *nat;
{
	icmphdr_t *icmp;
	udphdr_t *udp;
	ip_t *oip;
	int p;

	icmp = fin->fin_dp;
	oip = (ip_t *)&icmp->icmp_ip;

	if (fin->fin_out == 0) {
		if (nat->nat_dir == NAT_ENCAPIN) {
			oip->ip_src = nat->nat_odstip;
			oip->ip_dst = nat->nat_osrcip;
		} else {
			oip->ip_src = nat->nat_osrcip;
			oip->ip_dst = nat->nat_odstip;
		}
	} else {
		if (nat->nat_dir == NAT_ENCAPIN) {
			oip->ip_src = nat->nat_osrcip;
			oip->ip_dst = nat->nat_odstip;
		} else {
			oip->ip_src = nat->nat_odstip;
			oip->ip_dst = nat->nat_osrcip;
		}
	}

	udp = (udphdr_t *)(oip + 1);

	/*
	 * We use nat_p here because the original UDP header is quite likely
	 * to have been lost - the error packet returned contains the outer
	 * encapsulation header plus 64 bits of the inner IP header, no room
	 * for a UDP or TCP header unless extra data is returned.
	 *
	 * XXX - If the entire original packet has been included (possible)
	 *       then we should be just stripping off the outer encapsulation.
	 *       This is a "todo" for the near future.
	 */
	p = nat->nat_pr[1 - fin->fin_out];

	switch (p)
	{
	case IPPROTO_UDP :
		udp->uh_sum = 0;
		break;
	case IPPROTO_TCP :
		/*
		 * NAT doesn't track the sequence number so we can't pretend
		 * to know what value this field should carry.
		 */
		((tcphdr_t *)udp)->th_seq = 0;
		break;
	default :
		break;
	}

	if (p == IPPROTO_TCP || p == IPPROTO_UDP) {
		if (fin->fin_out == 0) {
			if (nat->nat_dir == NAT_ENCAPIN) {
				udp->uh_sport = nat->nat_odport;
				udp->uh_dport = nat->nat_osport;
			} else {
				udp->uh_sport = nat->nat_osport;
				udp->uh_dport = nat->nat_odport;
			}
		} else {
			if (nat->nat_dir == NAT_ENCAPIN) {
				udp->uh_sport = nat->nat_osport;
				udp->uh_dport = nat->nat_odport;
			} else {
				udp->uh_sport = nat->nat_odport;
				udp->uh_dport = nat->nat_osport;
			}
		}
	}

	/* TRACE (fin,oip,udp,icmp) */
	oip->ip_p = nat->nat_pr[1 - fin->fin_out];
	oip->ip_sum = 0;
	oip->ip_sum = ipf_cksum((u_short *)oip, sizeof(*oip));

	/*
	 * Reduce the next MTU setting by the size of the encap header
	 */
	if (icmp->icmp_type == ICMP_UNREACH &&
	    icmp->icmp_code == ICMP_UNREACH_NEEDFRAG) {
		icmp->icmp_nextmtu = ntohs(icmp->icmp_nextmtu);
		icmp->icmp_nextmtu -= 20;
		icmp->icmp_nextmtu = htons(icmp->icmp_nextmtu);
	}

	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = ipf_cksum((u_short *)icmp, fin->fin_dlen);

	/* TRACE (fin,oip,udp,icmp) */

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_matchflush                                          */
/* Returns:     int - -1 == error, 0 == success                             */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              nat(I) - pointer to current NAT session                     */
/*                                                                          */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_matchflush(data)
	caddr_t data;
{
	int *array, flushed, error;
	nat_t *nat, *natnext;
	ipfobj_t obj;

	error = ipf_matcharray_load(data, &obj, &array);
	if (error != 0)
		return error;

	flushed = 0;

	for (nat = ipf_nat_instances; nat != NULL; nat = natnext) {
		natnext = nat->nat_next;
		if (ipf_nat_matcharray(nat, array) == 0) {
			ipf_nat_delete(nat, NL_FLUSH);
			flushed++;
		}
	}

	obj.ipfo_retval = flushed;
	error = BCOPYOUT(&obj, data, sizeof(obj));

	KFREES(array, array[0] * sizeof(*array));

	return error;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_matcharray                                          */
/* Returns:     int - -1 == error, 0 == success                             */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              nat(I) - pointer to current NAT session                     */
/*                                                                          */
/* ------------------------------------------------------------------------ */
static int
ipf_nat_matcharray(nat, array)
	nat_t *nat;
	int *array;
{
	int i, n, *x, e, p;

	e = 0;
	n = array[0];
	x = array + 1;

	for (; n > 0; x += 3 + x[2]) {
		if (x[0] == IPF_EXP_END)
			break;
		e = 0;

		n -= x[2] + 3;
		if (n < 0)
			break;

		p = x[0] >> 16;
		if (p != 0 && p != nat->nat_pr[1])
			break;

		switch (x[0])
		{
		case IPF_EXP_IP_PR :
			for (i = 0; !e && i < x[2]; i++) {
				e |= (nat->nat_pr[1] == x[i + 3]);
			}
			break;

		case IPF_EXP_IP_SRCADDR :
			if (nat->nat_v != 4)
				break;
			for (i = 0; !e && i < x[2]; i++) {
				e |= ((nat->nat_nsrcaddr & x[i + 4]) ==
				      x[i + 3]);
			}
			break;

		case IPF_EXP_IP_DSTADDR :
			if (nat->nat_v != 4)
				break;
			for (i = 0; !e && i < x[2]; i++) {
				e |= ((nat->nat_ndstaddr & x[i + 4]) ==
				      x[i + 3]);
			}
			break;

		case IPF_EXP_IP_ADDR :
			if (nat->nat_v != 4)
				break;
			for (i = 0; !e && i < x[2]; i++) {
				e |= ((nat->nat_nsrcaddr & x[i + 4]) ==
				      x[i + 3]) ||
				     ((nat->nat_ndstaddr & x[i + 4]) ==
				      x[i + 3]);
			}
			break;

		case IPF_EXP_IP6_SRCADDR :
			if (nat->nat_v != 6)
				break;
			for (i = 0; !e && i < x[3]; i++) {
				e |= IP6_MASKEQ(&nat->nat_nsrc6, x + i + 7,
						x + i + 3);
			}
			break;

		case IPF_EXP_IP6_DSTADDR :
			if (nat->nat_v != 6)
				break;
			for (i = 0; !e && i < x[3]; i++) {
				e |= IP6_MASKEQ(&nat->nat_ndst6, x + i + 7,
						x + i + 3);
			}
			break;

		case IPF_EXP_IP6_ADDR :
			if (nat->nat_v != 6)
				break;
			for (i = 0; !e && i < x[3]; i++) {
				e |= IP6_MASKEQ(&nat->nat_nsrc6, x + i + 7,
						x + i + 3) ||
				     IP6_MASKEQ(&nat->nat_ndst6, x + i + 7,
						x + i + 3);
			}
			break;

		case IPF_EXP_UDP_PORT :
		case IPF_EXP_TCP_PORT :
			for (i = 0; !e && i < x[2]; i++) {
				e |= (nat->nat_nsport == x[i + 3]) ||
				     (nat->nat_ndport == x[i + 3]);
			}
			break;

		case IPF_EXP_UDP_SPORT :
		case IPF_EXP_TCP_SPORT :
			for (i = 0; !e && i < x[2]; i++) {
				e |= (nat->nat_nsport == x[i + 3]);
			}
			break;

		case IPF_EXP_UDP_DPORT :
		case IPF_EXP_TCP_DPORT :
			for (i = 0; !e && i < x[2]; i++) {
				e |= (nat->nat_ndport == x[i + 3]);
			}
			break;

		case IPF_EXP_TCP_STATE :
			for (i = 0; !e && i < x[2]; i++) {
				e |= (nat->nat_tcpstate[0] == x[i + 3]) ||
				     (nat->nat_tcpstate[1] == x[i + 3]);
			}
			break;

		case IPF_EXP_IDLE_GT :
			e |= (ipf_ticks - nat->nat_touched > x[3]);
			break;
		}
		e ^= x[1];

		if (!e)
			break;
	}

	return e;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nat_gettable                                            */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  data(I) - pointer to ioctl data                             */
/*                                                                          */
/* This function handles ioctl requests for tables of nat information.      */
/* At present the only table it deals with is the hash bucket statistics.   */
/* ------------------------------------------------------------------------ */
static int ipf_nat_gettable(data)
	char *data;
{
	ipftable_t table;
	int error;

	error = ipf_inobj(data, &table, IPFOBJ_GTABLE);
	if (error != 0)
		return error;

	switch (table.ita_type)
	{
	case IPFTABLE_BUCKETS_NATIN :
		error = COPYOUT(ipf_nat_stats.ns_side[0].ns_bucketlen,
				table.ita_table,
				ipf_nat_table_sz * sizeof(u_long));
		break;

	case IPFTABLE_BUCKETS_NATOUT :
		error = COPYOUT(ipf_nat_stats.ns_side[1].ns_bucketlen,
				table.ita_table,
				ipf_nat_table_sz * sizeof(u_long));
		break;

	default :
		ipf_interror = 60058;
		return EINVAL;
	}

	if (error != 0) {
		ipf_interror = 60059;
		error = EFAULT;
	}
	return error;
}
