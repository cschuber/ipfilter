/*
 * Copyright (C) 1993-2011 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * @(#)ip_frag.h	1.5 3/24/96
 * $Id$
 */

#ifndef	__IP_FRAG_H__
#define	__IP_FRAG_H__

#define	IPFT_SIZE	257

typedef	struct	ipfr	{
	struct	ipfr	*ipfr_hnext, **ipfr_hprev;
	struct	ipfr	*ipfr_next, **ipfr_prev;
	void	*ipfr_data;
	frentry_t *ipfr_rule;
	u_long	ipfr_ttl;
	ipftuneable_t	*ipf_frag_tune;
	u_int	ipfr_pkts;
	u_int	ipfr_bytes;
	u_int	ipfr_badorder;
	int	ipfr_ref;
	u_short	ipfr_off;
	u_short	ipfr_firstend;
	u_char	ipfr_p;
	u_char	ipfr_seen0;
	/*
	 * All of the fields, from ipfr_ifp to ipfr_pass, are compared
	 * using bcmp to see if an identical entry is present.  It is
	 * therefore important for this set to remain together.
	 */
	void	*ipfr_ifp;
	i6addr_t	ipfr_source;
	i6addr_t	ipfr_dest;
	u_32_t	ipfr_optmsk;
	u_short	ipfr_secmsk;
	u_short	ipfr_auth;
	u_32_t	ipfr_id;
	u_32_t	ipfr_pass;
	int	ipfr_v;
} ipfr_t;

#define	ipfr_src	ipfr_source.in4
#define	ipfr_dst	ipfr_dest.in4


typedef	struct	ipfrstat {
	u_long	ifs_exists;	/* add & already exists */
	u_long	ifs_nomem;
	u_long	ifs_new;
	u_long	ifs_hits;
	u_long	ifs_expire;
	u_long	ifs_inuse;
	u_long	ifs_retrans0;
	u_long	ifs_short;
	u_long	ifs_bad;
	u_long	ifs_overlap;
	u_long	ifs_unordered;
	u_long	ifs_strict;
	u_long	ifs_miss;
	u_long	ifs_maximum;
	u_long	ifs_newbad;
	u_long	ifs_newrestrictnot0;
	struct	ipfr	**ifs_table;
	struct	ipfr	**ifs_nattab;
} ipfrstat_t;

#define	IPFR_CMPSZ	(offsetof(ipfr_t, ipfr_pass) - \
			 offsetof(ipfr_t, ipfr_ifp))

extern	void	*ipf_frag_soft_create(ipf_main_softc_t *);
extern	int	ipf_frag_soft_init(ipf_main_softc_t *, void *);
extern	int	ipf_frag_soft_fini(ipf_main_softc_t *, void *);
extern	void	ipf_frag_soft_destroy(ipf_main_softc_t *, void *);
extern	int	ipf_frag_main_load(void);
extern	int	ipf_frag_main_unload(void);
extern	int	ipf_frag_load(void);
extern	void	ipf_frag_clear(ipf_main_softc_t *);
extern	void	ipf_frag_expire(ipf_main_softc_t *);
extern	void	ipf_frag_forget(void *);
extern	int	ipf_frag_init(void);
extern	u_32_t	ipf_frag_ipidknown(fr_info_t *);
extern	int	ipf_frag_ipidnew(fr_info_t *, u_32_t);
extern	frentry_t *ipf_frag_known(fr_info_t *, u_32_t *);
extern	void	ipf_frag_natforget(ipf_main_softc_t *, void *);
extern	int	ipf_frag_natnew(ipf_main_softc_t *, fr_info_t *, u_32_t, struct nat *);
extern	nat_t	*ipf_frag_natknown(fr_info_t *);
extern	int	ipf_frag_new(ipf_main_softc_t *, fr_info_t *, u_32_t);
extern	ipfrstat_t	*ipf_frag_stats(void *);
extern	void	ipf_frag_setlock(void *, int);
extern	void	ipf_frag_pkt_deref(ipf_main_softc_t *, void *);
extern	int	ipf_frag_pkt_next(ipf_main_softc_t *, ipftoken_t *,
				  ipfgeniter_t *);
extern	void	ipf_frag_nat_deref(ipf_main_softc_t *, void *);
extern	int	ipf_frag_nat_next(ipf_main_softc_t *, ipftoken_t *,
				  ipfgeniter_t *);
extern	void	ipf_slowtimer(ipf_main_softc_t *);

#endif	/* __IP_FRAG_H__ */
