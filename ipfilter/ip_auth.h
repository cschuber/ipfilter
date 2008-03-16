/*
 * Copyright (C) 1997-2001 by Darren Reed & Guido Van Rooij.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 *
 */
#ifndef	__IP_AUTH_H__
#define	__IP_AUTH_H__

#define FR_NUMAUTH      32

typedef struct  frauth {
	int	fra_age;
	int	fra_len;
	int	fra_index;
	u_32_t	fra_pass;
	fr_info_t	fra_info;
	char	*fra_buf;
	u_32_t	fra_flx;
#ifdef	MENTAT
	queue_t	*fra_q;
	mb_t	*fra_m;
#endif
} frauth_t;

typedef	struct	frauthent  {
	struct	frentry	fae_fr;
	struct	frauthent	*fae_next;
	struct	frauthent	**fae_pnext;
	u_long	fae_age;
	int	fae_ref;
} frauthent_t;

typedef struct  ipf_authstat {
	U_QUAD_T	fas_hits;
	U_QUAD_T	fas_miss;
	u_long		fas_nospace;
	u_long		fas_added;
	u_long		fas_sendfail;
	u_long		fas_sendok;
	u_long		fas_queok;
	u_long		fas_quefail;
	u_long		fas_expire;
	frauthent_t	*fas_faelist;
} ipf_authstat_t;


extern	frentry_t	*ipf_auth_ip;
extern	ipf_authstat_t	ipf_auth_stats;
extern	int	ipf_auth_defaultage;
extern	int	ipf_auth_start;
extern	int	ipf_auth_end;
extern	int	ipf_auth_size;
extern	int	ipf_auth_used;
extern	int	ipf_auth_lock;
extern	mb_t	**ipf_auth_pkts;

extern	frentry_t *ipf_auth_check __P((fr_info_t *, u_32_t *));
extern	void	ipf_auth_expire __P((void));
extern	int	ipf_auth_flush __P((void));
extern	int	ipf_auth_ioctl __P((caddr_t, ioctlcmd_t, int, int, void *));
extern	int	ipf_auth_init __P((void));
extern	int	ipf_auth_new __P((mb_t *, fr_info_t *));
extern	int	ipf_auth_precmd __P((ioctlcmd_t, frentry_t *, frentry_t **));
extern	void	ipf_auth_unload __P((void));
extern	int	ipf_auth_waiting __P((void));

#endif	/* __IP_AUTH_H__ */
