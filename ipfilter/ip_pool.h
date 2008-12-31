/*
 * Copyright (C) 1993-2001, 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#ifndef	__IP_POOL_H__
#define	__IP_POOL_H__

#include "radix_ipf.h"
#include "netinet/ip_lookup.h"

#define	IP_POOL_NOMATCH		0
#define	IP_POOL_POSITIVE	1

#if defined(_RADIX_IPF_H_)

typedef	struct ip_pool_node {
	struct	ipf_radix_node	ipn_nodes[2];
	addrfamily_t		ipn_addr;
	addrfamily_t		ipn_mask;
	int			ipn_info;
	int			ipn_ref;
	char			ipn_name[FR_GROUPLEN];
	u_long			ipn_hits;
	u_long			ipn_die;
	struct ip_pool_node	*ipn_next, **ipn_pnext;
	struct ip_pool_node	*ipn_dnext, **ipn_pdnext;
	struct ip_pool_s	*ipn_owner;
} ip_pool_node_t;


typedef	struct ip_pool_s {
	struct ip_pool_s	*ipo_next;
	struct ip_pool_s	**ipo_pnext;
	struct ipf_radix_node_head	*ipo_head;
	ip_pool_node_t		*ipo_list;
	ip_pool_node_t		*ipo_nextaddr;
	void			*ipo_radix;
	u_long			ipo_hits;
	int			ipo_unit;
	int			ipo_flags;
	int			ipo_ref;
	char			ipo_name[FR_GROUPLEN];
} ip_pool_t;

#define	IPOOL_DELETE	0x01
#define	IPOOL_ANON	0x02


typedef	struct	ipf_pool_stat	{
	u_long			ipls_pools;
	u_long			ipls_tables;
	u_long			ipls_nodes;
	ip_pool_t		*ipls_list[IPL_LOGSIZE];
} ipf_pool_stat_t;

#endif /* _RADIX_IPF_H_ */

extern	ipf_lookup_t	ipf_pool_backend;

#ifndef _KERNEL
extern	void	ipf_pool_dump __P((ipf_main_softc_t *, void *));
#endif

#endif /* __IP_POOL_H__ */
