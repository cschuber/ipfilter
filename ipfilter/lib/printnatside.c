/*
 * Copyright (C) 2007 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */
#include "ipf.h"

void
printnatside(side, nsp, ns)
	char *side;
	natstat_t *nsp;
	nat_stat_side_t *ns;
{
	printf("%lu\tproxy fail %s\n", ns->ns_appr_fail, side);
	printf("%lu\tbad nat %s\n", ns->ns_badnat, side);
	printf("%lu\tbad nat new %s\n", ns->ns_badnatnew, side);
	printf("%lu\tbad next addr %s\n", ns->ns_badnextaddr, side);
	printf("%lu\tbucket max %s\n", ns->ns_bucket_max, side);
	printf("%lu\tclone nomem %s\n", ns->ns_clone_nomem, side);
	printf("%lu\tdecap bad %s\n", ns->ns_decap_bad, side);
	printf("%lu\tdecap fail %s\n", ns->ns_decap_fail, side);
	printf("%lu\tdecap pullup %s\n", ns->ns_decap_pullup, side);
	printf("%lu\tdivert dup %s\n", ns->ns_divert_dup, side);
	printf("%lu\tdivert exist %s\n", ns->ns_divert_exist, side);
	printf("%lu\tdrop %s\n", ns->ns_drop, side);
	printf("%lu\tencap dup %s\n", ns->ns_encap_dup, side);
	printf("%lu\tencap pullup %s\n", ns->ns_encap_pullup, side);
	printf("%lu\texhausted %s\n", ns->ns_exhausted, side);
	printf("%lu\ticmp address %s\n", ns->ns_icmp_address, side);
	printf("%lu\ticmp basic %s\n", ns->ns_icmp_basic, side);
	printf("%u\tinuse %s\n", ns->ns_inuse, side);
	printf("%lu\ticmp mbuf wrong size %s\n", ns->ns_icmp_mbuf, side);
	printf("%lu\ticmp header unmatched %s\n", ns->ns_icmp_notfound, side);
	printf("%lu\ticmp rebuild failures %s\n", ns->ns_icmp_rebuild, side);
	printf("%lu\ticmp short %s\n", ns->ns_icmp_short, side);
	printf("%lu\ticmp packet size wrong %s\n", ns->ns_icmp_size, side);
	printf("%lu\tIFP address fetch failures %s\n",
		ns->ns_ifpaddrfail, side);
	printf("%lu\tpackets untranslated %s\n", ns->ns_ignored, side);
	printf("%lu\tNAT insert failures %s\n", ns->ns_insert_fail, side);
	printf("%lu\tNAT lookup misses %s\n", ns->ns_lookup_miss, side);
	printf("%lu\tNAT lookup nowild %s\n", ns->ns_lookup_nowild, side);
	printf("%lu\tnew ifpaddr failed %s\n", ns->ns_new_ifpaddr, side);
	printf("%lu\tmemory requests failed %s\n", ns->ns_memfail, side);
	printf("%lu\ttable max reached %s\n", ns->ns_table_max, side);
	printf("%lu\tpackets translated %s\n", ns->ns_translated, side);
	printf("%lu\tfinalised failed %s\n", ns->ns_unfinalised, side);
	printf("%lu\tsearch wraps %s\n", ns->ns_wrap, side);
	printf("%lu\tnull translations %s\n", ns->ns_xlate_null, side);
	printf("%lu\ttranslation exists %s\n", ns->ns_xlate_exists, side);
	printf("%lu\tno memory %s\n", ns->ns_memfail, side);

	if (opts & OPT_VERBOSE)
		printf("%p table %s\n", ns->ns_table, side);
}
