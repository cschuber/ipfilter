/*
 * Copyright (C) 2007-2008 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include "ipf.h"

wordtab_t natfields[] = {
	{ "all",	-2 },
	{ "ifp0",	1 },
	{ "ifp1",	2 },
	{ "mtu0",	3 },
	{ "mtu1",	4 },
	{ "ifname0",	5 },
	{ "ifname1",	6 },
	{ "sumd0",	7 },
	{ "sumd1",	8 },
	{ "pkts0",	9 },
	{ "pkts1",	10 },
	{ "bytes0",	11 },
	{ "bytes1",	12 },
	{ "proto0",	13 },
	{ "proto1",	14 },
	{ "hash0",	15 },
	{ "hash1",	16 },
	{ "ref",	17 },
	{ "rev",	18 },
	{ "v0",		19 },
	{ "redir",	20 },
	{ "use",	21 },
	{ "ipsumd",	22 },
	{ "dir",	23 },
	{ "olddstip",	24 },
	{ "oldsrcip",	25 },
	{ "newdstip",	26 },
	{ "newsrcip",	27 },
	{ "olddport",	28 },
	{ "oldsport",	29 },
	{ "newdport",	30 },
	{ "newsport",	31 },
	{ "age",	32 },
	{ "v1",		33 },
	{ NULL, 0 }
};


void printnatfield(n, fieldnum)
	nat_t *n;
	int fieldnum;
{
	int i;

	switch (fieldnum)
	{
	case -2 :
		for (i = 1; natfields[i].w_word != NULL; i++) {
			if (natfields[i].w_value > 0) {
				printnatfield(n, i);
				if (natfields[i + 1].w_value > 0)
					putchar('\t');
			}
		}
		break;

	case 1:
		printf("%#lx", (u_long)n->nat_ifps[0]);
		break;

	case 2:
		printf("%#lx", (u_long)n->nat_ifps[1]);
		break;

	case 3:
		printf("%d", n->nat_mtu[0]);
		break;

	case 4:
		printf("%d", n->nat_mtu[1]);
		break;

	case 5:
		printf("%s", n->nat_ifnames[0]);
		break;

	case 6:
		printf("%s", n->nat_ifnames[1]);
		break;

	case 7:
		printf("%d", n->nat_sumd[0]);
		break;

	case 8:
		printf("%d", n->nat_sumd[1]);
		break;

	case 9:
#ifdef USE_QUAD_T
		printf("%qu", n->nat_pkts[0]);
#else
		printf("%lu", n->nat_pkts[0]);
#endif
		break;

	case 10:
#ifdef USE_QUAD_T
		printf("%qu", n->nat_pkts[1]);
#else
		printf("%lu", n->nat_pkts[1]);
#endif
		break;

	case 11:
#ifdef USE_QUAD_T
		printf("%qu", n->nat_bytes[0]);
#else
		printf("%lu", n->nat_bytes[0]);
#endif
		break;

	case 12:
#ifdef USE_QUAD_T
		printf("%qu", n->nat_bytes[1]);
#else
		printf("%lu", n->nat_bytes[1]);
#endif
		break;

	case 13:
		printf("%d", n->nat_pr[0]);
		break;

	case 14:
		printf("%d", n->nat_pr[1]);
		break;

	case 15:
		printf("%u", n->nat_hv[0]);
		break;

	case 16:
		printf("%u", n->nat_hv[1]);
		break;

	case 17:
		printf("%d", n->nat_ref);
		break;

	case 18:
		printf("%d", n->nat_rev);
		break;

	case 19:
		printf("%d", n->nat_v[0]);
		break;

	case 33:
		printf("%d", n->nat_v[0]);
		break;

	case 20:
		printf("%d", n->nat_redir);
		break;

	case 21:
		printf("%d", n->nat_use);
		break;

	case 22:
		printf("%u", n->nat_ipsumd);
		break;

	case 23:
		printf("%d", n->nat_dir);
		break;

	case 24:
		printf("%s", hostname(n->nat_v[0], &n->nat_odstip));
		break;

	case 25:
		printf("%s", hostname(n->nat_v[0], &n->nat_osrcip));
		break;

	case 26:
		printf("%s", hostname(n->nat_v[1], &n->nat_ndstip));
		break;

	case 27:
		printf("%s", hostname(n->nat_v[1], &n->nat_nsrcip));
		break;

	case 28:
		printf("%hu", ntohs(n->nat_odport));
		break;

	case 29:
		printf("%hu", ntohs(n->nat_osport));
		break;

	case 30:
		printf("%hu", ntohs(n->nat_ndport));
		break;

	case 31:
		printf("%hu", ntohs(n->nat_nsport));
		break;

	case 32:
		printf("%u", n->nat_age);
		break;

	default:
		break;
	}
}
