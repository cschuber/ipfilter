/*
 * Copyright (C) 2002-2005 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Added redirect stuff and a variety of bug fixes. (mcn@EnGarde.com)
 */

#include "ipf.h"
#include "kmem.h"


#if !defined(lint)
static const char rcsid[] = "@(#)$Id$";
#endif


/*
 * Print out a NAT rule
 */
void printnat(np, opts)
	ipnat_t *np;
	int opts;
{
	struct protoent *pr;
	int proto;

	if (np->in_flags & IPN_NO)
		printf("no ");

	switch (np->in_redir)
	{
	case NAT_REDIRECT|NAT_ENCAP :
		printf("encap in on");
		proto = np->in_pr[0];
		break;
	case NAT_MAP|NAT_ENCAP :
		printf("encap out on");
		proto = np->in_pr[1];
		break;
	case NAT_REDIRECT|NAT_DIVERTUDP :
		printf("divert in on");
		proto = np->in_pr[0];
		break;
	case NAT_MAP|NAT_DIVERTUDP :
		printf("divert out on");
		proto = np->in_pr[1];
		break;
	case NAT_REDIRECT|NAT_REWRITE :
		printf("rewrite in on");
		proto = np->in_pr[0];
		break;
	case NAT_MAP|NAT_REWRITE :
		printf("rewrite out on");
		proto = np->in_pr[1];
		break;
	case NAT_REDIRECT :
		printf("rdr");
		proto = np->in_pr[0];
		break;
	case NAT_MAP :
		printf("map");
		proto = np->in_pr[1];
		break;
	case NAT_MAPBLK :
		printf("map-block");
		proto = np->in_pr[1];
		break;
	case NAT_BIMAP :
		printf("bimap");
		proto = np->in_pr[0];
		break;
	default :
		fprintf(stderr, "unknown value for in_redir: %#x\n",
			np->in_redir);
		proto = np->in_pr[0];
		break;
	}

	pr = getprotobynumber(proto);

	if (!strcmp(np->in_ifnames[0], "-"))
		printf(" \"%s\"", np->in_ifnames[0]);
	else
		printf(" %s", np->in_ifnames[0]);
	if ((np->in_ifnames[1][0] != '\0') &&
	    (strncmp(np->in_ifnames[0], np->in_ifnames[1], LIFNAMSIZ) != 0)) {
		if (!strcmp(np->in_ifnames[1], "-"))
			printf(",\"%s\"", np->in_ifnames[1]);
		else
			printf(",%s", np->in_ifnames[1]);
	}
	putchar(' ');

	if (np->in_redir & (NAT_REWRITE|NAT_ENCAP|NAT_DIVERTUDP)) {
		if ((proto != 0) || (np->in_flags & IPN_TCPUDP)) {
			printf("proto ");
			printproto(pr, proto, np);
			putchar(' ');
		}
	}

	if (np->in_flags & IPN_FILTER) {
		if (np->in_flags & IPN_NOTSRC)
			printf("! ");
		printf("from ");
		printnataddr(np->in_v[0], &np->in_osrc, np->in_ifnames[0]);
		if (np->in_scmp)
			printportcmp(proto, &np->in_tuc.ftu_src);

		if (np->in_flags & IPN_NOTDST)
			printf(" !");
		printf(" to ");
		printnataddr(np->in_v[0], &np->in_odst, np->in_ifnames[0]);
		if (np->in_dcmp)
			printportcmp(proto, &np->in_tuc.ftu_dst);
	}

	if (np->in_redir & (NAT_ENCAP|NAT_DIVERTUDP)) {
		printf(" -> src ");
		printnataddr(np->in_v[1], &np->in_nsrc, np->in_ifnames[0]);
		if ((np->in_redir & NAT_DIVERTUDP) != 0)
			printf(",%u", np->in_spmin);
		printf(" dst ");
		printnataddr(np->in_v[1], &np->in_ndst, np->in_ifnames[0]);
		if ((np->in_redir & NAT_DIVERTUDP) != 0)
			printf(",%u udp", np->in_dpmin);
		printf(";\n");

	} else if (np->in_redir & NAT_REWRITE) {
		printf(" -> src ");
		if (np->in_nsrcafunc == NA_RANDOM) {
			printf("random(");
		} else if (np->in_nsrcafunc == NA_HASHMD5) {
			printf("hash-md5(");
		}
		printnataddr(np->in_v[1], &np->in_nsrc, np->in_ifnames[0]);
		if (np->in_nsrcafunc != NA_NORMAL) {
			printf(")");
		}
		if ((((np->in_flags & IPN_TCPUDP) != 0)) &&
		    (np->in_spmin != 0)) {
			if ((np->in_flags & IPN_FIXEDSPORT) != 0) {
				printf(",port = %u", np->in_spmin);
			} else {
				printf(",%u", np->in_spmin);
				if (np->in_spmax != np->in_spmin)
					printf("-%u", np->in_spmax);
			}
		}
		printf(" dst ");
		if (np->in_ndstafunc == NA_RANDOM) {
			printf("random(");
		} else if (np->in_ndstafunc == NA_HASHMD5) {
			printf("hash-md5(");
		}
		printnataddr(np->in_v[1], &np->in_ndst, np->in_ifnames[0]);
		if (np->in_ndstafunc != NA_NORMAL) {
			printf(")");
		}
		if ((((np->in_flags & IPN_TCPUDP) != 0)) &&
		    (np->in_dpmin != 0)) {
			if ((np->in_flags & IPN_FIXEDDPORT) != 0) {
				printf(",port = %u", np->in_dpmin);
			} else {
				printf(",%u", np->in_dpmin);
				if (np->in_dpmax != np->in_dpmin)
					printf("-%u", np->in_dpmax);
			}
		}
		printf(";\n");

	} else if (np->in_redir == NAT_REDIRECT) {
		if (!(np->in_flags & IPN_FILTER)) {
			printnataddr(np->in_v[0], &np->in_odst,
				     np->in_ifnames[0]);
			if (np->in_flags & IPN_TCPUDP) {
				printf(" port %d", np->in_odport);
				if (np->in_odport != np->in_dtop)
					printf("-%d", np->in_dtop);
			}
		}
		if (np->in_flags & IPN_NO) {
			putchar(' ');
			printproto(pr, proto, np);
			printf(";\n");
			return;
		}
		printf(" -> ");
		printnataddr(np->in_v[1], &np->in_ndst, np->in_ifnames[0]);
		if (np->in_flags & IPN_TCPUDP) {
			if ((np->in_flags & IPN_FIXEDDPORT) != 0)
				printf(" port = %d", np->in_dpmin);
			else {
				printf(" port %d", np->in_dpmin);
				if (np->in_dpmin != np->in_dpmax)
					printf("-%d", np->in_dpmax);
			}
		}
		putchar(' ');
		printproto(pr, proto, np);
		if (np->in_flags & IPN_ROUNDR)
			printf(" round-robin");
		if (np->in_flags & IPN_FRAG)
			printf(" frag");
		if (np->in_age[0] != 0 || np->in_age[1] != 0) {
			printf(" age %d/%d", np->in_age[0], np->in_age[1]);
		}
		if (np->in_flags & IPN_STICKY)
			printf(" sticky");
		if (np->in_mssclamp != 0)
			printf(" mssclamp %d", np->in_mssclamp);
		if (*np->in_plabel != '\0')
			printf(" proxy %.*s", (int)sizeof(np->in_plabel),
				np->in_plabel);
		if (np->in_tag.ipt_tag[0] != '\0')
			printf(" tag %-.*s", IPFTAG_LEN, np->in_tag.ipt_tag);
		printf("\n");
		if (opts & OPT_DEBUG)
			printf("\tpmax %u\n", np->in_dpmax);

	} else {
		int protoprinted = 0;

		if (!(np->in_flags & IPN_FILTER)) {
			printnataddr(np->in_v[0], &np->in_osrc,
				     np->in_ifnames[0]);
		}
		if (np->in_flags & IPN_NO) {
			putchar(' ');
			printproto(pr, proto, np);
			printf(";\n");
			return;
		}
		printf(" -> ");
		if (np->in_flags & IPN_SIPRANGE) {
			printf("range ");
			printnataddr(np->in_v[1], &np->in_nsrc,
				     np->in_ifnames[0]);
		} else {
			printnataddr(np->in_v[1], &np->in_nsrc,
				     np->in_ifnames[0]);
		}
		if (*np->in_plabel != '\0') {
			printf(" proxy port ");
			if (np->in_odport != 0) {
				char *s;

				s = portname(proto, np->in_odport);
				if (s != NULL)
					fputs(s, stdout);
				else
					fputs("???", stdout);
			}
			printf(" %.*s/", (int)sizeof(np->in_plabel),
				np->in_plabel);
			printproto(pr, proto, NULL);
			protoprinted = 1;
		} else if (np->in_redir == NAT_MAPBLK) {
			if ((np->in_spmin == 0) &&
			    (np->in_flags & IPN_AUTOPORTMAP))
				printf(" ports auto");
			else
				printf(" ports %d", np->in_spmin);
			if (opts & OPT_DEBUG)
				printf("\n\tip modulous %d", np->in_spmax);

		} else if (np->in_spmin || np->in_spmax) {
			if (np->in_flags & IPN_ICMPQUERY) {
				printf(" icmpidmap ");
			} else {
				printf(" portmap ");
			}
			printproto(pr, proto, np);
			protoprinted = 1;
			if (np->in_flags & IPN_AUTOPORTMAP) {
				printf(" auto");
				if (opts & OPT_DEBUG)
					printf(" [%d:%d %d %d]",
					       np->in_spmin, np->in_spmax,
					       np->in_ippip, np->in_ppip);
			} else {
				printf(" %d:%d", np->in_spmin, np->in_spmax);
			}
		}

		if (np->in_flags & IPN_FRAG)
			printf(" frag");
		if (np->in_age[0] != 0 || np->in_age[1] != 0) {
			printf(" age %d/%d", np->in_age[0], np->in_age[1]);
		}
		if (np->in_mssclamp != 0)
			printf(" mssclamp %d", np->in_mssclamp);
		if (np->in_tag.ipt_tag[0] != '\0')
			printf(" tag %s", np->in_tag.ipt_tag);
		if (!protoprinted && (np->in_flags & IPN_TCPUDP || proto)) {
			putchar(' ');
			printproto(pr, proto, np);
		}
		printf("\n");
		if (opts & OPT_DEBUG) {
			struct in_addr nip;

			nip.s_addr = htonl(np->in_snip);

			printf("\tnextip %s pnext %d\n",
			       inet_ntoa(nip), np->in_spnext);
		}
	}

	if (opts & OPT_DEBUG) {
		printf("\tspace %lu use %u hits %lu flags %#x proto %d/%d",
			np->in_space, np->in_use, np->in_hits,
			np->in_flags, np->in_pr[0], np->in_pr[1]);
		printf(" hv %u/%u\n", np->in_hv[0], np->in_hv[1]);
		printf("\tifp[0] %p ifp[1] %p apr %p\n",
			np->in_ifps[0], np->in_ifps[1], np->in_apr);
		printf("\ttqehead %p/%p comment %p\n",
			np->in_tqehead[0], np->in_tqehead[1], np->in_comment);
	}
}
