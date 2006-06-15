/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include "ipf.h"


/*
 * returns -1 if neither "hostmask/num" or "hostmask mask addr" are
 * found in the line segments, there is an error processing this information,
 * or there is an error processing ports information.
 */
int	hostmask(family, seg, ifname, sa, msk, linenum)
int	family;
char	***seg, *ifname;
u_32_t	*sa, *msk;
int	linenum;
{
	struct in_addr maskaddr;
	char *s;

	if ((s = strchr(**seg, '='))) {
		*s++ = '\0';
		if (!strcmp(**seg, "pool")) {
			*sa = atoi(s);
			return 1;
		}
	}

	/*
	 * is it possibly hostname/num ?
	 */
	if ((s = strchr(**seg, '/')) ||
	    ((s = strchr(**seg, ':')) && !strchr(s + 1, ':'))) {
		*s++ ='\0';
		if (genmask(family, s, msk) == -1) {
			fprintf(stderr, "%d: bad mask (%s)\n", linenum, s);
			return -1;
		}
		if (hostnum(sa, **seg, linenum, ifname) == -1) {
			fprintf(stderr, "%d: bad host (%s)\n", linenum, **seg);
			return -1;
		}
		*sa &= *msk;
		(*seg)++;
		return 0;
	}

	/*
	 * look for extra segments if "mask" found in right spot
	 */
	if (*(*seg+1) && *(*seg+2) && !strcasecmp(*(*seg+1), "mask")) {
		if (hostnum(sa, **seg, linenum, ifname) == -1) {
			fprintf(stderr, "%d: bad host (%s)\n", linenum, **seg);
			return -1;
		}
		(*seg)++;
		(*seg)++;
		if (inet_aton(**seg, &maskaddr) == 0) {
			fprintf(stderr, "%d: bad mask (%s)\n", linenum, **seg);
			return -1;
		}
		*msk = maskaddr.s_addr;
		(*seg)++;
		*sa &= *msk;
		return 0;
	}

	if (**seg) {
		u_32_t k;

		if (hostnum(sa, **seg, linenum, ifname) == -1) {
			fprintf(stderr, "%d: bad host (%s)\n", linenum, **seg);
			return -1;
		}
		(*seg)++;
		k = *sa ? 0xffffffff : 0;
		if (family == AF_INET6) {
			msk[1] = k;
			msk[2] = k;
			msk[3] = k;
		}
		*msk = k;
		return 0;
	}
	fprintf(stderr, "%d: bad host (%s)\n", linenum, **seg);
	return -1;
}
