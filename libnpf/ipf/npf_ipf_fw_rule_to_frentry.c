/*
 * Copyright (c) 2007
 *      Darren Reed.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright    
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
#include <string.h>
#include <npf.h>
#include "npf_ipf.h"

static char rcsid[] = "$Id$";

int
npf_ipf_fw_rule_to_frentry(npf_filter_rule_t *nf, frentry_t *fr)
{

	/*
	 * Make sure the address families line up.
	 */
	if (nf->nfr_src.nra_addr.ss_family == AF_INET) {
		fr->fr_v = 4;
		if (nf->nfr_dst.nra_addr.ss_family != AF_INET &&
		    nf->nfr_dst.nra_addr.ss_family != AF_UNSPEC)
			return (-1);
	} else if (nf->nfr_src.nra_addr.ss_family == AF_INET6) {
		fr->fr_v = 6;
		if (nf->nfr_dst.nra_addr.ss_family != AF_INET6 &&
		    nf->nfr_dst.nra_addr.ss_family != AF_UNSPEC)
			return (-1);
	} else if (nf->nfr_dst.nra_addr.ss_family == AF_INET) {
		fr->fr_v = 4;
		if (nf->nfr_src.nra_addr.ss_family != AF_INET &&
		    nf->nfr_src.nra_addr.ss_family != AF_UNSPEC)
			return (-1);
	} else if (nf->nfr_dst.nra_addr.ss_family == AF_INET6) {
		fr->fr_v = 6;
		if (nf->nfr_src.nra_addr.ss_family != AF_INET6 &&
		    nf->nfr_src.nra_addr.ss_family != AF_UNSPEC)
			return (-1);
	}

	switch (nf->nfr_action)
	{
	case NPF_ALLOW :
		fr->fr_flags = FR_PASS;
		break;
	case NPF_BLOCK :
		fr->fr_flags = FR_BLOCK;
		break;
	case NPF_BLOCK_RETURN_UNREACH :
		fr->fr_flags = FR_BLOCK|FR_RETICMP;
		break;
	case NPF_BLOCK_RETURN_REFUSE :
		fr->fr_flags = FR_BLOCK|FR_RETRST;
		break;
	}
	fr->fr_flags |= FR_QUICK;

	/*
	 * The default is for rules to include "keep state" for the protocols
	 * that we know something about.
	 */
	fr->fr_proto = nf->nfr_protocol;
	switch (fr->fr_proto)
	{
	case IPPROTO_TCP :
		/*
		 * By default make the rule such that it matches up with SYN
		 * packets only because keep state works best that way.
		 */
		fr->fr_tcpf = TH_SYN;
		fr->fr_tcpfm = TH_SYN|TH_ACK|TH_URG|TH_PUSH|TH_FIN;
		fr->fr_flags |= FR_KEEPSTATE;
		break;
	case IPPROTO_ICMP :
		fr->fr_flags |= FR_KEEPSTATE;
	case IPPROTO_UDP :
		fr->fr_flags |= FR_KEEPSTATE;
		break;
	default :
		break;
	}

	if (nf->nfr_inout == 1)
		fr->fr_flags |= FR_OUTQUE;
	else
		fr->fr_flags |= FR_INQUE;

	strncpy(fr->fr_group, nf->nfr_group, sizeof(fr->fr_group));
	fr->fr_group[FR_GROUPLEN - 1] = '\0';

	strncpy(fr->fr_ifnames[0], nf->nfr_ifname, LIFNAMSIZ);
	fr->fr_ifnames[0][LIFNAMSIZ - 1] = '\0';

	strncpy(fr->fr_ifnames[1], nf->nfr_ifname, LIFNAMSIZ);
	fr->fr_ifnames[1][LIFNAMSIZ - 1] = '\0';

	if (fr->fr_v == 4) {
		struct sockaddr_in *sin;

		if (nf->nfr_src.nra_mask < 0 || nf->nfr_src.nra_mask > 32)
			return (-1);
		fr->fr_smask = 0xffffffff << (32 - nf->nfr_src.nra_mask);

		if (nf->nfr_dst.nra_mask < 0 || nf->nfr_dst.nra_mask > 32)
			return (-1);
		fr->fr_dmask = 0xffffffff << (32 - nf->nfr_dst.nra_mask);

		sin = &nf->nfr_src.nra_ipv4;
		if (sin->sin_family == AF_INET)
			fr->fr_saddr = sin->sin_addr.s_addr & fr->fr_smask;

		sin = &nf->nfr_dst.nra_ipv4;
		if (sin->sin_family == AF_INET)
			fr->fr_daddr = sin->sin_addr.s_addr & fr->fr_dmask;

	} else if (fr->fr_v == 6) {
		struct sockaddr_in6 *sin6;

		if (nf->nfr_src.nra_mask < 0 || nf->nfr_src.nra_mask > 128)
			return (-1);

		if (nf->nfr_dst.nra_mask < 0 || nf->nfr_dst.nra_mask > 128)
			return (-1);

		sin6 = &nf->nfr_src.nra_ipv6;
		if (sin6->sin6_family == AF_INET6)
			fr->fr_ip.fi_src.in6 = sin6->sin6_addr;
		npf_ipf_setv6mask(&fr->fr_ip.fi_src, &fr->fr_mip.fi_src,
				  nf->nfr_src.nra_mask);

		sin6 = &nf->nfr_dst.nra_ipv6;
		if (sin6->sin6_family == AF_INET6)
			fr->fr_ip.fi_dst.in6 = sin6->sin6_addr;
		npf_ipf_setv6mask(&fr->fr_ip.fi_dst, &fr->fr_mip.fi_dst,
				  nf->nfr_dst.nra_mask);
	}
	return (0);
}
