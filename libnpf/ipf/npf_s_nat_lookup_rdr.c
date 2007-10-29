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
#include <npf.h>
#include "npf_ipf.h"
#include <netinet/ip_nat.h>

static char rcsid[] = "$Id$";

int
npf_s_nat_lookup_rdr(npf_handle_t *handle, void *param, const char *options)
{
	npf_nat_desc_t *npfn = param;
	struct sockaddr_in *sin;
	natlookup_t nl;
	ipfobj_t obj;
	npf_ipf_t *ipf;

	if (npfn->npfn_inout != 0)
		return (-1);

	switch (npfn->npfn_inprotocol)
	{
	case IPPROTO_TCP :
		nl.nl_flags |= IPN_TCP;
		break;
	case IPPROTO_UDP :
		nl.nl_flags |= IPN_UDP;
		break;
	default :
		break;
	}

	sin = (struct sockaddr_in *)&npfn->npfn_external_src;
	if (sin->sin_family != AF_INET)
		return (-1);
	nl.nl_outip = sin->sin_addr;

	sin = (struct sockaddr_in *)&npfn->npfn_external_dst;
	if (sin->sin_family != AF_INET)
		return (-1);

	nl.nl_inip = sin->sin_addr;

	if ((nl.nl_flags & (IPN_UDP|IPN_TCP)) != 0) {
		sin = (struct sockaddr_in *)&npfn->npfn_external_src;
		nl.nl_outport = sin->sin_port;
		sin = (struct sockaddr_in *)&npfn->npfn_external_dst;
		nl.nl_inport = sin->sin_port;
	}

	obj.ipfo_rev = IPFILTER_VERSION;
	obj.ipfo_size = sizeof(nl);
	obj.ipfo_ptr = &nl;
	obj.ipfo_offset = 0;
	obj.ipfo_type = IPFOBJ_NATLOOKUP;

	ipf = npf_get_private(handle);

	if (ioctl(ipf->npfi_natfd, SIOCGNATL, &obj) == 0) {
		sin = (struct sockaddr_in *)&npfn->npfn_internal_dst;
		sin->sin_family = AF_INET;
		sin->sin_addr = nl.nl_realip;
		if ((nl.nl_flags & (IPN_UDP|IPN_TCP)) != 0) {
			sin->sin_port = nl.nl_realport;
		}
		return (0);
	}
	return (-1);
}
