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

static char rcsid[] = "$Id$";

int
npf_s_fw_insert_rule(npf_handle_t *handle, void *param, const char *options)
{
	npf_filter_rule_t *nf = param;
	ipfobj_t obj;
	frentry_t fr;
	fripf_t ipfdata;
	npf_ipf_t *ipf;

	bzero((char *)&fr, sizeof(fr));
	bzero((char *)&ipf, sizeof(ipf));

	fr.fr_ipf = &ipfdata;
	fr.fr_type = FR_T_IPF;
	fr.fr_dsize = sizeof(ipf);

	if (npf_ipf_fw_desc_to_frentry(fr, &fr) == -1)
		return (-1);

	obj.ipfo_rev = IPFILTER_VERSION;
	obj.ipfo_type = IPFOBJ_FRENTRY;
	obj.ipfo_size = sizeof(fr);
	obj.ipfo_ptr = &fr;
	obj.ipfo_offset = 0;

	ipf = npf_get_private(handle);
	if (ioctl(ipf->npfi_fd, SIOCADAFR, &obj) == 0)
		return (0);
	return (-1);
}
