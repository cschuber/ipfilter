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
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <npf.h>
#include "npf_ipf.h"

#include <netinet/in.h>
#include <netinet/ip_compat.h>
#include <netinet/ip_fil.h>

static char rcsid[] = "$Id$";

int
npf_s_init_lib(npf_handle_t *npf)
{
	npf_ipf_t *ipf;

	ipf = calloc(1, sizeof(*ipf));
	if (ipf == NULL) {
		npf->error = ENOMEM;
		return (-1);
	}

	ipf->npfi_fd = open(IPL_NAME, O_RDWR);
	if (ipf->npfi_fd == -1) {
		free(ipf);
		npf->error = errno;
		return (-1);
	}

	ipf->npfi_natfd = open(IPNAT_NAME, O_RDWR);
	if (ipf->npfi_natfd == -1) {
		close(ipf->npfi_fd);
		free(ipf);
		npf->error = errno;
		return (-1);
	}

	ipf->npfi_poolfd = open(IPLOOKUP_NAME, O_RDWR);
	if (ipf->npfi_poolfd == -1) {
		close(ipf->npfi_natfd);
		close(ipf->npfi_fd);
		free(ipf);
		npf->error = errno;
		return (-1);
	}

	npf_set_private(npf, ipf);
	return (0);
}
