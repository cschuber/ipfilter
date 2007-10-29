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


void
npf_ipf_setv6mask(i6addr_t *addr, i6addr_t *mask, int masklen)
{

	if (masklen >= 96) {
		mask->i6[0] = 0xffffffff;
		mask->i6[1] = 0xffffffff;
		mask->i6[2] = 0xffffffff;
		mask->i6[3] = 0xffffffff << (32 - (masklen - 96));
		addr->i6[3] &= mask->i6[3];
	} else if (masklen >= 64) {
		mask->i6[0] = 0xffffffff;
		mask->i6[1] = 0xffffffff;
		mask->i6[2] = 0xffffffff << (32 - (masklen - 64));
		mask->i6[3] = 0;
		addr->i6[2] &= mask->i6[2];
		addr->i6[3] = 0;
	} else if (masklen >= 32) {
		mask->i6[0] = 0xffffffff;
		mask->i6[1] = 0xffffffff << (32 - (masklen - 32));
		mask->i6[2] = 0;
		mask->i6[3] = 0;
		addr->i6[1] &= mask->i6[1];
		addr->i6[2] = 0;
		addr->i6[3] = 0;
	} else {
		mask->i6[0] = 0xffffffff << (32 - masklen);
		mask->i6[1] = 0;
		mask->i6[2] = 0;
		mask->i6[3] = 0;
		addr->i6[0] &= mask->i6[0];
		addr->i6[1] = 0;
		addr->i6[2] = 0;
		addr->i6[3] = 0;
	}
}
