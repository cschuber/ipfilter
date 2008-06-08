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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>

NPF_RCSID(rcsid,"$Id$");

static npf_func_t findfunc(void *lib, char *name);

npf_handle_t *
npf_open(const char *name, const npf_version_t version)
{
	npf_handle_t *npf;
	int libnamesiz;
	const char *fwname;
	char *libname;

	if (name == NULL) {
		fwname = getenv("NPF_DEFAULT");
		if (fwname == NULL)
			fwname = NPF_DEFAULT;
	} else {
		fwname = name;
	}

	libnamesiz = 7 + strlen(fwname) + 3 + 1;
	libname = malloc(libnamesiz);
	if (libname == NULL)
		return (NULL);
	snprintf(libname, libnamesiz, "libnpf_%s.so", fwname);

	npf = calloc(1, sizeof(*npf));
	if (npf == NULL) {
		free(libname);
		return (NULL);
	}

	npf->libname = libname;

	npf->lib = dlopen(libname, RTLD_NOW);
	if (npf->lib == NULL) {
		free(libname);
		free(npf);
		return (NULL);
	}

	npf->init_lib = (npf_func_t)dlfunc(npf->lib, "npf_s_init_lib");
	npf->fini_lib = (npf_func_t)dlfunc(npf->lib, "npf_s_fini_lib");

	if (npf->init_lib != NULL) {
		if (npf->init_lib(npf, NULL, NULL) == -1) {
			dlclose(npf->lib);
			free(npf);
			return (NULL);
		}
	}

	npf->version = version;

	npf->nat_delete_rule = findfunc(npf->lib, "npf_s_nat_delete_rule");
	npf->nat_find_rule = findfunc(npf->lib, "npf_s_nat_find_rule");
	npf->nat_getnext_rule = findfunc(npf->lib, "npf_s_nat_getnext_rule");
	npf->nat_insert_rule = findfunc(npf->lib, "npf_s_nat_insert_rule");
	npf->fw_insert_rule = findfunc(npf->lib, "npf_s_fw_insert_rule");
	npf->fw_delete_rule = findfunc(npf->lib, "npf_s_fw_delete_rule");
	return (npf);
}


static npf_func_t
findfunc(void *lib, char *name)
{
	return ((npf_func_t)dlfunc(lib, name));
}
