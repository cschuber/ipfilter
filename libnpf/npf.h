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
 * $Id$
 *
 */
#ifndef _NPF_H_
#define _NPF_H_

#include <sys/socket.h>
#include <net/if.h>

#ifndef LIFNAMSIZ
# ifdef IF_NAMESIZE
#  define	LIFNAMSIZ	IF_NAMESIZE
# else
#  ifdef IFNAMSIZ
#   define	LIFNAMSIZ	IFNAMSIZ
#  else
#   define	LIFNAMSIZ	16
#  endif
# endif
#endif

#define	NPF_DEFAULT		"ipf"


typedef struct npf_nat_desc {
	int			npfn_inout;
	int			npfn_inprotocol;
	int			npfn_outprotocol;
	char			npfn_inifname[LIFNAMSIZ];
	char			npfn_outifname[LIFNAMSIZ];
	int			npfn_ext_dstmsk;	/* # of bits to mask */
	int			npfn_ext_srcmsk;	/* # of bits to mask */
	int			npfn_int_dstmsk;	/* # of bits to mask */
	int			npfn_int_srcmsk;	/* # of bits to mask */
	struct sockaddr_storage	npfn_external_src;
	struct sockaddr_storage	npfn_external_dst;
	struct sockaddr_storage	npfn_internal_src;
	struct sockaddr_storage	npfn_internal_dst;
} npf_nat_desc_t;


typedef enum npf_permission_e {
	NPFE_ALLOW = 0,
	NPFE_BLOCK,
	NPFE_BLOCK_RETURN_ICMP,
	NPFE_BLOCK_RETURN_RESET
} npf_permission_t;

#define	NPF_GROUP_NAME_SIZE	64

typedef struct npf_filter_desc {
	npf_permission_t	npff_action;
	int			npff_log;
	int			npff_inout;
	int			npff_protocol;
	int			npff_srcmsk;	/* # of bits to mask */
	int			npff_dstmsk;	/* # of bits to mask */
	struct sockaddr_storage	npff_src;
	struct sockaddr_storage	npff_dst;
	char			npff_ifname[LIFNAMSIZ];
	char			npff_group[NPF_GROUP_NAME_SIZE];
} npf_filter_desc_t;


struct npf_handle;
typedef int (*npf_func_t)(struct npf_handle *, void *, const char *);

typedef struct npf_handle {
	void		*lib;
	char		*libname;
	int		error;
	char		*errstr;
	npf_func_t	init_lib;
	npf_func_t	fini_lib;
	npf_func_t	fw_insert_rule;
	npf_func_t	fw_delete_rule;
	npf_func_t	nat_delete_rule;
	npf_func_t	nat_find_rule;
	npf_func_t	nat_getnext_rule;
	npf_func_t	nat_insert_rule;
	npf_func_t	nat_lookup_rdr;
	void		*private;
} npf_handle_t;

extern npf_handle_t *npf_open(const char *name);
extern int npf_close(npf_handle_t *);
extern void npf_set_private(npf_handle_t *, void *);
extern void *npf_get_private(npf_handle_t *);

extern int npf_fw_delete_rule(npf_handle_t *, npf_filter_desc_t *,
			      const char *);
extern int npf_fw_insert_rule(npf_handle_t *, npf_filter_desc_t *,
			      const char *);

extern int npf_nat_delete_rule(npf_handle_t *, npf_nat_desc_t *, const char *);
extern int npf_nat_find_rule(npf_handle_t *, npf_nat_desc_t *, const char *);
extern int npf_nat_lookup_rdr(npf_handle_t *, npf_nat_desc_t *, const char *);
extern int npf_nat_getnext_rule(npf_handle_t *, npf_nat_desc_t *, const char *);
extern int npf_nat_insert_rule(npf_handle_t *, npf_nat_desc_t *, const char *);


/*
<xml>
<nat>
<rule>
<options desc=string>
<rule>
</nat>
<
</xml>
options=<xml><filter><rule desc=string state=yes quick=yes log=first group=miniupnpd></filter
*/
#endif /* _NPF_H_ */
