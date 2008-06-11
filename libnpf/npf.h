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
#include <netinet/in.h>

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
#define	NPF_GROUP_NAME_SIZE	64
#define	NPF_TABLE_NAME_SIZE	64

/* AF_UNSPEC => sockaddr_storage is a string */

typedef enum npf_version_e {
	NPF_VERSION = 0
} npf_version_t;

typedef enum npf_inout_e {
	NPF_IN = 0,
	NPF_OUT = 1
} npf_inout_t;

typedef enum npf_addr_type_e {
	NPF_ATYPE_ADDR = 0,
	NPF_ATYPE_IF_NAME = 1,
	NPF_ATYPE_TABLE_NAME = 2
} npf_addr_type_t;

typedef union {
	struct sockaddr_storage	na_addr;
	struct sockaddr_in	na_ipv4;
	struct sockaddr_in6	na_ipv6;
} npf_addr_t;

typedef struct npf_rule_addr_s {
	npf_addr_type_t		nra_type;
	int			nra_mask;
	union {
		npf_addr_t	nrau_addr;
		char		nrau_name[NPF_TABLE_NAME_SIZE];
	} nra_un;
} npf_rule_addr_t;

#define	nra_addr		nra_un.nrau_addr.na_addr
#define	nra_ipv4		nra_un.nrau_addr.na_ipv4
#define	nra_ipv6		nra_un.nrau_addr.na_ipv6
#define	nra_table_name		nra_un.nrau_name

typedef enum npf_compare_e {
	NPF_COMP_NONE = 0,
	NPF_COMP_EQ = 1,
	NPF_COMP_NE = 2,
	NPF_COMP_GT = 3,
	NPF_COMP_GE = 4,
	NPF_COMP_LT = 5,
	NPF_COMP_LE = 6,
	NPF_COMP_OUTSIDE = 7,
	NPF_COMP_INSIDE = 8,
	NPF_COMP_RANGE = 9
} npf_compare_t;

typedef struct npf_tcp_filter_rule_s {
	int			ntfr_sport_lo;
	int			ntfr_sport_hi;
	npf_compare_t		ntfr_sport_cmp;
	int			ntfr_dport_lo;
	int			ntfr_dport_hi;
	npf_compare_t		ntfr_dport_cmp;
	int			ntfr_flags;
	int			ntfr_flag_mask;
} npf_tcp_filter_rule_t;

typedef struct npf_udp_filter_rule_s {
	int			nufr_sport_lo;
	int			nufr_sport_hi;
	npf_compare_t		nufr_sport_cmp;
	int			nufr_dport_lo;
	int			nufr_dport_hi;
	npf_compare_t		nufr_dport_cmp;
} npf_udp_filter_rule_t;

typedef struct npf_icmp_filter_rule_s {
	int			nifr_type;
	npf_compare_t		nifr_type_cmp;
	int			nifr_code;
	npf_compare_t		nifr_code_cmp;
} npf_icmp_filter_rule_t;

typedef union {
	npf_tcp_filter_rule_t	n4_tcp;
	npf_udp_filter_rule_t	n4_udp;
	npf_icmp_filter_rule_t	n4_icmp;
} npf_l4hdr_match_t;

typedef enum npf_nat_change_e {
	NPF_NC_NONE = 0,
	NPF_NC_SERIAL = 1,	/* Includes serial space of 1 (fixed) */
	NPF_NC_RANDOM = 2,
	NPF_NC_HASH_SRC = 3,
	NPF_NC_HASH_DST = 4,
	NPF_NC_HASH_SRC_DST = 5,
	NPF_NC_FITTED = 6
} npf_nat_change_t;

/*
 * Needed:
 * - negation matching on fields
 */
typedef struct npf_nat_rule_s {
	npf_inout_t		nnr_inout;
	int			nnr_inprotocol;
	int			nnr_outprotocol;
	int			nnr_tcp_mss;
	char			nnr_inifname[LIFNAMSIZ];
	char			nnr_outifname[LIFNAMSIZ];
	npf_nat_change_t	nnr_dst_change;
	npf_nat_change_t	nnr_src_change;
	npf_rule_addr_t		nnr_ext_dst;
	npf_rule_addr_t		nnr_ext_src;
	npf_rule_addr_t		nnr_int_dst;
	npf_rule_addr_t		nnr_int_src;
	npf_l4hdr_match_t	nnr_l4match;
} npf_nat_rule_t;

typedef struct npf_nat_desc_s {
	npf_inout_t		nnd_inout;
	int			nnd_inprotocol;
	int			nnd_outprotocol;
	npf_addr_t		nnd_ext_dst;
	npf_addr_t		nnd_ext_src;
	npf_addr_t		nnd_int_dst;
	npf_addr_t		nnd_int_src;
} npf_nat_desc_t;

typedef enum npf_permission_e {
	NPF_ALLOW = 0,
	NPF_BLOCK = 1,
	NPF_BLOCK_RETURN_REFUSE = 2,
	NPF_BLOCK_RETURN_UNREACH = 3,
	NPF_COUNT = 4,
	NPF_DIVERT = 5
} npf_permission_t;

typedef enum npf_logaction_e {
	NPFL_NONE = 0,
	NPFL_LOG_ALL = 1,
	NPFL_LOG_FIRST = 2,
	NPFL_LOG_BODY = 4
} npf_logaction_t;

typedef struct npf_destination_s {
	struct sockaddr_storage	npfd_address;
	char			npfd_ifname[LIFNAMSIZ];
} npf_destination_t;

/*
 * Needed:
 * - negation matching on fields
 * - how to indicate state-based filtering/tracking
 */
typedef struct npf_filter_rule_s {
	npf_permission_t	nfr_action;
	npf_inout_t		nfr_inout;
	npf_logaction_t		nfr_log;
	int			nfr_log_level;
	int			nfr_family;
	int			nfr_protocol;
	int			nfr_tos;
	npf_rule_addr_t		nfr_src;
	npf_rule_addr_t		nfr_dst;
	npf_l4hdr_match_t	nfr_l4match;
	char			nfr_ifname[LIFNAMSIZ];
	char			nfr_group[NPF_GROUP_NAME_SIZE];
	npf_destination_t	nfr_nexthop[2];	/* fwd & rev */
} npf_filter_rule_t;

/*
 * 1 bit per option # for matching on.
 */
typedef struct npf_ip_option_rule_s {
	uint32_t		nior_options[8];
	uint32_t		nior_optionmask[8];
} npf_ip_option_rule_t;


struct npf_handle_s;
typedef int (*npf_func_t)(struct npf_handle_s *, void *, const char *);

typedef struct npf_handle_s {
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
	npf_version_t	version;
} npf_handle_t;

extern npf_handle_t *npf_open(const char *name, const npf_version_t version);
extern int npf_close(npf_handle_t *);
extern void npf_set_private(npf_handle_t *, void *);
extern void *npf_get_private(npf_handle_t *);

extern int npf_fw_delete_rule(npf_handle_t *, npf_filter_rule_t *,
			      const char *);
extern int npf_fw_insert_rule(npf_handle_t *, npf_filter_rule_t *,
			      const char *);

extern int npf_nat_delete_rule(npf_handle_t *, npf_nat_rule_t *, const char *);
extern int npf_nat_find_rule(npf_handle_t *, npf_nat_rule_t *, const char *);
extern int npf_nat_lookup_rdr(npf_handle_t *, npf_nat_desc_t *, const char *);
extern int npf_nat_getnext_rule(npf_handle_t *, npf_nat_rule_t *, const char *);
extern int npf_nat_insert_rule(npf_handle_t *, npf_nat_rule_t *, const char *);

/*
 * From FreeBSD...
 */
#if defined(__GNUC__) || defined(__INTEL_COMPILER)
#define NPF_RCSID(name,string) __asm__(".ident\t\"" string "\"")
#else
/*
 * The following definition might not work well if used in header files,
 * but it should be better than nothing.  If you want a "do nothing"
 * version, then it should generate some harmless declaration, such as:
 *    #define __IDSTRING(name,string)   struct __hack
 */
#define NPF_RCSID(name,string) static const char name[] __unused = string
#endif



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
