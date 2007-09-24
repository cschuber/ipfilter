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
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>

#include <arpa/nameser.h>

#include "queue.h"

#ifndef NO_IPFILTER
# include "ip_compat.h"
# include "ip_fil.h"
#endif


typedef	enum	action {
	Q_ALLOW = 1,
	Q_NOMATCH = 0,
	Q_BLOCK = -1,
	Q_REJECT = -2
} action_t;


typedef enum popttype {
	PO_T_INTEGER = 1
} popttype_t;

typedef struct portopt {
	SLIST_ENTRY(portopt)	po_next;
	int			po_option;
	popttype_t		po_type;
	int			po_int;
	long			po_long;
	void			*po_ptr;
} portopt_t;


typedef struct qinfo {
	int	qi_qtcount;
	int	*qi_qtypes;
	int	qi_ncount;
	char	**qi_names;
} qinfo_t;


typedef	struct inbound {
	STAILQ_ENTRY(inbound)	i_next;
	struct sockaddr_in	i_portspec;
	char			*i_name;
	int			i_fd;
	int			i_transparent;
	struct sockaddr_in	i_sender;
	char			i_buffer[2048];
	qinfo_t			i_qinfo;
} inbound_t;

STAILQ_HEAD(intop, inbound);


typedef	struct	name {
	STAILQ_ENTRY(name)	n_next;
	char			*n_name;
	int			n_namelen;
} name_t;

STAILQ_HEAD(ntop, name);


typedef	struct domain {
	STAILQ_ENTRY(domain)	d_next;
	action_t		d_pass;
	struct ntop		d_names;
} domain_t;

STAILQ_HEAD(dtop, domain);


typedef struct hostlist {
	STAILQ_ENTRY(hostlist)	hl_next;
	struct in_addr		hl_ipaddr;
	struct in_addr		hl_mask;
} hostlist_t;

STAILQ_HEAD(htop, hostlist);


typedef	struct acl	{
	STAILQ_ENTRY(acl)	acl_next;
	struct htop		acl_hosts;
	struct dtop		acl_domains;
	int			acl_maxttl;
	char			*acl_portname;
} acl_t;

STAILQ_HEAD(atop, acl);


typedef	struct query	{
	STAILQ_ENTRY(query)	q_next;
	inbound_t		*q_arrived;
	struct sockaddr_in	q_src;
	struct sockaddr_in	q_dst;
	u_short			q_origid;
	u_short			q_newid;
	time_t			q_recvd;
	time_t			q_dies;
} query_t;

STAILQ_HEAD(qtop, query);


typedef	struct forward {
	CIRCLEQ_ENTRY(forward)	f_next;
	struct in_addr		f_ipaddr;
	u_long			f_sends;
	u_long			f_recvs;
} forward_t;

CIRCLEQ_HEAD(ftop, forward);


typedef	struct qtypelist {
	STAILQ_ENTRY(qtypelist)	qt_next;
	int			qt_type;
} qtypelist_t;

STAILQ_HEAD(qttop, qtypelist);


typedef	struct querymatch {
	STAILQ_ENTRY(querymatch) qm_next;
	struct qttop		qm_types;
	struct ftop		qm_forwards;
	struct ntop		qm_names;
	forward_t		*qm_currentfwd;
	action_t		qm_action;
} querymatch_t;

STAILQ_HEAD(qmtop, querymatch);


typedef struct config {
	struct atop		c_acls;
	struct intop		c_ports;
	struct qtop		c_queries;
	struct ftop		c_forwards;
	struct qmtop		c_qmatches;
	forward_t		*c_currentforward;
	int			c_natfd;
	int			c_outfd;
	int			c_maxfd;
	fd_set			c_mfdr;
	int			c_debug;
	char			*c_cffile;
	int			c_keepprivs;
} config_t;


typedef struct {
	u_short		dns_id;
	u_short		dns_ctlword;
	u_short		dns_qdcount;
	u_short		dns_ancount;
	u_short		dns_nscount;
	u_short		dns_arcount;
} ipf_dns_hdr_t;

#define DNS_QR(x)	((ntohs(x) & 0x8000) >> 15)
#define DNS_OPCODE(x)	((ntohs(x) & 0x7800) >> 11) 
#define DNS_AA(x)	((ntohs(x) & 0x0400) >> 10)
#define DNS_TC(x)	((ntohs(x) & 0x0200) >> 9)
#define DNS_RD(x)	((ntohs(x) & 0x0100) >> 8)
#define DNS_RA(x)	((ntohs(x) & 0x0080) >> 7)
#define DNS_Z(x)	((ntohs(x) & 0x0070) >> 4)
#define DNS_RCODE(x)	((ntohs(x) & 0x000f) >> 0)


/*
 * Compat section
 */
#ifndef	T_MX
# define	T_MX	15
#endif
#ifndef	T_TXT
# define	T_TXT	16
#endif
#ifndef	T_RP
# define	T_RP	17
#endif
#ifndef	T_AFSDB
# define	T_AFSDB	18
#endif
#ifndef	T_X25
# define	T_X25	19
#endif
#ifndef	T_ISDN
# define	T_ISDN	20
#endif
#ifndef	T_RT
# define	T_RT	21
#endif
#ifndef	T_NSAP
# define	T_NSAP	22
#endif
#ifndef	T_NSAP_PTR
# define	T_NSAP_PTR	23
#endif
#ifndef	T_SIG
# define	T_SIG	24
#endif
#ifndef	T_KEY
# define	T_KEY	25
#endif
#ifndef	T_PX
# define	T_PX	26
#endif
#ifndef	T_GPOS
# define	T_GPOS	27
#endif
#ifndef	T_AAAA
# define	T_AAAA	28
#endif
#ifndef	T_LOC
# define	T_LOC	29
#endif
#ifndef	T_NXT
# define	T_NXT	30
#endif
#ifndef	T_EID
# define	T_EID	31
#endif
#ifndef	T_NIMLOC
# define	T_NIMLOC 32
#endif
#ifndef	T_SRV
# define	T_SRV	33
#endif
#ifndef	T_ATMA
# define	T_ATMA	34
#endif
#ifndef	T_NAPTR
# define	T_NAPTR	35
#endif
#ifndef	T_KX
# define	T_KX	36
#endif
#ifndef T_CERT
# define	T_CERT	37
#endif
#ifndef T_A6
# define	T_A6	38
#endif
#ifndef T_DNAME
# define	T_DNAME	39
#endif
#ifndef T_SINK
# define	T_SINK	40
#endif
#ifndef T_OPT
# define	T_OPT	41
#endif
#ifndef T_APL
# define	T_APL	42
#endif
#ifndef T_TKEY
# define	T_TKEY	249
#endif
#ifndef T_TSIG
# define	T_TSIG	250
#endif
#ifndef T_IXFR
# define	T_IXFR	251
#endif
#ifndef T_AXFR
# define	T_AXFR	252
#endif
#ifndef T_MAILB
# define	T_MAILB	253
#endif
#ifndef T_MAILA
# define	T_MAILA	254
#endif
#ifndef T_ANY
# define	T_ANY	255
#endif
#ifndef T_ZXFR
# define	T_ZXFR	256
#endif

extern void config_init(void);
extern int countv4bits(u_int);
extern char *get_variable(char *string, char **after, int line);
extern void logit(int level, char *string, ...);
extern void load_config(char *filename);
extern void dump_config(void);

