%{
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
#include "hdr.h"
#include "lexer.h"
#include <sys/stat.h>
#include <netdb.h>
#include <syslog.h>
#include <errno.h>
#include <arpa/inet.h>

#define YYDEBUG 1

extern	config_t config;
extern  void    yyerror __P((char *));
extern  int     yyparse __P((void));
extern  int     yylex __P((void));
extern  int     yydebug;
extern  FILE    *yyin;
extern  int     yylineNum;

static void		add_acl(acl_t *a);
static domain_t		*add_domains(domain_t *d1, domain_t *d2);
static void		add_forward(forward_t *forwards);
static hostlist_t	*add_host(hostlist_t *h1, hostlist_t *h2);
static name_t		*add_name(name_t *n1, name_t *n2);
static void		dump_hosts(struct htop *htop);
static inbound_t	*find_port(char *name);
static forward_t	*hosts_to_forward(hostlist_t *hosts);
static acl_t		*new_acl(hostlist_t *h, char *port, domain_t *d);
static domain_t		*new_domains(action_t act, name_t *names);
static hostlist_t	*new_iphost(u_int addr, u_int mask);
static name_t		*new_name(char *str1, char *str2);
static inbound_t *	new_port(char *, hostlist_t *, u_short, int);
static int		tosecs(char *units);
static qtypelist_t	*add_qtype(qtypelist_t *q1, qtypelist_t *q2);
static qtypelist_t	*new_qtype(int type);
static void		add_qmatch_qtypes(querymatch_t *qm, qtypelist_t *qt);
%}

%union {
	u_int		num;
	char		*str;
	hostlist_t	*host;
	acl_t		*acl;
	domain_t	*dom;
	name_t		*name;
	acl_t		aopt;
	inbound_t	*in;
	forward_t	*fwd;
	querymatch_t	*qm;
	qtypelist_t	*qt;
};

%token  <num>   YY_NUMBER YY_HEX
%token  <str>   YY_STR
%token          YY_COMMENT

%token		YY_ACL YY_ALLOW YY_BLOCK YY_REJECT YY_ALL YY_MAXTTL
%token		YY_PORT YY_TRANSPARENT YY_FORWARDERS YY_QUERY YY_TYPE
%token		YY_Q_A YY_Q_NS YY_Q_MD YY_Q_MF YY_Q_CNAME YY_Q_SOA YY_Q_MB
%token		YY_Q_MG YY_Q_MR YY_Q_NULL YY_Q_WKS YY_Q_PTR YY_Q_HINFO
%token		YY_Q_MINFO YY_Q_MX YY_Q_TXT YY_Q_RP YY_Q_AFSDB YY_Q_X25
%token		YY_Q_ISDN YY_Q_RT YY_Q_NSAP YY_Q_NSAP_PTR YY_Q_SIG YY_Q_KEY
%token		YY_Q_PX YY_Q_GPOS YY_Q_AAAA YY_Q_LOC YY_Q_NXT YY_Q_EID
%token		YY_Q_NIMLOC YY_Q_SRV YY_Q_ATMA YY_Q_NAPTR YY_Q_KX YY_Q_CERT
%token		YY_Q_A6 YY_Q_DNAME YY_Q_SINK YY_Q_OPT YY_Q_TKEY YY_Q_TSIG
%token		YY_Q_IXFR YY_Q_AXFR YY_Q_MAILB YY_Q_MAILA YY_Q_ANY YY_Q_ZXFR

%type	<num>	octet mask
%type	<host>	ipaddress hlist
%type	<acl>	acl
%type	<dom>	action actions
%type	<name>	names hname
%type	<aopt>	opts option optlist
%type	<in>	port
%type	<fwd>	forward
%type	<qm>	query
%type	<qt>	qtypes qtype qtist
%%

file:	line
	| file line
	;

line:	comment
	| acl ';'		{ add_acl($1); }
	| port ';'		{ add_port($1); }
	| forward ';'		{ add_forward($1); }
	| query ';'		{ add_query($1); }
	;

comment:
	YY_COMMENT
	;

acl:	YY_ACL YY_ALL YY_PORT YY_STR optlist '{' actions ';' '}'
				{ $$ = new_acl(NULL, $4, $7); }
	| YY_ACL hlist YY_PORT YY_STR optlist '{' actions ';' '}'
				{ $$ = new_acl($2, $4, $7); }
	;

port:	YY_PORT YY_STR ipaddress YY_NUMBER
				{ $$ = new_port($2, $3, $4, 0); }
	| YY_PORT YY_STR ipaddress YY_NUMBER YY_TRANSPARENT
				{ $$ = new_port($2, $3, $4, 1); }
	;

forward:
	YY_FORWARDERS '{' hlist ';' '}'    
				{ $$ = hosts_to_forward($3); }
	;

query:	YY_QUERY qtypes '{' forward ';' '}'
				{ $$ = new_querymatch();
				  if ($$ != NULL) {
					if ($2 != NULL) {
						add_qmatch_qtypes($$, $2);
					}
					if ($4 != NULL) {
						add_qmatch_forwards($$, $4);
					}
				  }
				}
	;

qtypes:				{ $$ = NULL; }
	| YY_TYPE '='
				{ yysetdict(queries); }
	'(' qtist ')'
				{ yyresetdict();
				  $$ = $5;
				}
	;

qtist:	qtype			{ $$ = add_qtype(NULL, $1); }
	| qtist ',' qtype	{ $$ = add_qtype($1, $3); }
	;

optlist: 			{ memset(&$$, 0, sizeof($$)); }
	| '(' opts ')'		{ $$ = $2; }
	;

opts:	option			{ $$ = $1; }
	| option ',' opts	{ merge_options(&$1, &$3, &$$); }
	;

option:	YY_MAXTTL YY_NUMBER YY_STR
				{ $$.acl_maxttl = $2 * tosecs($3); }
	;

actions:
	action			{ $$ = add_domains($1, NULL); }
	| actions ';' action	{ $$ = add_domains($1, $3); }
	;

action:	YY_BLOCK names		{ $$ = new_domains(Q_BLOCK, $2); }
	| YY_ALLOW names	{ $$ = new_domains(Q_ALLOW, $2); }
	| YY_REJECT names	{ $$ = new_domains(Q_REJECT, $2); }
	;

hlist:	ipaddress		{ $$ = add_host($1, NULL); }
	| hlist ',' ipaddress	{ $$ = add_host($1, $3); }
	;

names:	hname			{ $$ = add_name($1, NULL); }
	| names ',' hname	{ $$ = add_name($1, $3); }
	;

hname:	YY_STR			{ $$ = new_name(NULL, $1); free($1); }
	| '.' YY_STR		{ $$ = new_name(".", $2); free($2); }
	| '=' YY_STR		{ $$ = new_name("=", $2); free($2); }
	| '*' YY_STR		{ $$ = new_name("*", $2); free($2); }
	| '*' '.' YY_STR	{ $$ = new_name("*.", $3); free($3); }
	;

qtype:	YY_Q_A			{ $$ = new_qtype(T_A); }
	| YY_Q_NS		{ $$ = new_qtype(T_NS); }
	| YY_Q_MD		{ $$ = new_qtype(T_MD); }
	| YY_Q_MF		{ $$ = new_qtype(T_MF); }
	| YY_Q_CNAME		{ $$ = new_qtype(T_CNAME); }
	| YY_Q_SOA		{ $$ = new_qtype(T_SOA); }
	| YY_Q_MB		{ $$ = new_qtype(T_MB); }
	| YY_Q_MG		{ $$ = new_qtype(T_MG); }
	| YY_Q_MR		{ $$ = new_qtype(T_MR); }
	| YY_Q_NULL		{ $$ = new_qtype(T_NULL); }
	| YY_Q_WKS		{ $$ = new_qtype(T_WKS); }
	| YY_Q_PTR		{ $$ = new_qtype(T_PTR); }
	| YY_Q_HINFO		{ $$ = new_qtype(T_HINFO); }
	| YY_Q_MINFO		{ $$ = new_qtype(T_MINFO); }
	| YY_Q_MX		{ $$ = new_qtype(T_MX); }
	| YY_Q_TXT		{ $$ = new_qtype(T_TXT); }
	| YY_Q_RP		{ $$ = new_qtype(T_RP); }
	| YY_Q_AFSDB		{ $$ = new_qtype(T_AFSDB); }
	| YY_Q_X25		{ $$ = new_qtype(T_X25); }
	| YY_Q_ISDN		{ $$ = new_qtype(T_ISDN); }
	| YY_Q_RT		{ $$ = new_qtype(T_RT); }
	| YY_Q_NSAP		{ $$ = new_qtype(T_NSAP); }
	| YY_Q_NSAP_PTR		{ $$ = new_qtype(T_NSAP_PTR); }
	| YY_Q_SIG		{ $$ = new_qtype(T_SIG); }
	| YY_Q_KEY		{ $$ = new_qtype(T_KEY); }
	| YY_Q_PX		{ $$ = new_qtype(T_PX); }
	| YY_Q_GPOS		{ $$ = new_qtype(T_GPOS); }
	| YY_Q_AAAA		{ $$ = new_qtype(T_AAAA); }
	| YY_Q_LOC		{ $$ = new_qtype(T_LOC); }
	| YY_Q_NXT		{ $$ = new_qtype(T_NXT); }
	| YY_Q_EID		{ $$ = new_qtype(T_EID); }
	| YY_Q_NIMLOC		{ $$ = new_qtype(T_NIMLOC); }
	| YY_Q_SRV		{ $$ = new_qtype(T_SRV); }
	| YY_Q_ATMA		{ $$ = new_qtype(T_ATMA); }
	| YY_Q_NAPTR		{ $$ = new_qtype(T_NAPTR); }
	| YY_Q_KX		{ $$ = new_qtype(T_KX); }
	| YY_Q_CERT		{ $$ = new_qtype(T_CERT); }
	| YY_Q_A6		{ $$ = new_qtype(T_A6); }
	| YY_Q_DNAME		{ $$ = new_qtype(T_DNAME); }
	| YY_Q_SINK		{ $$ = new_qtype(T_SINK); }
	| YY_Q_OPT		{ $$ = new_qtype(T_OPT); }
	| YY_Q_TKEY		{ $$ = new_qtype(T_TKEY); }
	| YY_Q_TSIG		{ $$ = new_qtype(T_TSIG); }
	| YY_Q_IXFR		{ $$ = new_qtype(T_IXFR); }
	| YY_Q_AXFR		{ $$ = new_qtype(T_AXFR); }
	| YY_Q_MAILB		{ $$ = new_qtype(T_MAILB); }
	| YY_Q_MAILA		{ $$ = new_qtype(T_MAILA); }
	| YY_Q_ANY		{ $$ = new_qtype(T_ANY); }
	| YY_Q_ZXFR		{ $$ = new_qtype(T_ZXFR); }
	| '*'			{ $$ = new_qtype(0); }
	;

ipaddress:
	octet '.' octet '.' octet '.' octet
				{ int x = $1 << 24 | $3 << 16 | $5 <<8 | $7;
				  $$ = new_iphost(x, 0xffffffff);
				}
	| octet '.' octet '.' octet '.' octet '/' mask
				{ int x = $1 << 24 | $3 << 16 | $5 <<8 | $7;
				  $$ = new_iphost(x, 0xfffffff << (32 - $9));
				}
	| octet '.' octet '.' octet '/' mask
				{ int x = $1 << 24 | $3 << 16 | $5 <<8;
				  $$ = new_iphost(x, 0xfffffff << (32 - $7));
				}
	| octet '.' octet '/' mask
				{ int x = $1 << 24 | $3 << 16;
				  $$ = new_iphost(x, 0xfffffff << (32 - $5));
				}
	| octet '/' mask
				{ int x = $1 << 24;
				  $$ = new_iphost(x, 0xfffffff << (32 - $3));
				}
	| octet '.' octet '.' octet '.' '*'
				{ int x = $1 << 24 | $3 << 16 | $5 <<8;
				  $$ = new_iphost(x, 0xffffff00);
				}
	| octet '.' octet '.' '*'
				{ int x = $1 << 24 | $3 << 16;
				  $$ = new_iphost(x, 0xffff0000);
				}
	| octet '.' '*'
				{ int x = $1 << 24;
				  $$ = new_iphost(x, 0xff000000);
				}
	| '*'			{ $$ = new_iphost(0, 0); }
	;

octet:	YY_NUMBER		{ if ($1 < 0 || $1 > 255)
					yyerror("bad ip");
				  else
					$$ = $1;
				}
	;

mask:
	YY_NUMBER		{ $$ = $1; }
	| YY_HEX		{ $$ = $1; }
	;
%%

static struct wordtab words[26] = {
	{ "acl",		YY_ACL },
	{ "all",		YY_ALL },
	{ "allow",		YY_ALLOW },
	{ "block",		YY_BLOCK },
	{ "deny",		YY_BLOCK },
	{ "forwarders",		YY_FORWARDERS },
	{ "maxttl",		YY_MAXTTL },
	{ "pass",		YY_ALLOW },
	{ "port",		YY_PORT },
	{ "query",		YY_QUERY },
	{ "reject",		YY_REJECT },
	{ "transparent",	YY_TRANSPARENT },
	{ "type",		YY_TYPE },
	{ NULL,			0 }
};

static struct wordtab queries[50] = {
	{ "A",			YY_Q_A },
	{ "NS",			YY_Q_NS },
	{ "MD",			YY_Q_MD },
	{ "MF",			YY_Q_MF },
	{ "CNAME",		YY_Q_CNAME },
	{ "SOA",		YY_Q_SOA },
	{ "MB",			YY_Q_MB },
	{ "MG",			YY_Q_MG },
	{ "MR",			YY_Q_MR },
	{ "NULL",		YY_Q_NULL },
	{ "WKS",		YY_Q_WKS },
	{ "PTR",		YY_Q_PTR },
	{ "HINFO",		YY_Q_HINFO },
	{ "MINFO",		YY_Q_MINFO },
	{ "MX",			YY_Q_MX },
	{ "TXT",		YY_Q_TXT },
	{ "RP",			YY_Q_RP },
	{ "AFSDB",		YY_Q_AFSDB },
	{ "X25",		YY_Q_X25 },
	{ "ISDN",		YY_Q_ISDN },
	{ "RT",			YY_Q_RT },
	{ "NSAP",		YY_Q_NSAP },
	{ "NSAP_PTR",		YY_Q_NSAP_PTR },
	{ "SIG",		YY_Q_SIG },
	{ "KEY",		YY_Q_KEY },
	{ "PX",			YY_Q_PX },
	{ "GPOS",		YY_Q_GPOS },
	{ "AAAA",		YY_Q_AAAA },
	{ "LOC",		YY_Q_LOC },
	{ "NXT",		YY_Q_NXT },
	{ "EID",		YY_Q_EID },
	{ "NIMLOC",		YY_Q_NIMLOC },
	{ "SRV",		YY_Q_SRV },
	{ "ATMA",		YY_Q_ATMA },
	{ "NAPTR",		YY_Q_NAPTR },
	{ "KX",			YY_Q_KX },
	{ "CERT",		YY_Q_CERT },
	{ "A6",			YY_Q_A6 },
	{ "DNAME",		YY_Q_DNAME },
	{ "SINK",		YY_Q_SINK },
	{ "OPT",		YY_Q_OPT },
	{ "TKEY",		YY_Q_TKEY },
	{ "TSIG",		YY_Q_TSIG },
	{ "IXFR",		YY_Q_IXFR },
	{ "AXFR",		YY_Q_AXFR },
	{ "MAILB",		YY_Q_MAILB },
	{ "MAILA",		YY_Q_MAILA },
	{ "ANY",		YY_Q_ANY },
	{ "ZXFR",		YY_Q_ZXFR },
	{ NULL,			0 }
};

static struct wordtab dnsqtypes[50] = {
	{ "A",			T_A },
	{ "NS",			T_NS },
	{ "MD",			T_MD },
	{ "MF",			T_MF },
	{ "CNAME",		T_CNAME },
	{ "SOA",		T_SOA },
	{ "MB",			T_MB },
	{ "MG",			T_MG },
	{ "MR",			T_MR },
	{ "NULL",		T_NULL },
	{ "WKS",		T_WKS },
	{ "PTR",		T_PTR },
	{ "HINFO",		T_HINFO },
	{ "MINFO",		T_MINFO },
	{ "MX",			T_MX },
	{ "TXT",		T_TXT },
	{ "RP",			T_RP },
	{ "AFSDB",		T_AFSDB },
	{ "X25",		T_X25 },
	{ "ISDN",		T_ISDN },
	{ "RT",			T_RT },
	{ "NSAP",		T_NSAP },
	{ "NSAP_PTR",		T_NSAP_PTR },
	{ "SIG",		T_SIG },
	{ "KEY",		T_KEY },
	{ "PX",			T_PX },
	{ "GPOS",		T_GPOS },
	{ "AAAA",		T_AAAA },
	{ "LOC",		T_LOC },
	{ "NXT",		T_NXT },
	{ "EID",		T_EID },
	{ "NIMLOC",		T_NIMLOC },
	{ "SRV",		T_SRV },
	{ "ATMA",		T_ATMA },
	{ "NAPTR",		T_NAPTR },
	{ "KX",			T_KX },
	{ "CERT",		T_CERT },
	{ "A6",			T_A6 },
	{ "DNAME",		T_DNAME },
	{ "SINK",		T_SINK },
	{ "OPT",		T_OPT },
	{ "TKEY",		T_TKEY },
	{ "TSIG",		T_TSIG },
	{ "IXFR",		T_IXFR },
	{ "AXFR",		T_AXFR },
	{ "MAILB",		T_MAILB },
	{ "MAILA",		T_MAILA },
	{ "ANY",		T_ANY },
	{ "ZXFR",		T_ZXFR },
	{ NULL,			0 }
};


void
config_init()
{
	config.c_debug = 0;

	if (config.c_cffile == NULL)
		config.c_cffile = "/etc/dns-proxy.conf";

	STAILQ_INIT(&config.c_acls);
	STAILQ_INIT(&config.c_ports);
	STAILQ_INIT(&config.c_queries);
	STAILQ_INIT(&config.c_qmatches);
	CIRCLEQ_INIT(&config.c_forwards);

	config.c_outfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (config.c_outfd == -1) {
		logit(-1, "failed to create outbound UDP socket\n");
		exit(1);
	}
}

void
load_config(char *filename)
{       
	FILE *fp;
	char *s;

	s = getenv("YYDEBUG");
	if (s != NULL)
		yydebug = atoi(s);

	yysettab(words);

	fp = fopen(filename, "r"); 
	if (fp != NULL) {
		yyin = fp;
		
		while (yyparse())
			;
		fclose(fp);
	}

	if (STAILQ_EMPTY(&config.c_ports)) {
		logit(-1, "no inbound ports defined\n");
		exit(1);
	}

	logit(0, "Configuration loaded\n");
}


static hostlist_t *
new_iphost(u_int addr, u_int mask)
{
	hostlist_t *h;

	h = calloc(1, sizeof(*h));
	if (h == NULL) {
		logit(-1, "new_iphost cannot allocate another hostlist_t\n");
		return (NULL);
	}

	h->hl_ipaddr.s_addr = htonl(addr);
	h->hl_mask.s_addr = htonl(mask);
	return (h);
}


static hostlist_t *
add_host(hostlist_t *h1, hostlist_t *h2)
{
	STAILQ_NEXT(h1, hl_next) = h2;
	return (h1);
}


static qtypelist_t *
new_qtype(int type)
{
	qtypelist_t *qt;

	qt = calloc(1, sizeof(*qt));
	if (qt == NULL) {
		logit(-1, "new_qtype cannot allocate another qtypelist_t\n");
		return (NULL);
	}

	qt->qt_type = type;
	return (qt);
}


static qtypelist_t *
add_qtype(qtypelist_t *q1, qtypelist_t *q2)
{
	if (q1 != NULL) {
		STAILQ_NEXT(q1, qt_next) = q2;
		return (q1);
	}

	return (q2);
}


static querymatch_t *
new_querymatch()
{
	querymatch_t *qm;

	qm = calloc(1, sizeof(*qm));
	if (qm == NULL) {
		logit(-1, "new_querymatch cannot allocate memory\n");
		return (NULL);
	}

	STAILQ_INIT(&qm->qm_types);
	CIRCLEQ_INIT(&qm->qm_forwards);

	return (qm);
}


static void
add_qmatch_qtypes(querymatch_t *qm, qtypelist_t *qt)
{
	qtypelist_t *qt1, *qt2;

	for (qt1 = qt; qt1 != NULL; qt1 = qt2) {
		qt2 = STAILQ_NEXT(qt1, qt_next);
		STAILQ_NEXT(qt1, qt_next) = NULL;
		STAILQ_INSERT_TAIL(&qm->qm_types, qt1, qt_next);
	}
}


static void
add_qmatch_forwards(querymatch_t *qm, forward_t *forwards)
{
	forward_t *f, *fn;

	if (config.c_debug > 1)
		printf("# add_qmatch_forwards %p %p\n", qm, forwards);

	for (f = forwards; f != NULL; f = fn) {
		fn = CIRCLEQ_NEXT(f, f_next);
		CIRCLEQ_NEXT(f, f_next) = NULL;
		CIRCLEQ_INSERT_TAIL(&qm->qm_forwards, f, f_next);
	}
}


static name_t *
add_name(name_t *n1, name_t *n2)
{
	STAILQ_NEXT(n1, n_next) = n2;
	return (n1);
}


static name_t *
new_name(char *str1, char *str2)
{
	int namelen;
	name_t *n;

	if (str1 != NULL)
		namelen = strlen(str1);
	else
		namelen = 0;
	if (str2 != NULL)
		namelen += strlen(str2);

	n = calloc(1, sizeof(*n));
	if (n != NULL) {
		n->n_name = malloc(namelen + 1);
		snprintf(n->n_name, namelen + 1, "%s%s",
			 str1 ? str1 : "", str2 ? str2 : "");
		n->n_namelen = namelen;
	}
	return (n);
}


static domain_t *
new_domains(action_t act, name_t *names)
{
	domain_t *d;

	d = calloc(1, sizeof(*d));
	if (d != NULL) {
		STAILQ_INIT(&d->d_names);
		STAILQ_FIRST(&d->d_names) = names;
		d->d_pass = act;
	}
	return (d);
}


static domain_t *
add_domains(domain_t *d1, domain_t *d2)
{
	STAILQ_NEXT(d1, d_next) = d2;
	return (d1);
}


static acl_t *
new_acl(hostlist_t *h, char *port, domain_t *d)
{
	acl_t *a;

	if (find_port(port) == NULL) {
		logit(-1, "unknown port '%s' in acl rule\n", port);
		return (NULL);
	}

	a = calloc(1, sizeof(*a));
	if (a != NULL) {
		STAILQ_INIT(&a->acl_hosts);
		if (h == NULL) {
			STAILQ_FIRST(&a->acl_hosts) = new_iphost(0, 0);
		} else {
			STAILQ_FIRST(&a->acl_hosts) = h;
		}
		STAILQ_INIT(&a->acl_domains);
		STAILQ_FIRST(&a->acl_domains) = d;
		a->acl_portname = port;
	}
	return (a);
}


static void
add_acl(acl_t *a)
{
	if (a != NULL) {
		STAILQ_INSERT_TAIL(&config.c_acls, a, acl_next);
	}
}


static inbound_t *
new_port(char *name, hostlist_t *addr, u_short port, int transparent)
{
	inbound_t *in;

	logit(4, "new_port(%s,%s,%d,%d)\n", name, inet_ntoa(addr->hl_ipaddr),
	      port, transparent);

	if (find_port(name) != NULL) {
		logit(1, "port '%s' already exists\n", name);
		return (NULL);
	}

	if (addr->hl_mask.s_addr != 0xffffffff) {
		return (NULL);
	}

	in = calloc(1, sizeof(*in));
	if (in != NULL) {
		in->i_name = name;
		in->i_portspec.sin_family = AF_INET;
		in->i_portspec.sin_addr = addr->hl_ipaddr;
		in->i_portspec.sin_port = htons(port & 0xffff);
		in->i_transparent = transparent;
		in->i_fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (in->i_fd >= 0) {
			if (bind(in->i_fd, (struct sockaddr *)&in->i_portspec,
				 sizeof(in->i_portspec)) != 0) {
				logit(-1, "cannot bind UDP Port (%s,%d): %s\n",
				      inet_ntoa(addr->hl_ipaddr), port,
				      strerror(errno));
				close(in->i_fd);
				in->i_fd = -1;
				free(name);
				free(in);
				in = NULL;
			}
		}
	}
	return (in);
}


static inbound_t *
find_port(char *name)
{
	inbound_t *i;

	STAILQ_FOREACH(i, &config.c_ports, i_next) {
		if (!strcmp(name, i->i_name))
			return (i);
	}

	return (NULL);
}


static void
add_port(inbound_t *in)
{
	inbound_t *i;

	while ((i = in) != NULL) {
		in = STAILQ_NEXT(i, i_next);
		STAILQ_INSERT_TAIL(&config.c_ports, i, i_next);
	}
}


static void
add_forward(forward_t *forwards)
{
	forward_t *f, *fn;

	if (config.c_debug > 1)
		printf("# add_forward %p\n", forwards);

	for (f = forwards; f != NULL; f = fn) {
		fn = CIRCLEQ_NEXT(f, f_next);
		CIRCLEQ_NEXT(f, f_next) = NULL;
		CIRCLEQ_INSERT_TAIL(&config.c_forwards, f, f_next);

		if (config.c_debug > 1)
			printf("# forward added (%p,%p) %s\n", f, fn,
			       inet_ntoa(f->f_ipaddr));
	}
}


static void
add_query(querymatch_t *qmatch)
{
	STAILQ_INSERT_TAIL(&config.c_qmatches, qmatch, qm_next);
}


static int
tosecs(char *units)
{
	if (!strcasecmp(units, "s"))
		return (1);
	if (!strcasecmp(units, "sec"))
		return (1);
	if (!strcasecmp(units, "secs"))
		return (1);
	if (!strcasecmp(units, "seconds"))
		return (1);
	if (!strcasecmp(units, "m"))
		return (60);
	if (!strcasecmp(units, "min"))
		return (60);
	if (!strcasecmp(units, "mins"))
		return (60);
	if (!strcasecmp(units, "minutes"))
		return (60);
	if (!strcasecmp(units, "h"))
		return (3600);
	if (!strcasecmp(units, "hr"))
		return (3600);
	if (!strcasecmp(units, "hrs"))
		return (3600);
	if (!strcasecmp(units, "hours"))
		return (3600);
	return (0);
}


static char *
qtype_to_name(int type)
{
	static char buffer[10];
	wordtab_t *w;

	for (w = dnsqtypes; w->w_word != NULL; w++)
		if (w->w_value == type)
			return (w->w_word);

	(void) snprintf(buffer, sizeof(buffer), "%d", type);

	return (buffer);
}


static void
merge_options(acl_t *as1, acl_t *as2, acl_t *ad)
{
	if (as1->acl_maxttl != 0)
		ad->acl_maxttl = as1->acl_maxttl;
	else if (as2->acl_maxttl != 0)
		ad->acl_maxttl = as2->acl_maxttl;
}


static forward_t *
hosts_to_forward(hostlist_t *hosts)
{
	forward_t *f, *top, *last;
	hostlist_t *h;

	top = NULL;

	while ((h = hosts) != NULL) {
		hosts = STAILQ_NEXT(h, hl_next);
		f = calloc(1, sizeof(*f));
		if (f == NULL) {
			logit(-1, "no memory for host->forward\n");
		} else {
			f->f_ipaddr = h->hl_ipaddr;
			if (top == NULL) {
				top = f;
			} else {
				CIRCLEQ_NEXT(last, f_next) = f;
			}
			last = f;

			if (config.c_debug > 1)
				printf("# hosts_to_forward f=%p\n", f);
		}
		free(h);
	}

	if (config.c_debug > 1)
		printf("# hosts_to_forward top=%p\n", top);

	return (top);
}


char *       
get_action(action_t act)
{

	switch (act)
	{
	case Q_ALLOW :
		return ("allow");
	case Q_BLOCK :
		return ("block");
	case Q_REJECT :
		return ("reject");
	case Q_NOMATCH :
		return ("nomatch");
	default :
		break;
	}
	return ("???");
}



static void
dump_hosts(struct htop *hosts)
{
	hostlist_t *h;

	STAILQ_FOREACH(h, hosts, hl_next) {
		if ((h->hl_mask.s_addr == 0) && (h->hl_ipaddr.s_addr == 0)) {
			printf("all");
		} else if (h->hl_mask.s_addr == 0xffffffff) {
			printf("%s%s", inet_ntoa(h->hl_ipaddr),
			       STAILQ_NEXT(h, hl_next) ? "," : "");
		} else {
			printf("%s/%d%s", inet_ntoa(h->hl_ipaddr),
			       countv4bits(h->hl_mask.s_addr),
			       STAILQ_NEXT(h, hl_next) ? "," : "");
		}
	}
}


void
dump_names(struct ntop *ntop)
{
	name_t *n;

	STAILQ_FOREACH(n, ntop, n_next) {
		printf("%s", n->n_name);
		if (STAILQ_NEXT(n, n_next) != NULL)
			putchar(',');
	}
}


void
dump_domains(struct dtop *dtop)
{
	domain_t *d;

	STAILQ_FOREACH(d, dtop, d_next) {
		printf(" %s ", get_action(d->d_pass));
		dump_names(&d->d_names);
		printf(";");
	}
}


void
dump_ports(struct intop *ptop)
{
	inbound_t *in;

	STAILQ_FOREACH(in, ptop, i_next) {
		printf("port %s %s %d;\n", in->i_name,
		       inet_ntoa(in->i_portspec.sin_addr),
		       ntohs(in->i_portspec.sin_port));
	}
}


void
dump_forwarders(struct ftop *ftop, int eol)
{
	forward_t *f;

	printf("forwarders {");
	CIRCLEQ_FOREACH(f, ftop, f_next) {
		printf(" %s", inet_ntoa(f->f_ipaddr));
		if (f != CIRCLEQ_LAST(ftop))
			putchar(',');
	}
	printf(";};");
	if (eol)
		putchar('\n');
}


void
dump_acls(struct atop *atop)
{
	acl_t *a;

	STAILQ_FOREACH(a, atop, acl_next) {
		printf("acl ");
		dump_hosts(&a->acl_hosts);
		printf(" port %s {", a->acl_portname);
		dump_domains(&a->acl_domains);
		printf(" };\n");
	}
}


void
dump_querymatches(struct qmtop *qmtop)
{
	querymatch_t *qm;

	STAILQ_FOREACH(qm, qmtop, qm_next) {
		printf("query ");
		if (!STAILQ_EMPTY(&qm->qm_types)) {
			qtypelist_t *qt;

			printf("type=(");
			STAILQ_FOREACH(qt, &qm->qm_types, qt_next) {
				printf("%s", qtype_to_name(qt->qt_type));
				if (STAILQ_NEXT(qt, qt_next) != NULL) {
					printf(",");
				}
			}
			printf(")");
		}

		printf(" {");

		if (!CIRCLEQ_EMPTY(&qm->qm_forwards)) {
			dump_forwarders(&qm->qm_forwards, 0);
		}
		printf(" };\n");
	}
}


void
dump_config()
{
	dump_ports(&config.c_ports);
	dump_acls(&config.c_acls);
	dump_forwarders(&config.c_forwards, 1);
	dump_querymatches(&config.c_qmatches);
}
