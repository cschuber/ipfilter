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

static forwarder_t *forwarder_find(char *name);
static forwarder_t *forwarder_new(char *name, hostlist_t *hosts);
static hostlist_t *iphost_new(u_int addr, u_int mask);
static hostlist_t *iphost_new(u_int addr, u_int mask);
static hostlist_t *host_add(hostlist_t *h1, hostlist_t *h2);
static name_t *name_add(name_t *n1, name_t *n2);
static domain_t *domains_new(action_t act, name_t *names);
static domain_t *domains_add(domain_t *d1, domain_t *d2);
static acl_t *acl_new(char *, hostlist_t *, name_t *, int, domain_t *);
static acl_t *acl_find(char *name);
static void acl_add(acl_t *a);
static inbound_t *port_new(char *name, hostlist_t *addr, u_short port, portopt_t *options);
static inbound_t *port_find(char *name);
static void port_add(inbound_t *in);
static portopt_t *portopt_new(int option, void *arg);
static portopt_t *portopt_add(portopt_t *po1, portopt_t *po2);
static modify_t *modify_new(char *name, int type, name_t *acls,
			    rrlist_t *keep, rrlist_t *strip, rrlist_t *clean);
static void rrarray_set(int type, u_char array[256]);
static forward_t *forward_new(name_t *acls, name_t *fwdrs);
static void names_to_acllist(name_t *names, struct acllisttop *top);
static void names_to_fwdlist(name_t *names, struct fwdlisttop *top);
static void names_to_fwdlist(name_t *names, struct fwdlisttop *top);
static void forward_add(forward_t *forward);
static void forwarder_add(forwarder_t *fwdr);
static void modify_add(modify_t *m);
static rrlist_t * rrtype_add(rrlist_t *r1, rrlist_t *r2);
static rrlist_t * rrtype_new(int type);
static char *rrtype_to_name(int type);
char *get_action(action_t act);
static void hosts_dump(struct htop *hosts);
void names_dump(struct ntop *ntop);
void domains_dump(struct dtop *dtop);
void ports_dump(struct intop *ptop);
void acls_dump(struct atop *atop);
void forwarder_dump(forwarder_t *fr);
void forwarders_dump(struct frtop *frtop);
void port_dump(inbound_t *port);

%}

%union {
	u_int		num;
	char		*str;
	hostlist_t	*host;
	acl_t		*acl;
	acl_t		aopt;
	modify_t	*mods;
	server_t	*srv;
	domain_t	*dom;
	name_t		*name;
	inbound_t	*in;
	inlist_t	*inl;
	forward_t	*fwd;
	forwarder_t	*fwdr;
	rrlist_t	*rr;
	portopt_t	*popt;
	modopt_t	mopt;
};

%token  <num>   YY_NUMBER YY_HEX YY_ON YY_OFF
%token  <str>   YY_STR
%token          YY_COMMENT

%token		YY_ACL YY_ALL YY_ALLOW YY_BLOCK YY_CLEAR YY_DISABLE
%token		YY_ENABLE YY_FORWARD YY_FORWARDERS
%token		YY_KEEP YY_MODIFY YY_NOMATCH YY_OFF YY_ON YY_PORT YY_POLICY
%token		YY_PRESERVE YY_RECURSION YY_REJECT
%token		YY_SOURCE YY_STRIP YY_TO YY_TRANSPARENT YY_UDP
%token		YY_QUESTION YY_ADDITIONAL YY_NAMESERVER YY_ANSWER

%token		YY_Q_A YY_Q_NS YY_Q_MD YY_Q_MF YY_Q_CNAME YY_Q_SOA YY_Q_MB
%token		YY_Q_MG YY_Q_MR YY_Q_NULL YY_Q_WKS YY_Q_PTR YY_Q_HINFO
%token		YY_Q_MINFO YY_Q_MX YY_Q_TXT YY_Q_RP YY_Q_AFSDB YY_Q_X25
%token		YY_Q_ISDN YY_Q_RT YY_Q_NSAP YY_Q_NSAP_PTR YY_Q_SIG YY_Q_KEY
%token		YY_Q_PX YY_Q_GPOS YY_Q_AAAA YY_Q_LOC YY_Q_NXT YY_Q_EID
%token		YY_Q_NIMLOC YY_Q_SRV YY_Q_ATMA YY_Q_NAPTR YY_Q_KX YY_Q_CERT
%token		YY_Q_A6 YY_Q_DNAME YY_Q_SINK YY_Q_OPT YY_Q_TKEY YY_Q_TSIG
%token		YY_Q_IXFR YY_Q_AXFR YY_Q_MAILB YY_Q_MAILA YY_Q_ANY YY_Q_ZXFR

%type	<acl>	acl
%type	<dom>	actions action
%type	<fwd>	forward
%type	<fwdr>	forwarders
%type	<host>	ipaddress hlist
%type	<in>	port
%type	<mods>	modify
%type	<mopt>	modopt
%type	<name>	names hname namelist dnames dname
%type	<num>	octet mask anyonoff onoff actionword rrtype rtype
%type	<popt>	portoptionlist portoptions portoption
%type	<rr>	rrlist
%%

file:	line
	| file line
	;

line:	comment
	| assign ';'
	| acl ';'		{ acl_add($1); }
	| port ';'		{ port_add($1); }
	| forward ';'		{ forward_add($1); }
	| forwarders ';'	{ forwarder_add($1); }
	| modify ';'		{ modify_add($1); }
	;

comment:
	YY_COMMENT
	;

assign:	YY_STR '=' { yyvarnext = 1; } YY_STR
				{ set_variable($1, $4); yyvarnext = 0; }
	;

acl:	YY_ACL YY_STR '{' YY_SOURCE '(' { yyexpectaddr = 1; } hlist ')' ';'
			  { yyexpectaddr = 0; }
			  YY_PORT '(' namelist ')' ';'
			  YY_RECURSION anyonoff ';';
			  YY_POLICY '{' actions ';' '}' ';' '}'
				{ $$ = acl_new($2, $7, $13, $17, $21); }
	;

port:	YY_PORT YY_STR '{' YY_UDP { yyexpectaddr = 1; }
			   ipaddress { yyexpectaddr = 0; } ',' YY_NUMBER ';'
			   portoptionlist '}'
				{ $$ = port_new($2, $6, $9, $11); }
	;

forwarders:
	YY_FORWARDERS YY_STR '{' { yyexpectaddr = 1; } hlist ';' '}'    
				{ $$ = forwarder_new($2, $5);
				  yyexpectaddr = 0;
				}
	;

forward:
	YY_FORWARD '{' YY_ACL '(' namelist ')' ';'
		       YY_TO '(' namelist ')' ';' '}'
				{ $$ = forward_new($5, $10); }
	;

modify:	YY_MODIFY YY_STR rtype '{' YY_ACL '(' namelist ')' ';'
				   YY_RECURSION modopt ';'
				   YY_KEEP '('
				   { yysetdict(queries); } rrlist ')' ';'
				   YY_STRIP '('
				   { yysetdict(queries); } rrlist ')' ';'
				   YY_CLEAR '('
				   { yysetdict(queries); } rrlist ')' ';'
				   '}'
				{ $$ = modify_new($2, $3, $7, $16, $22, $28);
				  if ($$ != NULL) {
					$$->m_recursion = $11;
				  }
				}
	;

namelist:
	YY_ALL			{ $$ = name_new(NULL, "*", NULL); }
	| '*'			{ $$ = name_new(NULL, "*", NULL); }
	| names;		{ $$ = $1; }
	;

names:	YY_STR			{ $$ = name_new(NULL, $1, NULL); }
	| names ',' YY_STR	{ $$ = name_add($1, name_new(NULL, $3, NULL)); }
	;

actions:
	action			{ $$ = domains_add($1, NULL); }
	| actions ';' action	{ $$ = domains_add($1, $3); }
	;

action:	actionword dnames	{ $$ = domains_new($1, $2); }
	;

actionword:
	YY_BLOCK		{ $$ = Q_BLOCK; }
	| YY_ALLOW		{ $$ = Q_ALLOW; }
	| YY_REJECT		{ $$ = Q_REJECT; }
	| YY_NOMATCH		{ $$ = Q_NOMATCH; }
	;

dnames:	dname			{ $$ = name_add($1, NULL); }
	| dnames ',' dname	{ $$ = name_add($1, $3); }
	;

dname:	hname			{ $$ = $1; }
	| hname '(' { yysetdict(queries); } rrlist ')'
				{ $$ = $1; name_set_rrs($1, $4); }
	;

portoptionlist:			{ $$ = NULL; }
	| portoptions ';'	{ $$ = $1; }
	;

portoptions:
	portoption		{ $$ = portopt_add($1, NULL); }
	| portoptions ';' portoption
				{ $$ = portopt_add($1, $3); }
	;

portoption:
	YY_TRANSPARENT onoff	{ $$ = portopt_new(YY_TRANSPARENT, &$2); }
	;

hlist:	YY_ALL			{ $$ = host_add(iphost_new(0, 0), NULL); }
	| ipaddress		{ $$ = host_add($1, NULL); }
	| hlist ';' ipaddress	{ $$ = host_add($1, $3); }
	;

hname:	YY_STR			{ $$ = name_new(NULL, $1, NULL); free($1); }
	| '.' YY_STR		{ $$ = name_new(".", $2, NULL); free($2); }
	| '=' YY_STR		{ $$ = name_new("=", $2, NULL); free($2); }
	| '*' YY_STR		{ $$ = name_new("*", $2, NULL); free($2); }
	| '*' '.' YY_STR	{ $$ = name_new("*.", $3, NULL); free($3); }
	| '*'			{ $$ = name_new(NULL, "*", NULL); }
	;

anyonoff:
	'*'			{ $$ = -1; }
	| onoff			{ $$ = $1; }
	;

onoff:	YY_ON			{ $$ = 1; }
	| YY_OFF		{ $$ = 0; }
	;

modopt:	YY_ENABLE		{ $$ = M_ENABLE; }
	| YY_DISABLE		{ $$ = M_DISABLE; }
	| YY_PRESERVE		{ $$ = M_PRESERVE; }
	;

rrlist:	rrtype			{ $$ = rrtype_add(rrtype_new($1), NULL); }
	| rrlist ',' rrtype	{ $$ = rrtype_add(rrtype_new($3), $1); }
	|			{ $$ = NULL; }
	;

rtype:	YY_QUESTION		{ $$ = Q_QUESTION; }
	| YY_ADDITIONAL		{ $$ = Q_ADDITIONAL; }
	| YY_ANSWER		{ $$ = Q_ANSWER; }
	| YY_NAMESERVER		{ $$ = Q_NAMESERVER; }
	;

rrtype:	YY_Q_A			{ $$ = T_A; }
	| YY_Q_NS		{ $$ = T_NS; }
	| YY_Q_MD		{ $$ = T_MD; }
	| YY_Q_MF		{ $$ = T_MF; }
	| YY_Q_CNAME		{ $$ = T_CNAME; }
	| YY_Q_SOA		{ $$ = T_SOA; }
	| YY_Q_MB		{ $$ = T_MB; }
	| YY_Q_MG		{ $$ = T_MG; }
	| YY_Q_MR		{ $$ = T_MR; }
	| YY_Q_NULL		{ $$ = T_NULL; }
	| YY_Q_WKS		{ $$ = T_WKS; }
	| YY_Q_PTR		{ $$ = T_PTR; }
	| YY_Q_HINFO		{ $$ = T_HINFO; }
	| YY_Q_MINFO		{ $$ = T_MINFO; }
	| YY_Q_MX		{ $$ = T_MX; }
	| YY_Q_TXT		{ $$ = T_TXT; }
	| YY_Q_RP		{ $$ = T_RP; }
	| YY_Q_AFSDB		{ $$ = T_AFSDB; }
	| YY_Q_X25		{ $$ = T_X25; }
	| YY_Q_ISDN		{ $$ = T_ISDN; }
	| YY_Q_RT		{ $$ = T_RT; }
	| YY_Q_NSAP		{ $$ = T_NSAP; }
	| YY_Q_NSAP_PTR		{ $$ = T_NSAP_PTR; }
	| YY_Q_SIG		{ $$ = T_SIG; }
	| YY_Q_KEY		{ $$ = T_KEY; }
	| YY_Q_PX		{ $$ = T_PX; }
	| YY_Q_GPOS		{ $$ = T_GPOS; }
	| YY_Q_AAAA		{ $$ = T_AAAA; }
	| YY_Q_LOC		{ $$ = T_LOC; }
	| YY_Q_NXT		{ $$ = T_NXT; }
	| YY_Q_EID		{ $$ = T_EID; }
	| YY_Q_NIMLOC		{ $$ = T_NIMLOC; }
	| YY_Q_SRV		{ $$ = T_SRV; }
	| YY_Q_ATMA		{ $$ = T_ATMA; }
	| YY_Q_NAPTR		{ $$ = T_NAPTR; }
	| YY_Q_KX		{ $$ = T_KX; }
	| YY_Q_CERT		{ $$ = T_CERT; }
	| YY_Q_A6		{ $$ = T_A6; }
	| YY_Q_DNAME		{ $$ = T_DNAME; }
	| YY_Q_SINK		{ $$ = T_SINK; }
	| YY_Q_OPT		{ $$ = T_OPT; }
	| YY_Q_TKEY		{ $$ = T_TKEY; }
	| YY_Q_TSIG		{ $$ = T_TSIG; }
	| YY_Q_IXFR		{ $$ = T_IXFR; }
	| YY_Q_AXFR		{ $$ = T_AXFR; }
	| YY_Q_MAILB		{ $$ = T_MAILB; }
	| YY_Q_MAILA		{ $$ = T_MAILA; }
	| YY_Q_ANY		{ $$ = T_ANY; }
	| YY_Q_ZXFR		{ $$ = T_ZXFR; }
	| '*'			{ $$ = -1; }
	;

ipaddress:
	octet '.' octet '.' octet '.' octet
				{ int x = $1 << 24 | $3 << 16 | $5 <<8 | $7;
				  $$ = iphost_new(x, 0xffffffff);
				}
	| octet '.' octet '.' octet '.' octet '/' mask
				{ int x = $1 << 24 | $3 << 16 | $5 <<8 | $7;
				  $$ = iphost_new(x, 0xfffffff << (32 - $9));
				}
	| octet '.' octet '.' octet '/' mask
				{ int x = $1 << 24 | $3 << 16 | $5 <<8;
				  $$ = iphost_new(x, 0xfffffff << (32 - $7));
				}
	| octet '.' octet '/' mask
				{ int x = $1 << 24 | $3 << 16;
				  $$ = iphost_new(x, 0xfffffff << (32 - $5));
				}
	| octet '/' mask
				{ int x = $1 << 24;
				  $$ = iphost_new(x, 0xfffffff << (32 - $3));
				}
	| octet '.' octet '.' octet '.' '*'
				{ int x = $1 << 24 | $3 << 16 | $5 <<8;
				  $$ = iphost_new(x, 0xffffff00);
				}
	| octet '.' octet '.' '*'
				{ int x = $1 << 24 | $3 << 16;
				  $$ = iphost_new(x, 0xffff0000);
				}
	| octet '.' '*'
				{ int x = $1 << 24;
				  $$ = iphost_new(x, 0xff000000);
				}
	| '*'			{ $$ = iphost_new(0, 0); }
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

static struct wordtab words[31] = {
	{ "acl",		YY_ACL },
	{ "additional",		YY_ADDITIONAL },
	{ "all",		YY_ALL },
	{ "answer",		YY_ANSWER },
	{ "allow",		YY_ALLOW },
	{ "block",		YY_BLOCK },
	{ "clear",		YY_CLEAR },
	{ "deny",		YY_BLOCK },
	{ "disable",		YY_DISABLE },
	{ "enable",		YY_ENABLE },
	{ "forward",		YY_FORWARD },
	{ "forwarders",		YY_FORWARDERS },
	{ "keep",		YY_KEEP },
	{ "modify",		YY_MODIFY },
	{ "off",		YY_OFF },
	{ "on",			YY_ON },
	{ "nameserver",		YY_NAMESERVER },
	{ "nomatch",		YY_NOMATCH },
	{ "pass",		YY_ALLOW },
	{ "policy",		YY_POLICY },
	{ "port",		YY_PORT },
	{ "preserve",		YY_PRESERVE },
	{ "question",		YY_QUESTION },
	{ "recursion",		YY_RECURSION },
	{ "reject",		YY_REJECT },
	{ "source",		YY_SOURCE },
	{ "strip",		YY_STRIP },
	{ "to",			YY_TO },
	{ "transparent",	YY_TRANSPARENT },
	{ "udp",		YY_UDP },
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

static struct wordtab dnsqtpyes[50] = {
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
	STAILQ_INIT(&config.c_modifies);
	STAILQ_INIT(&config.c_forwards);
	STAILQ_INIT(&config.c_forwarders);

	config.c_outfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (config.c_outfd == -1) {
		logit(-1, "failed to create outbound UDP socket\n");
		exit(1);
	}

	config.c_natfd = -1;
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


static rrlist_t *
rrtype_new(int type)
{
	rrlist_t *r;

	r = calloc(1, sizeof(*r));
	if (r == NULL) {
		logit(1, "rrtype_new(%d): cannot allocate memory\n", type);
		return (NULL);
	}

	r->rr_qtype = type;

	return (r);
}


static rrlist_t *
rrtype_add(rrlist_t *r1, rrlist_t *r2)
{

	if (r1 != NULL) {
		STAILQ_NEXT(r1, rr_next) = r2;
	}

	return (r1);
}


static hostlist_t *
iphost_new(u_int addr, u_int mask)
{
	hostlist_t *h;

	h = calloc(1, sizeof(*h));
	if (h == NULL) {
		logit(-1, "iphost_new cannot allocate another hostlist_t\n");
		return (NULL);
	}

	h->hl_ipaddr.s_addr = htonl(addr);
	h->hl_mask.s_addr = htonl(mask);
	return (h);
}


static hostlist_t *
host_add(hostlist_t *h1, hostlist_t *h2)
{
	STAILQ_NEXT(h1, hl_next) = h2;
	return (h1);
}


static name_t *
name_add(name_t *n1, name_t *n2)
{
	STAILQ_NEXT(n1, n_next) = n2;
	return (n1);
}


static void
name_set_rrs(name_t *n, rrlist_t *rrs)
{
	rrlist_t *r, *next;

	if (n == NULL)
		return;

	n->n_rrtypes = calloc(1, 256 * sizeof(*n->n_rrtypes));
	if (n->n_rrtypes == NULL) {
		logit(1, "name_set_rrs(%s): failed to allocate memory\n",
		      n->n_name);
		goto badnamesetrrs;
	}

	for (r = rrs; r != NULL; r = next) {
		next = STAILQ_NEXT(r, rr_next);
		rrarray_set(r->rr_qtype, n->n_rrtypes);
		free(r);
	}
	return;

badnamesetrrs:
	STAILQ_FREE_LIST(rrs, rrlist, rr_next, free);
	return;
}


static name_t *
name_new(char *str1, char *str2, rrlist_t *rrs)
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
	if (n == NULL) {
		logit(1, "cannot create new name \"%s+%s\"\n",
			str1 ? str1 : "", str2 ? str2 : "");
		goto badnewname;
	}

	n->n_name = malloc(namelen + 1);
	if (n->n_name == NULL) {
		goto badnewname;
	}
	snprintf(n->n_name, namelen + 1, "%s%s",
		 str1 ? str1 : "", str2 ? str2 : "");
	n->n_namelen = namelen;

	STAILQ_INIT(&n->n_rtypes);
	STAILQ_FROM_LIST(&n->n_rtypes, rrlist, rr_next, rrs);

	return (n);

badnewname:
	STAILQ_FREE_LIST(rrs, rrlist, rr_next, free);
	return (NULL);
}


static domain_t *
domains_new(action_t act, name_t *names)
{
	domain_t *d;

	d = calloc(1, sizeof(*d));
	if (d == NULL) {
		logit(1, "Cannot allocate new domain_t structure\n");
		goto badnewdomains;
	}

	STAILQ_INIT(&d->d_names);
	STAILQ_FROM_LIST(&d->d_names, name, n_next, names);
	d->d_pass = act;
	return (d);

badnewdomains:
	STAILQ_FREE_LIST(names, name, n_next, name_free);
	return (NULL);
}


static domain_t *
domains_add(domain_t *d1, domain_t *d2)
{
	STAILQ_NEXT(d1, d_next) = d2;
	return (d1);
}


static acl_t *
acl_find(char *name)
{
	acl_t *a;

	STAILQ_FOREACH(a, &config.c_acls, acl_next) {
		if (!strcmp(a->acl_name, name))
			return (a);
	}

	return (NULL);
}


static acl_t *
acl_new(char *name, hostlist_t *hosts, name_t *ports, int recursion,
	domain_t *domains)
{
	inlist_t *i, *ilist;
	hostlist_t *h;
	inbound_t *p;
	domain_t *d;
	name_t *n;
	acl_t *a;
	void *next;

	ilist = NULL;

	if (name == NULL || *name == '\0') {
		fprintf(stderr, "ACL with NULL name\n");
		goto badacl;
	}

	if (ports == NULL) {
		fprintf(stderr, "acl(%s): no ports defined\n", name);
		goto badacl;
	}

	/*
	 * Validate the ports first so that cleanup does not need to worry
	 * about whether a host is on the acl or not.
	 */
	for (n = ports; n != NULL; n = STAILQ_NEXT(n, n_next)) {
		if (!strcmp(n->n_name, "*")) {
			p = NULL;
		} else {
			p = port_find(n->n_name);
			if (p == NULL) {
				logit(-1, "acl(%s): unknown port '%s'\n",
				      name, n->n_name);
				goto badacl;
			}
		}

		i = calloc(1, sizeof(*i));
		if (i == NULL) {
			fprintf(stderr, "acl(%s): cannot add another port\n",
				name);
			goto badacl;
		}
		i->il_port = p;
		STAILQ_NEXT(i, il_next) = ilist;
		ilist = i;
	}

	if (hosts == NULL) {
		hosts = iphost_new(0, 0);
		if (hosts == NULL) {
			fprintf(stderr,
				"acl(%s): cannot allocate NULL hosts\n", name);
			goto badacl;
		}
	}

	a = calloc(1, sizeof(*a));
	if (a == NULL) {
		fprintf(stderr, "acl(%s): could not allocate new acl\n", name);
		goto badacl;
	}
	a->acl_name = name;
	a->acl_recursion = recursion;

	STAILQ_INIT(&a->acl_domains);
	STAILQ_FROM_LIST(&a->acl_domains, domain, d_next, domains);

	STAILQ_INIT(&a->acl_ports);
	STAILQ_FROM_LIST(&a->acl_ports, inlist, il_next, ilist);

	STAILQ_INIT(&a->acl_sources);
	STAILQ_FROM_LIST(&a->acl_sources, hostlist, hl_next, hosts);

	return (a);

badacl:
	for (h = hosts; h != NULL; h = next) {
		next = STAILQ_NEXT(h, hl_next);
		hostlist_free(h);
	}

	for (n = ports; n != NULL; n = next) {
		next = STAILQ_NEXT(n, n_next);
		name_free(n);
	}

	for (d = domains; d != NULL; d = next) {
		next = STAILQ_NEXT(d, d_next);
		domain_free(d);
	}

	return (NULL);
}


static void
acl_add(acl_t *a)
{

	if (a != NULL) {
		STAILQ_INSERT_TAIL(&config.c_acls, a, acl_next);
	}
}


static inbound_t *
port_new(char *name, hostlist_t *addr, u_short port, portopt_t *options)
{
	portopt_t *po1, *po2;
	inbound_t *in;

	logit(4, "port_new(%s,%s,%d,%p)\n", name, inet_ntoa(addr->hl_ipaddr),
	      port, options);

	if (port_find(name) != NULL) {
		logit(1, "port '%s' already exists\n", name);
		goto badnewport;
	}

	if (addr->hl_mask.s_addr != 0xffffffff) {
		goto badnewport;
	}

	in = calloc(1, sizeof(*in));
	if (in == NULL) {
		logit(1, "Could not allocate memory for new port\n");
		goto badnewport;
	}

	in->i_name = name;
	in->i_portspec.sin_family = AF_INET;
	in->i_portspec.sin_addr = addr->hl_ipaddr;
	in->i_portspec.sin_port = htons(port & 0xffff);
	in->i_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (in->i_fd >= 0) {
		if (bind(in->i_fd, (struct sockaddr *)&in->i_portspec,
			 sizeof(in->i_portspec)) != 0) {
			logit(-1, "cannot bind UDP Port (%s,%d): %s\n",
			      inet_ntoa(addr->hl_ipaddr), port,
			      strerror(errno));
			close(in->i_fd);
			in->i_fd = -1;
			free(in);
			in = NULL;

			goto badnewport;
		}
	}

	free(addr);

	for (po1 = options; po1 != NULL; po1 = po2) {
		po2 = SLIST_NEXT(po1, po_next);

		switch(po1->po_type)
		{
		case YY_TRANSPARENT :
			in->i_transparent = po1->po_int;
			break;
		default :
			break;
		}
		free(po1);
	}
	return (in);

badnewport:
	for (po1 = options; po1 != NULL; po1 = po2) {
		po2 = SLIST_NEXT(po1, po_next);
		free(po1);
	}

	if (name != NULL)
		free(name);

	if (addr != NULL)
		free(addr);
	return (NULL);
}


static inbound_t *
port_find(char *name)
{
	inbound_t *i;

	logit(8, "port_find(%s)\n", name);

	STAILQ_FOREACH(i, &config.c_ports, i_next) {
		if (!strcmp(name, i->i_name))
			return (i);
	}

	return (NULL);
}


static void
port_add(inbound_t *in)
{
	inbound_t *i;

	while ((i = in) != NULL) {
		in = STAILQ_NEXT(i, i_next);
		STAILQ_INSERT_TAIL(&config.c_ports, i, i_next);
	}
}


static portopt_t *
portopt_add(portopt_t *po1, portopt_t *po2)
{

	SLIST_NEXT(po1, po_next) = po2;
	return (po1);
}


static portopt_t *
portopt_new(int option, void *arg)
{
	portopt_t *popt;

	popt = calloc(1, sizeof(*popt));
	if (popt == NULL) {
		return (NULL);
	}

	popt->po_option = option;

	switch (option)
	{
	case YY_TRANSPARENT :
		popt->po_type = PO_T_INTEGER;
		popt->po_int = *(int *)arg;
		break;
	default :
		break;
	}

	return (popt);
}


static modify_t *
modify_new(char *name, int type, name_t *acls, rrlist_t *keep, rrlist_t *strip,
	   rrlist_t *clean)
{
	modify_t *m;
	rrlist_t *r, *next;

	m = calloc(1, sizeof(*m));
	if (m == NULL) {
		logit(1, "modify_new(%s): cannot allocate memory for modify\n",
		      name);
		goto badmodify;
	}

	STAILQ_INIT(&m->m_acls);
	names_to_acllist(acls, &m->m_acls);

	for (r = keep; r != NULL; r = next) {
		next = STAILQ_NEXT(r, rr_next);
		rrarray_set(r->rr_qtype, m->m_keep);
		free(r);
	}

	for (r = strip; r != NULL; r = next) {
		next = STAILQ_NEXT(r, rr_next);
		rrarray_set(r->rr_qtype, m->m_strip);
		free(r);
	}

	for (r = clean; r != NULL; r = next) {
		next = STAILQ_NEXT(r, rr_next);
		rrarray_set(r->rr_qtype, m->m_clean);
		free(r);
	}

	m->m_type = type;

	return (m);

badmodify:
	STAILQ_FREE_LIST(acls, name, n_next, name_free);
	STAILQ_FREE_LIST(keep, rrlist, rr_next, free);
	STAILQ_FREE_LIST(strip, rrlist, rr_next, free);
	return (NULL);
}


static void
modify_add(modify_t *m)
{

	STAILQ_INSERT_TAIL(&config.c_modifies, m, m_next);
}


static void
rrarray_set(int type, u_char array[256])
{

	if (type < -1 || type > 255) {
		logit(1, "RR type (%d) out of bounds\n", type);
		return;
	}

	if (type == -1) {
		memset(array, 1, 256);
	} else {
		if (array[type] != 0) {
			logit(2, "RR type (%d) already set\n", type);
		} else {		
			array[type] = 1;
		}
	}
}


static forward_t *
forward_new(name_t *acls, name_t *fwdrs)
{
	forward_t *f;

	f = calloc(1, sizeof(*f));
	if (f == NULL) {
		logit(-1, "cannot allocate memory for forward_t\n");
		goto badforward;
	}

	STAILQ_INIT(&f->f_acls);
	names_to_acllist(acls, &f->f_acls);

	CIRCLEQ_INIT(&f->f_to);
	names_to_fwdlist(fwdrs, &f->f_to);

	return (f);

badforward:
	STAILQ_FREE_LIST(acls, name, n_next, name_free);
	STAILQ_FREE_LIST(fwdrs, name, n_next, name_free);

	return (NULL);
}


static void
names_to_acllist(name_t *names, struct acllisttop *top)
{
	name_t *n, *next;
	acllist_t *a;
	acl_t *acl;

	for (n = names; n != NULL; n = next) {
		next = STAILQ_NEXT(n, n_next);

		if (!strcmp("*", n->n_name)) {
			acl = NULL;
		} else {
			acl = acl_find(n->n_name);
			if (acl == NULL) {
				logit(1, "cannot find acl '%s'\n", n->n_name);
				name_free(n);
				continue;
			}
		}

		/*
		 * Do not need n from here on.
		 */
		name_free(n);

		a = calloc(1, sizeof(*a));
		if (a == NULL) {
			logit(1, "cannot allocate acllist memory\n");
			continue;
		}
		a->acll_acl = acl;
		STAILQ_INSERT_TAIL(top, a, acll_next);
	}
}


static void
names_to_fwdlist(name_t *names, struct fwdlisttop *top)
{
	name_t *n, *next;
	fwdlist_t *f;
	forwarder_t *fwd;

	for (n = names; n != NULL; n = next) {
		next = STAILQ_NEXT(n, n_next);

		fwd = forwarder_find(n->n_name);
		if (fwd == NULL) {
			logit(1, "cannot find forwarder '%s'\n", n->n_name);
			name_free(n);
			continue;
		}

		/*
		 * Do not need n from here on.
		 */
		name_free(n);

		f = calloc(1, sizeof(*f));
		if (f == NULL) {
			logit(1, "cannot allocate fwdlist memory\n");
			continue;
		}
		f->fl_fwd = fwd;
		CIRCLEQ_INSERT_TAIL(top, f, fl_next);
	}
}


static forwarder_t *
forwarder_find(char *name)
{
	forwarder_t *f;

	STAILQ_FOREACH(f, &config.c_forwarders, fr_next) {
		if (!strcmp(f->fr_name, name))
			return (f);
	}

	return (NULL);
}


static void
forward_add(forward_t *forward)
{
	fwdlist_t *fl;

	STAILQ_INSERT_TAIL(&config.c_forwards, forward, f_next);

	fl = CIRCLEQ_FIRST(&forward->f_to);
	if (fl != NULL) {
		forward->f_server = CIRCLEQ_FIRST(&fl->fl_fwd->fr_servers);
	}
	forward->f_fwdr = fl;
}


static void
forwarder_add(forwarder_t *fwdr)
{

	STAILQ_INSERT_TAIL(&config.c_forwarders, fwdr, fr_next);
}


static forwarder_t *
forwarder_new(char *name, hostlist_t *hosts)
{
	hostlist_t *hl, *hltop;
	forwarder_t *fr;
	server_t *s;

	hltop = hosts;

	fr = calloc(1, sizeof(*fr));
	if (fr == NULL) {
		logit(1, "forwarders(%s): cannot allocate memory\n", name);
		goto badnewforwarders;
	}

	CIRCLEQ_INIT(&fr->fr_servers);

	while ((hl = hltop) != NULL) {
		s = calloc(1, sizeof(*s));
		if (s == NULL) {
			logit(1, "forwarder(%s): cannot allocate new server\n",
			      name);
			goto badnewforwarders;
		}
		s->s_ipaddr = hl->hl_ipaddr;
		CIRCLEQ_INSERT_TAIL(&fr->fr_servers, s, s_next);

		hltop = STAILQ_NEXT(hl, hl_next);
		STAILQ_NEXT(hl, hl_next) = NULL;
		hostlist_free(hl);
	}

	fr->fr_name = name;
	return (fr);

badnewforwarders:
	if (fr != NULL) {
		while ((s = CIRCLEQ_FIRST(&fr->fr_servers)) != NULL) {
			CIRCLEQ_REMOVE(&fr->fr_servers, s, s_next);
			free(s);
		}
		free(fr);
	}
	STAILQ_FREE_LIST(hltop, hostlist, hl_next, hostlist_free);
	return (NULL);
}


static char *
rrtype_to_name(int type)
{
	static char buffer[10];
	wordtab_t *w;

	for (w = dnsqtpyes; w->w_word != NULL; w++)
		if (w->w_value == type)
			return (w->w_word);

	(void) snprintf(buffer, sizeof(buffer), "%d", type);

	return (buffer);
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
hosts_dump(struct htop *hosts)
{
	hostlist_t *h;

	STAILQ_FOREACH(h, hosts, hl_next) {
		if ((h->hl_mask.s_addr == 0) && (h->hl_ipaddr.s_addr == 0)) {
			printf("all");
		} else if (h->hl_mask.s_addr == 0xffffffff) {
			printf("%s", inet_ntoa(h->hl_ipaddr));
		} else {
			printf("%s/%d", inet_ntoa(h->hl_ipaddr),
			       countv4bits(h->hl_mask.s_addr));
		}

		if (STAILQ_NEXT(h, hl_next) != NULL)
			putchar(',');
	}
}


static void
rrtypes_dump(u_char *rrarray)
{
	int i, count;

	for (i = 0, count = 0; i < 256; i++) {
		if (rrarray[i] != 0)
			count++;
	}

	if (count == 256) {
		putchar('*');
	} else {
		for (i = 0; i < 256; i++) {
			if (rrarray[i] != 0) {
				printf("%s", rrtype_to_name(i));
				count--;
				if (count > 0)
					putchar(',');
			}
		}
	}
}


void
names_dump(struct ntop *ntop)
{
	name_t *n;

	STAILQ_FOREACH(n, ntop, n_next) {
		printf("%s", n->n_name);
		if (n->n_rrtypes != NULL) {
			putchar('(');
			rrtypes_dump(n->n_rrtypes);
			putchar(')');
		}
		if (STAILQ_NEXT(n, n_next) != NULL)
			putchar(',');
	}
}


void
domains_dump(struct dtop *dtop)
{
	domain_t *d;

	STAILQ_FOREACH(d, dtop, d_next) {
		printf(" %s ", get_action(d->d_pass));
		names_dump(&d->d_names);
		printf(";");
	}
}


void
ports_dump(struct intop *ptop)
{
	inbound_t *in;

	STAILQ_FOREACH(in, ptop, i_next) {
		port_dump(in);
	}
}


void
port_dump(inbound_t *port)
{
	printf("port %s { udp %s,%d;", port->i_name,
	       inet_ntoa(port->i_portspec.sin_addr),
	       ntohs(port->i_portspec.sin_port));
	if (port->i_transparent)
		printf(" transparent on;");
	printf(" };\n");
}


void
forwarders_dump(struct frtop *frtop)
{
	forwarder_t *fr;

	STAILQ_FOREACH(fr, frtop, fr_next) {
		forwarder_dump(fr);
	}
}


char *
qtype_to_name(qtype_t qt)
{
	switch (qt)
	{
	case Q_QUESTION :
		return ("question");
	case Q_NAMESERVER :
		return ("nameserver");
	case Q_ANSWER :
		return ("answer");
	case Q_ADDITIONAL :
		return ("additional");
	default :
		break;
	}

	return ("???");
}


const char *
modopt_print(modopt_t opt)
{
	switch (opt)
	{
	case M_DISABLE :
		return ("disable");
	case M_PRESERVE :
		return ("preserve");
	case M_ENABLE :
		return ("enable");
	}

	return ("???");
}


void
modify_dump(struct mtop *mtop)
{
	acllist_t *a;
	modify_t *m;

	STAILQ_FOREACH(m, mtop, m_next) {
		printf("modify default %s { acls (", qtype_to_name(m->m_type));
		STAILQ_FOREACH(a, &m->m_acls, acll_next) {
			if (a->acll_acl == NULL) {
				putchar('*');
			} else {
				printf("%s", a->acll_acl->acl_name);
			}
			if (STAILQ_NEXT(a, acll_next))
				putchar(',');
		}
		printf("); ");
		printf("recursion %s; ", modopt_print(m->m_recursion));
		printf("keep (");
		rrtypes_dump(m->m_keep);
		printf("); strip (");
		rrtypes_dump(m->m_strip);
		printf("); clean (");
		rrtypes_dump(m->m_clean);
		printf("); };\n");
	}
}


void
forwarder_dump(forwarder_t *fr)
{
	server_t *s;

	printf("forwarder %s {", fr->fr_name);
	CIRCLEQ_FOREACH(s, &fr->fr_servers, s_next) {
		printf(" %s", inet_ntoa(s->s_ipaddr));
		if (s != CIRCLEQ_LAST(&fr->fr_servers))
			putchar(',');
	}
	printf("; };\n");
}


char *
onoff_dump(int onoff)
{

	switch (onoff)
	{
	case 0 :
		return ("off");
	case 1 :
		return ("on");
	case -1 :
		return ("*");
	}

	return ("???");
}


void
acls_dump(struct atop *atop)
{
	inlist_t *il;
	acl_t *a;

	STAILQ_FOREACH(a, atop, acl_next) {
		printf("acl %s {", a->acl_name);
		printf(" source (");
		if (!STAILQ_EMPTY(&a->acl_sources)) {
			hosts_dump(&a->acl_sources);
		} else {
			putchar('*');
		}
		printf("); port (");
		STAILQ_FOREACH(il, &a->acl_ports, il_next) {
			if (il->il_port == NULL) {
				putchar('*');
			} else {
				printf("%s", il->il_port->i_name);
			}
			if (STAILQ_NEXT(il, il_next))
				putchar(',');
		}
		printf("); ");
		printf("recursion %s; ", onoff_dump(a->acl_recursion));
		printf("policy {");
		domains_dump(&a->acl_domains);
		printf(" };\n");
	}
}


void
config_dump()
{
	ports_dump(&config.c_ports);
	acls_dump(&config.c_acls);
	forwarders_dump(&config.c_forwarders);
	modify_dump(&config.c_modifies);
}
