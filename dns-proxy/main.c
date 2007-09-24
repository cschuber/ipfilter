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
#include "ipl.h"
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <fcntl.h>
#include <pwd.h>
#include <arpa/inet.h>

#include "ip_nat.h"

static void	add_qname(qinfo_t *qip, char *name);
static void	add_qtype(qinfo_t *qip, int type);
static void	add_query(inbound_t *in, int buflen);
static void	add_reply(struct sockaddr_in *, char *buffer, int buflen);
static action_t	allow_query(struct sockaddr_in *, char *qname);
static void	build_aio(void);
static action_t	check_answers(struct sockaddr_in *, char *buffer, int buflen);
static void	check_events(void);
static void	check_query(inbound_t *in, int buflen);
static action_t	check_questions(qinfo_t *qip, struct sockaddr_in *,
				char *buffer, int buflen);
static forward_t *choose_forward(struct ftop *ftop, forward_t **currentp,
				 struct sockaddr_in *dst);
static void	do_args(int argc, char *argv[]);
static void	do_query(inbound_t *in);
static void	do_reply(void);
static void	drop_privs(void);
static void	expire_queries(time_t now);
static query_t *find_query(struct sockaddr_in *sin, char *buffer, int buflen);
static action_t	find_query_forward(qinfo_t *qi, struct ftop **top,
				   forward_t ***current);
static void	free_qinfo(qinfo_t *qip);
static int	get_name(void *start, int len, void *buffer, int buflen);
static int	get_transparent(inbound_t *in, struct sockaddr_in *dst);
static void	handle_alarm(int info);
static void	handle_int(int info);
static void	handle_term(int info);
static void	init_ipf(void);
static void	init_signals();
static void	make_background();
static int	match_name(name_t *n, char *query, int qlen);
static action_t match_names(domain_t *d, char *query, int qlen);
static void	process_packets(void);
static query_t	*query_exists(inbound_t *in, int buflen);
static void	send_reject(inbound_t *in, int buflen);
static void	start_logging(char *execname);
static void	usage(char *prog);
static void	write_pid(void);
#ifdef SIGINFO
static void	dump_status(int info);
#endif


config_t	config;


int
main(int argc, char *argv[])
{

	config_init();

	do_args(argc, argv);

	start_logging(argv[0]);

	load_config(config.c_cffile);

	if (config.c_debug)
		dump_config();

	init_ipf();
	init_signals();

	if (!config.c_debug)
		make_background();

	write_pid();

	drop_privs();

	build_aio();

	process_packets();

	exit(0);
}


static void
start_logging(char *execname)
{
	char *prog;

	prog = strrchr(execname, '/');
	if (prog == NULL)
		prog = execname;
	else
		prog++;
	openlog(prog, LOG_PID|LOG_NDELAY, LOG_LOCAL4);
}


static void
do_args(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "df:V")) >= 0) {
		switch (c)
		{
		case 'd' :
			config.c_debug++;
			break;
		case 'f' :
			config.c_cffile = optarg;
			break;
		case 'V' :
			printf("Version 1.0\n");
			exit(0);
		default :
			usage(argv[0]);
			break;
		}
	}
}


static void
usage(char *prog)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "%s [-dV] [-f file]\n", prog);
}


static void
write_pid()
{
	FILE *fp;

	fp = fopen("/var/run/dnsproxy.pid", "w");
	if (fp != NULL) {
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}
}


static void
init_ipf()
{
	inbound_t *in;

	STAILQ_FOREACH(in, &config.c_ports, i_next) {
		if (in->i_transparent) {
			config.c_natfd = open(IPNAT_NAME, O_RDWR);
			if (config.c_natfd == -1) {
				perror("open(/dev/ipnat) failed");
				exit(1);
			}
		}
	}
}


static void
build_aio()
{
	inbound_t *in;

	FD_ZERO(&config.c_mfdr);

	if (config.c_natfd >= 0) {
		if (config.c_natfd > config.c_maxfd)
			config.c_maxfd = config.c_natfd;

		logit(0, "NAT on fd %d set\n", config.c_natfd);
	}

	if (config.c_outfd >= 0) {
		if (config.c_outfd > config.c_maxfd)
			config.c_maxfd = config.c_outfd;
		FD_SET(config.c_outfd, &config.c_mfdr);

		logit(0, "outbound on fd %d set\n", config.c_outfd);
	}

	STAILQ_FOREACH(in, &config.c_ports, i_next) {
		if (in->i_fd >= 0) {
			FD_SET(in->i_fd, &config.c_mfdr);
			if (config.c_maxfd < in->i_fd)
				config.c_maxfd = in->i_fd;
			logit(0, "inbound on fd %d set\n", in->i_fd);
		}
	}

	logit(0, "maxfd set to %d\n", config.c_maxfd);
}


static void
drop_privs()
{
#if 0
	struct passwd *p;

	p = getpwnam("nobody");

	if (p != NULL) {
		if (geteuid() == 0)
			setuid(p->pw_uid);
	}
#endif
}


static void
process_packets()
{
	time_t now, then;

	now = then = time(NULL);

	syslog(LOG_NOTICE, "packet processing starting");
	logit(2, "packet processing starting\n");

	while (1) {

		check_events();

		now = time(NULL);

		if (now - then > 0) {
			expire_queries(now);
		}
	}
}


static void
expire_queries(time_t now)
{
	query_t *q;

	while ((q = STAILQ_FIRST(&config.c_queries)) != NULL) {
		if (q->q_dies > now)
			break;

		STAILQ_REMOVE_HEAD(&config.c_queries, q_next);
		free(q);
	}
}


static void
check_events()
{
	struct timeval tv, *tvp;
	inbound_t *in;
	fd_set rd;
	int nfd;

	rd = config.c_mfdr;

	tv.tv_usec = 0;

	if (STAILQ_EMPTY(&config.c_queries)) {
		tvp = NULL;
	} else {
		query_t *q = STAILQ_FIRST(&config.c_queries);

		tv.tv_sec = q->q_dies - time(NULL);
		tvp = &tv;
	}

	nfd = select(config.c_maxfd + 1, &rd, NULL, NULL, tvp);

	logit(7, "select=%d\n", nfd);

	if (nfd > 0) {
		STAILQ_FOREACH(in, &config.c_ports, i_next) {
			if ((in->i_fd >= 0) && FD_ISSET(in->i_fd, &rd)) {
				logit(7, "active in fd %d\n", in->i_fd);
				do_query(in);
				nfd--;
			}
		}

		if ((nfd > 0) && FD_ISSET(config.c_outfd, &rd)) {
			logit(7, "active out fd %d\n", config.c_outfd);
			do_reply();
		}
	}
	logit(8, "tick\n");
}


static void
do_query(inbound_t *in)
{
	ipf_dns_hdr_t *dns;
	socklen_t slen;
	int n;

	slen = sizeof(in->i_sender);

	n = recvfrom(in->i_fd, in->i_buffer, sizeof(in->i_buffer), 0,
		     (struct sockaddr *)&in->i_sender, &slen);
	if (n > 0) {
		if (n <= sizeof(ipf_dns_hdr_t)) {
			logit(1, "query too short (%d)\n", n);
			return;
		}
		dns = (ipf_dns_hdr_t *)in->i_buffer;

		/*
		 * Check that we received a query on the query side.
		 */
		if (DNS_QR(dns->dns_ctlword)) {
			logit(1, "inbound not a query %x\n",
			      ntohs(dns->dns_ctlword));
			return;
		}

		if (DNS_OPCODE(dns->dns_ctlword) != 0) {
			logit(2, "non-name query, allow\n");
			add_query(in, n);
			return;
		}

		check_query(in, n);
	}
}


static void
do_reply()
{
	struct sockaddr_in sin;
	char buffer[2048];
	socklen_t slen;
	int n;

	slen = sizeof(sin);

	n = recvfrom(config.c_outfd, buffer, sizeof(buffer), 0,
		     (struct sockaddr *)&sin, &slen);
	if (n > 0) {
		add_reply(&sin, buffer, n);
	}
}


static void
check_query(inbound_t *in, int buflen)
{
	action_t rc;

	rc = check_questions(&in->i_qinfo, &in->i_sender, in->i_buffer,
			     buflen);
	switch (rc)
	{
	case Q_NOMATCH :
	case Q_ALLOW :
		add_query(in, buflen);
		break;
	case Q_BLOCK :
		/* Do nothing - just drop the query */
		break;
	case Q_REJECT :
		send_reject(in, buflen);
		break;
	}

	free_qinfo(&in->i_qinfo);
}


static void
free_qinfo(qinfo_t *qip)
{
	int i;

	if (qip->qi_names != NULL) {
		for (i = 0; i < qip->qi_ncount; i++) {
			free(qip->qi_names[i]);
			qip->qi_names[i] = NULL;
		}
		free(qip->qi_names);
	}


	if (qip->qi_qtypes != NULL) {
		free(qip->qi_qtypes);
		qip->qi_qtypes = NULL;
		qip->qi_qtcount = 0;
	}
}


static action_t
check_questions(qinfo_t *qip, struct sockaddr_in *sin, char *buffer, int buflen)
{
	u_short type, class;
	ipf_dns_hdr_t *dns;
	int dlen, len, qc;
	char qname[1024];
	u_char *data;
	action_t rc;

	dns = (ipf_dns_hdr_t *)buffer;

	qc = ntohs(dns->dns_qdcount);
	if (qc == 0) {
		logit(1, "no questions, dropping\n");
		return (Q_BLOCK);
	}

	data = (u_char *)(dns + 1);
	dlen = buflen - sizeof(*dns);

	for (rc = Q_NOMATCH; (dlen > 0) && (qc > 0); qc--) {
		len = get_name(data, dlen, qname, sizeof(qname));
		if (len == 0) {
			logit(1, "zero length name, block\n");
			rc = Q_BLOCK;
			break;
		}
		logit(3, "question name [%s]\n", qname);
		rc = allow_query(sin, qname);
		if (rc != Q_NOMATCH)
			break;
		data += len + 1;
		dlen -= len + 1;
		add_qname(qip, qname);

		type = (data[0] << 8) | data[1];
		data += 2;
		dlen -= 2;
		if (qip != NULL)
			add_qtype(qip, type);

		class = (data[0] << 8) | data[1];
		data += 2;
		dlen -= 2;

		if (class != C_IN) {	/* C_IN = Internet class */
			logit(1, "blocking non-Internet class query\n");
			rc = Q_BLOCK;
			break;
		}
	}

	return (rc);
}


static void
add_qtype(qinfo_t *qip, int type)
{
	int i;

	for (i = 0; i < qip->qi_qtcount; i++)
		if (qip->qi_qtypes[i] == type)
			return;

	qip->qi_qtcount++;

	if (qip->qi_qtypes == NULL) {
		qip->qi_qtypes = malloc(sizeof(*qip->qi_qtypes));
	} else {
		qip->qi_qtypes = realloc(qip->qi_qtypes, qip->qi_qtcount *
					 sizeof(*qip->qi_qtypes));
	}

	qip->qi_qtypes[qip->qi_qtcount - 1] = type;
	logit(3, "Added question for type %d\n", type);
}


static void
add_qname(qinfo_t *qip, char *name)
{
	int i;

	for (i = 0; i < qip->qi_ncount; i++)
		if (!strcasecmp(qip->qi_names[i], name) == 0)
			return;

	qip->qi_ncount++;

	if (qip->qi_names == NULL) {
		qip->qi_names = malloc(sizeof(*qip->qi_names));
	} else {
		qip->qi_names = realloc(qip->qi_names, qip->qi_qtcount *
					 sizeof(*qip->qi_names));
	}

	qip->qi_names[qip->qi_ncount - 1] = strdup(name);
	logit(3, "Added question for name %s\n", name);
}


static action_t
check_answers(struct sockaddr_in *sin, char *buffer, int buflen)
{
	char *data, qname[1024];
	int dlen, len, qc, ac;
	ipf_dns_hdr_t *dns;
	action_t rc;

	dns = (ipf_dns_hdr_t *)buffer;

	qc = ntohs(dns->dns_qdcount);
	data = (char *)(dns + 1);
	dlen = buflen - sizeof(*dns);
	/*
	 * The only way to get to the answers is to go through all
	 * of the questions first.
	 */
	for (; (dlen > 0) && (qc > 0); qc--) {
		len = get_name(data, dlen, qname, sizeof(qname));
		data += len;
		dlen -= len;
	}

	ac = ntohs(dns->dns_ancount);
	if (ac == 0) {
		logit(1, "no answers, dropping\n");
		return (Q_BLOCK);
	}

	for (rc = Q_NOMATCH; (dlen > 0) && (qc > 0); qc--) {
		len = get_name(data, dlen, qname, sizeof(qname));
		if (len == 0) {
			logit(1, "zero length name, block\n");
			return (Q_BLOCK);
		}
		logit(3, "answer name [%s]\n", qname);
		rc = allow_query(sin, qname);
		if (rc != Q_NOMATCH)
			break;
		data += len;
		dlen -= len;
	}

	return (rc);
}


static void
add_query(inbound_t *in, int buflen)
{
	forward_t *f, **current;
	ipf_dns_hdr_t *dns;
	struct ftop *ftop;
	action_t match;
	query_t *q;
	int ok;

	f = NULL;

	match = find_query_forward(&in->i_qinfo, &ftop, &current);
	switch (match)
	{
	case Q_NOMATCH :
		logit(2, "Using default forwarding hosts\n");
		ftop = &config.c_forwards;
		current = &config.c_currentforward;
		break;

	case Q_ALLOW :
		if (CIRCLEQ_EMPTY(ftop)) {
			ftop = &config.c_forwards;
			current = &config.c_currentforward;
		}
		logit(2, "Matched query to forwarder (%d)\n", match);
		break;

	case Q_REJECT :
		logit(2, "Query rejected\n");
		send_reject(in, buflen);
		return;

	case Q_BLOCK :
		logit(2, "Query blocked\n");
		return;
	}

	q = query_exists(in, buflen);
	if (q == NULL) {
		q = calloc(1, sizeof(*q));
		if (q == NULL) {
			logit(1, "malloc failed for new query\n");
			return;
		}
		dns = (ipf_dns_hdr_t *)in->i_buffer;
		q->q_arrived = in;
		q->q_origid = dns->dns_id;
		memcpy(&q->q_src, &in->i_sender, sizeof(q->q_src));
	} else {
		STAILQ_REMOVE(&config.c_queries, q, query, q_next);
	}
	q->q_recvd = time(NULL);
	q->q_dies = q->q_recvd + 180;

	STAILQ_INSERT_TAIL(&config.c_queries, q, q_next);

	ok = -1;

	if (in->i_transparent == 1) {
		ok = get_transparent(in, &q->q_dst);
		if (ok == 0)
			f = choose_forward(ftop, current, NULL);
	}

	if (ok == -1)
		f = choose_forward(ftop, current, &q->q_dst);

	logit(5, "ok %d f %p\n", ok, f);

	if (f != NULL) {
		/*
		 * The query id returned here should become a random number
		 * that is not currently in use.
		 */
		q->q_newid = (u_short)(f->f_sends & 0xffff);
		dns->dns_id = q->q_newid;
		logit(4, "query %d -> %d for %s,%d\n", q->q_origid,
		      q->q_newid, inet_ntoa(in->i_sender.sin_addr),
		      ntohs(in->i_sender.sin_port));
		logit(3, "Query destination %s\n",
		      inet_ntoa(q->q_dst.sin_addr));

		(void) sendto(config.c_outfd, in->i_buffer, buflen, 0,
			      (struct sockaddr *)&q->q_dst, sizeof(q->q_dst));
	}
}


static action_t
find_query_forward(qinfo_t *qi, struct ftop **top, forward_t ***current)
{
	action_t act, act2;
	int i, j, namelen;
	querymatch_t *qm;
	qtypelist_t *qt;
	char *name;
	name_t *n;

	STAILQ_FOREACH(qm, &config.c_qmatches, qm_next) {
		act = Q_NOMATCH;
		for (i = 0; i < qi->qi_qtcount; i++) {
			STAILQ_FOREACH(qt, &qm->qm_types, qt_next) {
				logit(2, "Query type match.%d %d =? %d\n", i,
				      qt->qt_type, qi->qi_qtypes[i]);
				if ((qt->qt_type == qi->qi_qtypes[i]) ||
				    (qi->qi_qtypes[i] == 0)) {
					act = qm->qm_action;
				}
			}
		}

		if ((act == Q_NOMATCH) && (qi->qi_qtcount > 0))
			continue;

		act2 = Q_NOMATCH;

		for (i = 0; i < qi->qi_ncount; i++) {
			STAILQ_FOREACH(n, &qm->qm_names, n_next) {
				name = qi->qi_names[i];
				namelen = strlen(name);

				for (j = 0; j < qi->qi_ncount; j++) {
					switch (match_name(n, name, namelen))
					{
					case 0 :
						act2 = qm->qm_action;
						break;
					default :
						break;
					}
				}
			}
		}

		if ((act2 != Q_NOMATCH) || (qi->qi_ncount == 0)) {
			*top = &qm->qm_forwards;
			*current = &qm->qm_currentfwd;
			break;
		}
	}

	return (Q_NOMATCH);
}


static query_t *
query_exists(inbound_t *in, int buflen)
{
	ipf_dns_hdr_t *dns;
	query_t *q;

	dns = (ipf_dns_hdr_t *)in->i_buffer;

	STAILQ_FOREACH(q, &config.c_queries,  q_next) {
		if ((dns->dns_id == q->q_origid) && (q->q_arrived == in) &&
		    (memcmp(&in->i_sender, &q->q_src, sizeof(q->q_src)) == 0))
			return (q);
	}

	return (NULL);
}


static forward_t *
choose_forward(struct ftop *ftop, forward_t **currentp, struct sockaddr_in *dst)
{
	forward_t *f, *fn;

	f = *currentp;
	logit(5, "choose_forward(%p,%p,%p) f=%p\n", ftop, currentp, dst, f);

	if (f == NULL) {
		fn = CIRCLEQ_FIRST(ftop);
		if (fn == NULL) {
			logit(1, "no forwarders\n");
			return (NULL);
		}
	} else {
		fn = CIRCLEQ_LOOP_NEXT(ftop, f, f_next);
	}
	*currentp = fn;
	fn->f_sends++;

	if (dst != NULL) {
		logit(4, "Found forwarder %s (Use %d)\n",
		      inet_ntoa(fn->f_ipaddr), fn->f_sends);

		dst->sin_family = AF_INET;
		dst->sin_addr = fn->f_ipaddr;
		dst->sin_port = htons(53);
	} else {
		logit(4, "Found forwarder %p %s (Use %d) Not Used\n",
		      fn, inet_ntoa(fn->f_ipaddr), fn->f_sends);
	}

	return (fn);
}


static int
get_transparent(inbound_t *in, struct sockaddr_in *dst)
{
	natlookup_t nat;
	ipfobj_t obj;

	memset(&obj, 0, sizeof(obj));
	obj.ipfo_rev = IPFILTER_VERSION;
	obj.ipfo_size = sizeof(nat);
	obj.ipfo_ptr = &nat;
	obj.ipfo_type = IPFOBJ_NATLOOKUP;

	memset(&nat, 0, sizeof(nat));
	nat.nl_flags = IPN_UDP;
	nat.nl_inip = in->i_portspec.sin_addr;
	nat.nl_inport = in->i_portspec.sin_port;
	nat.nl_outip = in->i_sender.sin_addr;
	nat.nl_outport = in->i_sender.sin_port;

	if (ioctl(config.c_natfd, SIOCGNATL, &obj) != 0) {
		logit(1, "NAT ioctl failed\n");
		return (-1);
	} 
	dst->sin_addr = nat.nl_realip;
	dst->sin_port = nat.nl_realport;
	return (0);
}


static void
add_reply(struct sockaddr_in *sin, char *buffer, int buflen)
{
	ipf_dns_hdr_t *dns;
	forward_t *f;
	query_t *q;

	dns = (ipf_dns_hdr_t *)buffer;

	CIRCLEQ_FOREACH(f, &config.c_forwards, f_next) {
		if (sin->sin_addr.s_addr == f->f_ipaddr.s_addr)
			break;
	}

	if (f == NULL) {
		logit(1, "reply from unknown forwarder %s\n",
		      inet_ntoa(sin->sin_addr));
		return;
	}

	f->f_recvs++;

	q = find_query(sin, buffer, buflen);
	if (q == NULL) {
		logit(1, "cannot find query to match\n");
		return;
	}

	/*
	 * Check that we received a response on the outbound side.
	 */
	if (!DNS_QR(dns->dns_ctlword)) {
		logit(1, "non-response received from outbound side\n");
		return;
	}

	switch (check_questions(NULL, &q->q_src, buffer, buflen))
	{
	case Q_BLOCK :
	case Q_REJECT :
		logit(1, "reply dropped because of question\n");
		return;
	default :
		break;
	}

	switch (check_answers(&q->q_src, buffer, buflen))
	{
	case Q_BLOCK :
	case Q_REJECT :
		logit(1, "reply dropped because of answer\n");
		return;
	default :
		break;
	}

	dns->dns_id = q->q_origid;

	(void) sendto(q->q_arrived->i_fd, buffer, buflen, 0,
		      (struct sockaddr *)&q->q_src, sizeof(q->q_src));

	STAILQ_REMOVE(&config.c_queries, q, query, q_next);
	free(q);
}


static query_t *
find_query(struct sockaddr_in *sin, char *buffer, int buflen)
{
	ipf_dns_hdr_t *dns;
	query_t *q;

	dns = (ipf_dns_hdr_t *)buffer;

	logit(6, "find query %s,%d id %d\n", inet_ntoa(sin->sin_addr),
	      ntohs(sin->sin_port), dns->dns_id);

	STAILQ_FOREACH(q, &config.c_queries, q_next) {
		if (sin->sin_addr.s_addr != q->q_dst.sin_addr.s_addr)
			continue;

		if (q->q_newid != dns->dns_id)
			continue;
		break;
	}

	return (q);
}


void
logit(int level, char *string, ...)
{
	va_list ap;

	if (config.c_debug > level) {
		va_start(ap, string);
		vfprintf(stderr, string, ap);
		va_end(ap);
	}
}


static void
handle_alarm(int info)
{
}


static void
init_signals()
{
	struct sigaction act;

	act.sa_sigaction = NULL;
	act.sa_handler = handle_alarm;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGALRM, &act, NULL);

	signal(SIGINT, handle_int);
	signal(SIGTERM, handle_term);
#ifdef SIGINFO
	signal(SIGINFO, dump_status);
#endif
}


static void
make_background()
{

	/*
	 * This redirects fd 0, 1 and 2 to /dev/null.
	 */
	daemon(1, 0);
}


int
countv4bits(u_int mask)
{
	u_int copy = mask;
	int bits = 0;

	while (copy != 0) {
		if (copy & 1)
			bits++;
		copy >>= 1;
	}
	return (bits);
}


static void
handle_term(int info)
{
	exit(SIGTERM);
}


static void
handle_int(int info)
{
	exit(SIGINT);
}


#ifdef SIGINFO
static void
dump_status(int info)
{
}
#endif


/*
 * 0 = name maches
 * 1 = no match possible
 * -1 = didn't match
 */
static int
match_name(name_t *n, char *query, int qlen)
{
	char *base;
	int blen;

	blen = n->n_namelen;
	base = n->n_name;

	if (blen > qlen)
		return (1);

	if (blen == qlen) {
		if (strncasecmp(base, query, qlen) == 0)
			return (0);
	}

	/*
	 * If the base string string is shorter than the query,
	 * allow the tail of the base to match the same length
	 * tail of the query *if*:
	 * - the base string starts with a '*' (*cnn.com)
	 * - the base string represents a domain (.cnn.com)
	 * as otherwise it would not be possible to block just
	 * "cnn.com" without also impacting "foocnn.com", etc.
	 */
	if (*base == '*') {
		base++;
		blen--;
	} else if (*base != '.')
		return (1);

	if (strncasecmp(base, query + qlen - blen, blen) == 0)
		return (0);

	return (-1);
}

/*
 * Tries to match the base string (in our ACL) with the query from a packet.
 */
static action_t
match_names(domain_t *d, char *query, int qlen)
{
	name_t *n;

	STAILQ_FOREACH(n, &d->d_names, n_next) {
		switch (match_name(n, query, qlen))
		{
		case 0 :
			return 0;
		default :
			break;
		}
	}
	return (1);
}


static int
get_name(void *start, int len, void *buffer, int buflen)
{
	u_char *s, *t, clen;
	int slen, blen;

	s = (u_char *)start;
	t = (u_char *)buffer;
	slen = len;
	blen = buflen - 1;	/* Always make room for trailing \0 */

	if (buflen <= 0) {
		logit(6, "buflen(%d) <= 0\n", buflen);
		return (0);
	}

	if (blen <= 0) {
		logit(6, "blen(%d) <= 0\n", blen);
		*t = '\0';
		return (0);
	}

	while (*s != '\0') {
		clen = *s;
		logit(8, "clen = %d\n", clen);
		if ((clen & 0xc0) == 0xc0) {	/* Doesn't do compression */
			logit(5, "compressed name (%x)\n", clen);
			return (0);
		}

		if (clen > slen) {
			logit(4, "name too long (%d vs %d)\n", clen, slen);
			return (0);	/* Does the name run off the end? */
		}

		if ((clen + 1) > blen) {
			logit(4, "buffer too small (%d vs %d)\n", clen, blen);
			return (0);	/* Enough room for name+.? */
		}

		s++;
		bcopy(s, t, clen);
		t += clen;
		s += clen;
		*t++ = '.';
		slen -= clen;
		blen -= (clen + 1);
	}

	*(t - 1) = '\0';
	return (s - (u_char *)start);
}


static action_t
allow_query(struct sockaddr_in *sin, char *qname)
{
	hostlist_t *h;
	domain_t *d;
	acl_t *a;
	int len;

	len = strlen(qname);

	STAILQ_FOREACH(a, &config.c_acls, acl_next) {
		STAILQ_FOREACH(h, &a->acl_hosts, hl_next) {
			if ((sin->sin_addr.s_addr & h->hl_mask.s_addr) !=
			    h->hl_ipaddr.s_addr)
				continue;
			STAILQ_FOREACH(d, &a->acl_domains, d_next) {
				if (match_names(d, qname, len) == 0)
					return (d->d_pass);
			}
		}
	}
	return (Q_NOMATCH);
}


static void
send_reject(inbound_t *in, int buflen)
{
	ipf_dns_hdr_t *dns;

	logit(2, "rejecting dns query\n");

	dns = (ipf_dns_hdr_t *)in->i_buffer;
	dns->dns_ctlword |= htons(0x8003);	/* Response + name error(3) */

	(void) sendto(in->i_fd, in->i_buffer, buflen, 0,
		      (struct sockaddr *)&in->i_sender, sizeof(in->i_sender));
}
