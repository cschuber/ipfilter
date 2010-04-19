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

#ifndef NO_IPFILTER
#include "ip_nat.h"
#endif

static acl_t	*acl_determine(inbound_t *in, qinfo_t *qip);
static query_t	*add_query(inbound_t *in, qinfo_t *qip, int buflen);
static void	add_reply(struct sockaddr_in *, char *buffer, int buflen);
static void	build_aio(void);
static action_t	check_answers(query_t *, qinfo_t *, void *buffer);
static void	check_events(void);
static void	check_query(inbound_t *in, int buflen);
static action_t	check_questions(qinfo_t *qip, struct sockaddr_in *,
				char *buffer, int buflen);
static void	do_args(int argc, char *argv[]);
static void	do_query(inbound_t *in);
static void	do_reply(void);
static void	drop_privs(void);
static void	expire_queries(time_t now);
static query_t *find_query(struct sockaddr_in *sin, char *buffer, int buflen);
static int	get_name(void *, void *, int, void *, int);
static int	get_transparent(inbound_t *in, struct sockaddr_in *dst);
static void	handle_alarm(int info);
static void	handle_int(int info);
static void	handle_term(int info);
static void	init_ipf(void);
static void	init_signals();
static void	make_background();
static	void	modify_apply(modify_t *m, qinfo_t *qip, qrec_t *qr);
static void	modify_packet(qinfo_t *qip);
static int	name_match(name_t *n, char *query, int qlen);
static void	process_packets(void);
static int	qinfo_build(qinfo_t *qip);
static int	name_qrec_match(name_t *name, qrec_t *qr);
static query_t	*query_exists(inbound_t *in, int buflen);
static int	query_validate(inbound_t *in, int buflen);
static void	send_reject(inbound_t *in, int buflen);
static void	start_logging(char *execname);
static void	usage(char *prog);
static void	write_pid(void);
static action_t	time_ok(timeset_t *tset);
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
		config_dump();

	init_ipf();
	init_signals();

	if (!config.c_debug)
		make_background();

	write_pid();

	if (!config.c_keepprivs)
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

	while ((c = getopt(argc, argv, "dkf:V")) >= 0) {
		switch (c)
		{
		case 'd' :
			config.c_debug++;
			break;
		case 'f' :
			config.c_cffile = optarg;
			break;
		case 'k' :
			config.c_keepprivs = 1;
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
#ifndef NO_IPFILTER
	inbound_t *in;

	STAILQ_FOREACH(in, &config.c_ports, i_next) {
		if (in->i_transparent && (config.c_natfd < 0)) {
			config.c_natfd = open(IPNAT_NAME, O_RDWR);
			if (config.c_natfd == -1) {
				perror("open(/dev/ipnat) failed");
				exit(1);
			}
		}
	}
#endif
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
	struct passwd *p;

	p = getpwnam("nobody");

	if (p != NULL) {
		if (geteuid() == 0)
			setuid(p->pw_uid);
	} else {
		if (geteuid() == 0)
			setuid(65534);
	}
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
		query_free(q);
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
				logit(5, "active in fd %s/%d\n",
				      in->i_name, in->i_fd);
				do_query(in);
				nfd--;
			}
		}

		if ((nfd > 0) && FD_ISSET(config.c_outfd, &rd)) {
			logit(5, "active out fd %d\n", config.c_outfd);
			do_reply();
		}
	}
	logit(8, "tick\n");
}


static void
do_query(inbound_t *in)
{
	socklen_t slen;
	int n;

	slen = sizeof(in->i_sender);

	n = recvfrom(in->i_fd, in->i_buffer, sizeof(in->i_buffer), 0,
		     (struct sockaddr *)&in->i_sender, &slen);

	if (query_validate(in, n) == 0)
		check_query(in, n);
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


static int
query_validate(inbound_t *in, int len)
{
	dns_hdr_t *dns;

	if (len <= sizeof(dns_hdr_t)) {
		logit(1, "query too short (%d)\n", len);
		return (-1);
	}

	dns = (dns_hdr_t *)in->i_buffer;

	switch (DNS_OPCODE(dns->dns_ctlword))
	{
	case NS_NOTIFY_OP :
		logit(1, "inbound query for notify - dropping\n");
		return (-1);
	case NS_UPDATE_OP :
		logit(1, "inbound query for update - dropping\n");
		return (-1);
	case STATUS :
		logit(1, "inbound query for status - dropping\n");
		return (-1);
	case IQUERY :
	case QUERY :
	default :
		break;
	}

	/*
	 * Check that we received a query on the query side.
	 */
	if (DNS_QR(dns->dns_ctlword)) {
		logit(1, "inbound not a query %x - dropping\n",
		      ntohs(dns->dns_ctlword));
		return (-1);
	}

	if (dns->dns_ancount) {
		logit(1, "query from %s with answers %d - dropping\n",
		      inet_ntoa(in->i_sender.sin_addr),
		      ntohs(dns->dns_ancount));
		return (-1);
	}
	if (dns->dns_nscount) {
		logit(1, "query from %s with servers %d - dropping\n",
		      inet_ntoa(in->i_sender.sin_addr),
		      ntohs(dns->dns_nscount));
		return (-1);
	}
	if (dns->dns_arcount) {
		logit(1, "query from %s with additional %d - dropping\n",
		      inet_ntoa(in->i_sender.sin_addr),
		      ntohs(dns->dns_arcount));
		return (-1);
	}

	return (0);
}


/*
 * Check what to do with a DNS query
 */
static void
check_query(inbound_t *in, int buflen)
{
	qinfo_t *qip;
	action_t rc;
	acl_t *acl;
	query_t *q;

	qip = qinfo_alloc(in->i_buffer, buflen);
	if (qip == NULL)
		return;

	if (qinfo_build(qip) == -1) {
		logit(2, "qinfo_build failed - blocking\n");
		qinfo_free(qip);
		return;
	}

	acl = acl_determine(in, qip);
	if (acl == NULL) {
		rc = Q_BLOCK;
	} else {
		rc = time_ok(acl->acl_times);
	}
	if (rc == Q_ALLOW)
		rc = check_questions(qip, &in->i_sender, in->i_buffer, buflen);

	logit(6, "check_query acl %p rc %d\n", acl, rc);

	switch (rc)
	{
	case Q_NOMATCH :
	case Q_ALLOW :
		q = add_query(in, qip, buflen);
		if (q != NULL) {
			q->q_acl = acl;
			q->q_info = qip;
			qip = NULL;
		}
		break;
	case Q_BLOCK :
		/* Do nothing - just drop the query */
		break;
	case Q_REJECT :
		send_reject(in, buflen);
		break;
	}

	if (qip != NULL)
		qinfo_free(qip);
}


/*
 * Find a matching acl_t.
 * Need to check:
 * - list of ports associated with the acl
 * - the source addresses allowed by the acl
 * - the list of names in the policy section has at least one match
 *   with the questions in the packet.
 */
static acl_t *
acl_determine(inbound_t *in, qinfo_t *qip)
{
	int block, pass, reject, nomatch;
	struct sockaddr_in *sin;
	hostlist_t *hl;
	inlist_t *il;
	domain_t *d;
	qrec_t *qr;
	name_t *n;
	acl_t *a;

	sin = &in->i_sender;
	nomatch = 0;
	reject = 0;
	block = 0;
	pass = 0;

	STAILQ_FOREACH(a, &config.c_acls, acl_next) {
		if ((a->acl_recursion >= 0) &&
		    (a->acl_recursion != qip->qi_recursion))
			continue;

		STAILQ_FOREACH(il, &a->acl_ports, il_next) {
			if ((il->il_port == NULL) || (il->il_port == in))
				break;
		}
		if (il == NULL)
			continue;

		STAILQ_FOREACH(hl, &a->acl_sources, hl_next) {
			if ((sin->sin_addr.s_addr & hl->hl_mask.s_addr) ==
			    hl->hl_ipaddr.s_addr)
				break;
		}
		if (hl == NULL)
			continue;

		STAILQ_FOREACH(qr, &qip->qi_recs, qir_next) {
			if (qr->qir_qtype != Q_QUESTION)
				continue;

			STAILQ_FOREACH(d, &a->acl_domains, d_next) {
				STAILQ_FOREACH(n, &d->d_names, n_next) {
					if (name_qrec_match(n, qr) == 0) {
						switch (d->d_pass)
						{
						case Q_REJECT :
							reject++;
							break;
						case Q_BLOCK :
							block++;
							break;
						case Q_ALLOW :
							pass++;
							break;
						case Q_NOMATCH :
							nomatch++;
							break;
						default :
							break;
						}
					}
					if (reject || block || pass || nomatch)
						break;
				}
				if (reject || block || pass || nomatch)
					break;
			}

			if (reject > 0) {
				qip->qi_result = Q_REJECT;
				return (a);
			}
			if (block > 0) {
				qip->qi_result = Q_BLOCK;
				return (a);
			}
			if (pass > 0) {
				qip->qi_result = Q_ALLOW;
				return (a);
			}
			if (nomatch > 0) {
				nomatch = 0;
			}
		}
	}

	return (NULL);
}


static int
name_qrec_match(name_t *name, qrec_t *qr)
{
	int rc;

	logit(9, "name_qrec_match(%s,%s)\n", name->n_name, qr->qir_name);

	if (name->n_rrtypes != NULL) {
		if (name->n_rrtypes[qr->qir_rrtype] == 0) {
			logit(9, "name_qrec_match: ignore rrtype %d\n",
			      qr->qir_rrtype);
			return (-1);
		}
	}
	rc = name_match(name, qr->qir_name, strlen(qr->qir_name));
	printf("rc = %d\n", rc);
	return (rc);
}


/*
 * Process the packet and store all of the records on qip.
 * XXX - TODO: decompress names
 */
static int
qinfo_build(qinfo_t *qip)
{
	int dlen, len, count, rdlen;
	dns_hdr_t *dns;
	char qname[1024];
	u_char *data;
	qtype_t qt;
	qrec_t *qr;

	dns = qip->qi_dns;

	if (config.c_debug > 8) {
		printf("opcode %x rcode %x\n",
		DNS_OPCODE(dns->dns_ctlword), DNS_RCODE(dns->dns_ctlword));
		hex_dump(qip->qi_buffer, qip->qi_buflen);
	}

	if (DNS_RD(dns->dns_ctlword))
		qip->qi_recursion = 1;

	count = ntohs(dns->dns_qdcount);
	qt = Q_QUESTION;
	data = (u_char *)(dns + 1);
	dlen = qip->qi_buflen - sizeof(*dns);

	while (dlen > 0) {
		if (count == 0) {
			switch (qt)
			{
			case Q_QUESTION :
				count = ntohs(dns->dns_ancount);
				qt = Q_ANSWER;
				break;

			case Q_ANSWER :
				count = ntohs(dns->dns_nscount);
				qt = Q_NAMESERVER;
				break;

			case Q_NAMESERVER :
				count = ntohs(dns->dns_arcount);
				qt = Q_ADDITIONAL;
				break;

			case Q_ADDITIONAL :
			default :
				/*
				 * Force the while loop to exit.
				 */
				dlen = 0;
				break;
			}
			continue;
		}

		count--;

		qr = calloc(1, sizeof(*qr));
		if (qr == NULL) {
			logit(1, "cannot allocate qrec_t\n");
			goto badqbuild;
		}

		qr->qir_qtype = qt;
		STAILQ_INSERT_TAIL(&qip->qi_recs, qr, qir_next);

		memset(qname, 0, sizeof(qname));
		len = get_name(qip->qi_buffer, data, dlen,
			       qname, sizeof(qname));

		qr->qir_data = data;
		qr->qir_name = strdup(qname);
		if (qr->qir_name == NULL) {
			logit(1, "cannot allocate qret_t name(%s)\n", qname);
			goto badqbuild;
		}

		data += len;
		dlen -= len;

		qr->qir_rrtype = (data[0] << 8) | data[1];
		data += 2;
		dlen -= 2;

		qr->qir_class = (data[0] << 8) | data[1];

		logit(3, "%d.question name [%s] len %d, dlen %d rr %d cl %d\n",
		      qt, qname, len, dlen, qr->qir_rrtype, qr->qir_class);

		if (qr->qir_class != C_IN) {
			logit(2, "blocking non-Internet class(%d/%s) query\n",
			      qr->qir_class, qr->qir_name);
			goto badqbuild;
		}
		data += 2;
		dlen -= 2;

		switch (qt)
		{
		case Q_QUESTION :
		default :
			break;
		case Q_ANSWER :
		case Q_NAMESERVER :
		case Q_ADDITIONAL :
			qr->qir_ttl = (data[0] << 24) | (data[1] << 16) |
				      (data[2] << 8) | (data[3]);
			data += 4;	/* TTL */
			dlen -= 4;

			rdlen = (data[0] << 8) | data[1];
			qr->qir_rdlen = rdlen;
			data += 2;
			dlen -= 2;

			qr->qir_rdata = data;
			data += rdlen;
			dlen -= rdlen;
			break;
		}
	}

	return (0);

badqbuild:
	while ((qr = STAILQ_FIRST(&qip->qi_recs)) != NULL) {
		STAILQ_REMOVE_HEAD(&qip->qi_recs, qir_next);
		qrec_free(qr);
	}
	return (-1);
}


static action_t
check_questions(qinfo_t *qip, struct sockaddr_in *sin, char *buffer, int buflen)
{
	dns_hdr_t *dns;
	action_t rc;
	qrec_t *qr;

	dns = (dns_hdr_t *)buffer;
	rc = Q_NOMATCH;

	if (ntohs(dns->dns_qdcount) == 0) {
		logit(1, "no questions, dropping\n");
		return (Q_BLOCK);
	}

	STAILQ_FOREACH(qr, &qip->qi_recs, qir_next) {
		if (qr->qir_qtype != Q_QUESTION)
			continue;
		if ((qr->qir_name == NULL) || (*qr->qir_name == '\0')) {
			logit(2, "blocking zero-length name for %d/%d\n",
			      qr->qir_qtype, qr->qir_class);
			rc = Q_BLOCK;
			break;
		}
	}

	return (rc);
}


static action_t
check_answers(query_t *q, qinfo_t *qip, void *buffer)
{
	dns_hdr_t *dns;
	action_t rc;
	qrec_t *qr, *qra;

	rc = Q_NOMATCH;
	dns = (dns_hdr_t *)buffer;

	if ((dns->dns_ancount == 0) && (DNS_RCODE(dns->dns_ctlword) == 0)) {
		/*
		 * If there are no answers, allow the reply if nameservers
		 * are present and recursion is disabled.
		 */
		if (!DNS_RD(dns->dns_ctlword) && (dns->dns_nscount != 0)) {
			;
		} else {
			STAILQ_FOREACH(qr, &qip->qi_recs, qir_next) {
				if (qr->qir_rrtype == T_CNAME)
					break;
			}

#if 0
			if (qr == NULL) {
				logit(1, "no answers, dropping\n");
				rc = Q_BLOCK; 
				goto escapecheckanswers;
			}
#endif
		}
	}

	/*
	 * Make sure that the questions in the query and reply match up 1:1
	 */
	STAILQ_FOREACH(qr, &qip->qi_recs, qir_next) {
		if (qr->qir_qtype != Q_QUESTION)
			continue;

		STAILQ_FOREACH(qra, &q->q_info->qi_recs, qir_next) {
			if (qra->qir_qtype != Q_QUESTION)
				continue;
			if (!strcmp(qra->qir_name, qr->qir_name)) {
				qra->qir_qtype = Q_MATCHED;
				qr->qir_qtype = Q_MATCHED;
				break;
			}
		}

		if (qr->qir_qtype != Q_MATCHED) {
			logit(2, "reply question %s not in query\n",
				qr->qir_name);
			rc = Q_BLOCK;
			goto escapecheckanswers;
		}
	}

	STAILQ_FOREACH(qra, &q->q_info->qi_recs, qir_next) {
		if (qra->qir_qtype == Q_QUESTION) {
			logit(2, "query question %s not in reply\n",
				qra->qir_name);
			rc = Q_BLOCK;
			break;
		}
	}

escapecheckanswers:
	return (rc);
}


static server_t *
server_determine(qinfo_t *qip)
{
	fwdlist_t *fl;
	acllist_t *al;
	forward_t *f;
	server_t *s;

	STAILQ_FOREACH(f, &config.c_forwards, f_next) {
		STAILQ_FOREACH(al, &f->f_acls, acll_next) {
			if (al->acll_acl == qip->qi_acl)
				break;
		}

		/*
		 * Only stop if we have an ACL match that has a server.
		 */
		if ((al != NULL) && (f->f_server != NULL))
			break;
	}

	if (f == NULL)
		return (NULL);

	s = f->f_server;

	fl = f->f_fwdr;

	if (s == CIRCLEQ_LAST(&fl->fl_fwd->fr_servers)) {
		f->f_fwdr = CIRCLEQ_LOOP_NEXT(&f->f_to, fl, fl_next);
		f->f_server = CIRCLEQ_FIRST(&fl->fl_fwd->fr_servers);
	} else {
		f->f_server = CIRCLEQ_LOOP_NEXT(&fl->fl_fwd->fr_servers,
						s, s_next);
	}

	return (s);
}


static query_t *
add_query(inbound_t *in, qinfo_t *qip, int buflen)
{
	dns_hdr_t *dns;
	server_t *s;
	query_t *q;
	int ok;

	s = NULL;

	q = query_exists(in, buflen);
	if (q == NULL) {
		q = calloc(1, sizeof(*q));
		if (q == NULL) {
			logit(1, "malloc failed for new query\n");
			return (NULL);
		}
		dns = (dns_hdr_t *)in->i_buffer;
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
	if (in->i_transparent == 1)
		ok = get_transparent(in, &q->q_dst);

	if (ok == -1) {
		s = server_determine(qip);
		if (s == NULL) {
			logit(1, "no server for the query\n");
			query_free(q);
			return (NULL);
		}

		q->q_dst.sin_addr = s->s_ipaddr;
		q->q_dst.sin_port = htons(53);
		ok = 0;
	}

	q->q_dst.sin_family = AF_INET;
	logit(5, "ok %d s %p\n", ok, s);

	if (s != NULL) {
		/*
		 * The query id returned here should become a random number
		 * that is not currently in use.
		 */
		q->q_newid = (u_short)(s->s_sends & 0xffff);
		dns->dns_id = q->q_newid;
		logit(4, "query %d -> %d for %s,%d\n", q->q_origid,
		      q->q_newid, inet_ntoa(in->i_sender.sin_addr),
		      ntohs(in->i_sender.sin_port));
	}

	modify_packet(qip);

	if (config.c_debug > 9)
		hex_dump(in->i_buffer, buflen);

	ok = sendto(config.c_outfd, in->i_buffer, buflen, 0,
		    (struct sockaddr *)&q->q_dst, sizeof(q->q_dst));
	logit(3, "Query destination %s = %d (%d)\n",
	      inet_ntoa(q->q_dst.sin_addr), ok, errno);

	if ((s != NULL) && (ok != buflen))
		s->s_errors++;

	return (q);
}


query_t *
query_exists(inbound_t *in, int buflen)
{
	dns_hdr_t *dns;
	query_t *q;

	dns = (dns_hdr_t *)in->i_buffer;

	STAILQ_FOREACH(q, &config.c_queries,  q_next) {
		if ((dns->dns_id == q->q_origid) && (q->q_arrived == in) &&
		    (memcmp(&in->i_sender, &q->q_src, sizeof(q->q_src)) == 0))
			return (q);
	}

	return (NULL);
}


static int
get_transparent(inbound_t *in, struct sockaddr_in *dst)
{
#ifndef NO_IPFILTER
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
#else
	return (-1);
#endif
}


static void
add_reply(struct sockaddr_in *sin, char *buffer, int buflen)
{
	dns_hdr_t *dns;
	forwarder_t *fr;
	qinfo_t *qip;
	server_t *s;
	query_t *q;
	int ok;

	if (buflen <= sizeof(dns_hdr_t))
		return;

	dns = (dns_hdr_t *)buffer;

	STAILQ_FOREACH(fr, &config.c_forwarders, fr_next) {
		CIRCLEQ_FOREACH(s, &fr->fr_servers, s_next) {
			if (sin->sin_addr.s_addr == s->s_ipaddr.s_addr)
				break;
		}

		if (s != NULL)
			break;
	}

	if (s == NULL) {
		logit(1, "reply from unknown forwarder %s\n",
		      inet_ntoa(sin->sin_addr));
		return;
	}

	s->s_recvs++;

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

	qip = qinfo_alloc(buffer, buflen);
	if (qip == NULL) {
		logit(1, "cannot allocate memory for qinfo_t, blocking\n");
		return;
	}
	if (qinfo_build(qip) == -1) {
		logit(2, "qinfo_build failed - blocking\n");
		qinfo_free(qip);
		return;
	}

	switch (check_questions(qip, &q->q_src, buffer, buflen))
	{
	case Q_BLOCK :
	case Q_REJECT :
		logit(1, "reply dropped because of question\n");
		goto answersdone;
	default :
		break;
	}

	switch (check_answers(q, qip, buffer))
	{
	case Q_BLOCK :
	case Q_REJECT :
		logit(1, "reply dropped because of answer\n");
		goto answersdone;
	default :
		break;
	}

	modify_packet(qip);

	dns->dns_id = q->q_origid;

	if (config.c_debug > 9)
		hex_dump(buffer, buflen);

	ok = sendto(q->q_arrived->i_fd, buffer, buflen, 0,
		    (struct sockaddr *)&q->q_src, sizeof(q->q_src));

	if (ok != buflen)
		q->q_arrived->i_errors++;

answersdone:
	STAILQ_REMOVE(&config.c_queries, q, query, q_next);
	query_free(q);
	qinfo_free(qip);
}


static query_t *
find_query(struct sockaddr_in *sin, char *buffer, int buflen)
{
	dns_hdr_t *dns;
	query_t *q;

	dns = (dns_hdr_t *)buffer;

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


static void
modify_packet(qinfo_t *qip)
{
	acllist_t *a;
	modify_t *m;
	qrec_t *qr;
	dns_hdr_t *dns;

	dns = qip->qi_dns;

	STAILQ_FOREACH(qr, &qip->qi_recs, qir_next) {
		if (qr->qir_qtype == Q_MATCHED) {
			/*
			 * Convert MATCHED back to QUESTION
			 */
			qr->qir_qtype = Q_QUESTION;
		}
	}

	STAILQ_FOREACH(m, &config.c_modifies, m_next) {
		STAILQ_FOREACH(qr, &qip->qi_recs, qir_next) {
			if (m->m_type == qr->qir_qtype) {
				STAILQ_FOREACH(a, &m->m_acls, acll_next) {
					if ((a->acll_acl == NULL) ||
					    (a->acll_acl == qip->qi_acl))
						break;
				}

				if (a != NULL)
					modify_apply(m, qip, qr);
			}
		}
	}
}


void
modify_apply(modify_t *m, qinfo_t *qip, qrec_t *qr)
{
	dns_hdr_t *dns = qip->qi_dns;

	switch (m->m_recursion)
	{
	case M_DISABLE :
		dns->dns_ctlword &= htons(0xfe7f);
		break;
	case M_PRESERVE :
		break;
	case M_ENABLE :
		dns->dns_ctlword |= htons(0x0100);
		break;
	}

	if (m->m_keep[qr->qir_rrtype]) {
		;
	} else if (m->m_clean[qr->qir_rrtype]) {
		if (qr->qir_rdlen > 0) {
			memset(qr->qir_rdata, 0,
			       qr->qir_rdlen);;
		}
		if ((*qr->qir_data & 0xc0) == 0xc0) {
			/* Find a \0 to point to */
			;
		} else {
			memset(qr->qir_data + 1, 0,
			       *qr->qir_data);
			memset(qr->qir_name, 0,
			       strlen(qr->qir_name));
		}
	} else if (m->m_strip[qr->qir_rrtype]) {
		;
	}
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
name_match(name_t *n, char *query, int qlen)
{
	char *base;
	int blen;

	blen = n->n_namelen;
	base = n->n_name;

	if (blen > qlen)
		return (1);

	if (blen == 1 && *base == '*')
		return (0);

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


static int
get_name(void *base, void *start, int len, void *buffer, int buflen)
{
	u_char *s, *t, clen, *from;
	int slen, blen, pos;

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

	if (*s == '\0') {
		snprintf(buffer, buflen, ".");
		return (1);
	}

	while (*s != '\0') {
		clen = *s;
		logit(8, "clen %d slen %d blen %d\n", clen, slen, blen);

		if ((clen & 0xc0) == 0xc0) {
			if (slen < 2) {
				logit(3, "not enough room for compression\n");
				return (0);
			}
			pos = ((s[0] & 0x3f) << 8) | s[1];

			logit(5, "compressed name (%d)\n", pos);

			if (pos > (u_char *)start - (u_char *)base + len) {
				logit(3, "name beyond end of packet\n");
				return (0);
			}

			from = (u_char *)base + pos;
			clen = *(from + 1);
			s += 2;
			slen -= 2;
			(void) get_name(base, from,
				        len - ((char *)from - (char *)start),
				        t, blen);
			return (2);
		} else {
			if (clen > slen) {
				logit(4, "name too long (%d vs %d)\n",
				      clen, slen);
				/* Does the name run off the end? */
				return (0);
			}

			if ((clen + 1) > blen) {
				logit(4, "buffer too small (%d vs %d)\n",
				      clen, blen);
				return (0);	/* Enough room for name+.? */
			}

			s++;
			from = s;
			s += clen;
			slen -= clen;
		}
		bcopy(from, t, clen);
		t += clen;
		*t++ = '.';
		blen -= (clen + 1);
	}

	/*
	 * Most include the trailing \0! in space we've looked at.
	 */
	s++;
	*(t - 1) = '\0';
	return (s - (u_char *)start);
}


static void
send_reject(inbound_t *in, int buflen)
{
	dns_hdr_t *dns;

	logit(2, "rejecting dns query\n");

	dns = (dns_hdr_t *)in->i_buffer;
	dns->dns_ctlword |= htons(0x8003);	/* Response + name error(3) */

	if (config.c_debug > 9)
		hex_dump(in->i_buffer, buflen);

	(void) sendto(in->i_fd, in->i_buffer, buflen, 0,
		      (struct sockaddr *)&in->i_sender, sizeof(in->i_sender));
}


/*
 * Return 0 if the time is ok, -1 if it is not.
 */
static action_t
time_ok(timeset_t *tset)
{
	timeentry_t *ent;
	struct tm *tm;
	time_t now;

	if (tset == NULL)
		return (Q_ALLOW);	/* Nothing to enforce = ok */

	now = time(NULL);
	tm = localtime(&now);

	STAILQ_FOREACH(ent, &tset->ts_entries, te_next) {
		if (ent->te_days[tm->tm_wday] == 0)
			continue;
		if (tm->tm_hour < ent->te_start_hour)
			continue;
		if (tm->tm_min < ent->te_start_min)
			continue;
		if (tm->tm_hour > ent->te_end_hour)
			continue;
		if (tm->tm_min > ent->te_end_min)
			continue;
		return (Q_ALLOW);
	}

	return (Q_BLOCK);
}
