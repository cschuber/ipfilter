#include "hdr.h"

void
name_free(name_t *name)
{

	if (name->n_name != NULL)
		free(name->n_name);
	if (name->n_rrtypes != NULL)
		free(name->n_rrtypes);
	free(name);
}

void
rrtop_free(struct rrtop *rrtop)
{
	rrlist_t *rr;

	while ((rr = STAILQ_FIRST(rrtop)) != NULL) {
		STAILQ_REMOVE_HEAD(rrtop, rr_next);            
		free(rr);
	}

	free(rrtop);
}


void
inlist_free(struct iltop *top)
{
	inlist_t *il;

	while ((il = STAILQ_FIRST(top)) != NULL) {
		STAILQ_REMOVE_HEAD(top, il_next);
		free(il);
	}
}


void
hosttop_free(struct htop *top)
{
	hostlist_t *h;

	while ((h = STAILQ_FIRST(top)) != NULL) {
		STAILQ_REMOVE_HEAD(top, hl_next);
		hostlist_free(h);
	}
}


void
domaintop_free(struct dtop *top)
{
	domain_t *d;

	while ((d = STAILQ_FIRST(top)) != NULL) {
		STAILQ_REMOVE_HEAD(top, d_next);
		domain_free(d);
	}
}


void
acl_free(acl_t *a)
{
	hosttop_free(&a->acl_sources);
	inlist_free(&a->acl_ports);
	domaintop_free(&a->acl_domains);
	free(a->acl_name);
	free(a);
}


void
hostlist_free(hostlist_t *host)
{
	free(host);
}


void
domain_free(domain_t *dom)
{
	name_t *n;

	while ((n = STAILQ_FIRST(&dom->d_names)) != NULL) {
		STAILQ_REMOVE_HEAD(&dom->d_names, n_next);
		name_free(n);
	}
	free(dom);
}


void
dtop_free(struct dtop *top)
{
	domain_t *d;

	while ((d = STAILQ_FIRST(top)) != NULL) {
		domain_free(d);
	}
}


void
qrec_free(qrec_t *qir)
{
	if (qir->qir_name != NULL)
		free(qir->qir_name);
	free(qir);
}


void
qinfo_free(qinfo_t *qi)
{
	qrec_t *qr;

	while ((qr = STAILQ_FIRST(&qi->qi_recs)) != NULL) {
		STAILQ_REMOVE_HEAD(&qi->qi_recs, qir_next);
		qrec_free(qr);
	}

	free(qi);
}


qinfo_t *
qinfo_alloc(void *buffer, size_t buflen)
{
	qinfo_t *qip;

	qip = calloc(1, sizeof(*qip));
	if (qip == NULL) {
                logit(1, "could not allocate qinfo_t structure\n");
		return (NULL);
	}

	qip->qi_buffer = buffer;
	qip->qi_buflen = buflen;
	qip->qi_dns = (dns_hdr_t *)buffer;

	STAILQ_INIT(&qip->qi_recs);
	return (qip);
}


void
query_free(query_t *q)
{

	if (q->q_info != NULL)
		qinfo_free(q->q_info);
	free(q);
}


void
hex_dump(void *buffer, size_t buflen)
{
	u_char *s, *t;
	int len, i, j;

	s = buffer;
	len = buflen;

	while (len > 0) {
		for (t = s, i = len, j = 16; (j > 0) && (i > 0); i--, j--) {
			fprintf(stderr, "%02x", *t++);
			if (j > 1)
				fputc(' ',stderr);
		}
		for (; j > 1; j--)
			fprintf(stderr, "   ");
		if (j == 1)
			fprintf(stderr, "  ");
		fprintf(stderr, "\t");
		for (t = s, i = len, j = 16; (j > 0) && (i > 0); i--, j--) {
			if (*t >= 0x20 && *t <= 0x7f)
				fputc(*t, stderr);
			else
				fputc('.', stderr);
			t++;
		}
		fprintf(stderr, "\n");

		len -= t - s;
		s = t;
	}
}
