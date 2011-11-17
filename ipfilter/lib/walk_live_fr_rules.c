#include "ipf.h"
#include "ipl.h"

extern int ipf_fd;

void
walk_live_fr_rules(ticks, out, set, group, walker)
	u_long ticks;
	int out, set;
	char *group;
	ipf_fr_walk_func_t walker;
{
	struct frentry fb;
	ipfruleiter_t rule;
	frentry_t zero;
	frentry_t *fp;
	frgroup_t *g;
	ipfobj_t obj;
	int n;

	n = 0;

	rule.iri_inout = out;
	rule.iri_active = set;
	rule.iri_rule = &fb;
	rule.iri_nrules = 1;
	if (group != NULL)
		strncpy(rule.iri_group, group, FR_GROUPLEN);
	else
		rule.iri_group[0] = '\0';

	bzero((char *)&zero, sizeof(zero));

	bzero((char *)&obj, sizeof(obj));
	obj.ipfo_rev = IPFILTER_VERSION;
	obj.ipfo_type = IPFOBJ_IPFITER;
	obj.ipfo_size = sizeof(rule);
	obj.ipfo_ptr = &rule;

	do {
		u_long array[1000];

		memset(array, 0xff, sizeof(array));
		fp = (frentry_t *)array;
		rule.iri_rule = fp;
		if (ioctl(ipf_fd, SIOCIPFITER, &obj) == -1) {
			ipferror(ipf_fd, "ioctl(SIOCIPFITER)");
			n = IPFGENITER_IPF;
			(void) ioctl(ipf_fd,SIOCIPFDELTOK, &n);
			return;
		}
		if (bcmp(fp, &zero, sizeof(zero)) == 0)
			break;
#ifdef USE_INET6
		if (use_inet6 != 0) {
			if (fp->fr_family != 0 && fp->fr_family != AF_INET6)
				continue;
		} else
#endif
		{
		if (fp->fr_family != 0 && fp->fr_family != AF_INET)
			continue;
		}
		if (fp->fr_data != NULL)
			fp->fr_data = (char *)fp + fp->fr_size;
		if (fp->fr_die != 0)
			fp->fr_die -= ticks;
		walker(fp);
	} while (fp->fr_next != NULL);

	n = IPFOBJ_IPFITER;
	(void) ioctl(ipf_fd,SIOCIPFDELTOK, &n);

}
