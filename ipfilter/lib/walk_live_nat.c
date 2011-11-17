#include "ipf.h"
#include "ipl.h"

extern int ipnat_fd;

void
walk_live_nat(ticks, filter, walker)
	u_long ticks;
	int *filter;
	ipf_nat_t_walk_func_t walker;
{
	ipfgeniter_t iter;
	ipfobj_t obj;
	nat_t nat;
	int n;

	obj.ipfo_rev = IPFILTER_VERSION;
	obj.ipfo_type = IPFOBJ_GENITER;
	obj.ipfo_size = sizeof(iter);
	obj.ipfo_ptr = &iter;

	iter.igi_type = IPFGENITER_NAT;
	iter.igi_nitems = 1;
	iter.igi_data = &nat;

	while (ioctl(ipnat_fd, SIOCGENITER, &obj) == 0) {
		if (nat.nat_pnext == NULL)
			break;
		/*
		 * This allows the walking function to know that there
		 * are no groups by checking for the name being NULL.
		 */
		walker(ticks, filter, &nat);
		if (nat.nat_next == NULL)
			break;
	}

	n = IPFGENITER_NAT;
	(void) ioctl(ipnat_fd, SIOCIPFDELTOK, &n);
}
