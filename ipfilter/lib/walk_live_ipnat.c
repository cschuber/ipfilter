#include "ipf.h"
#include "ipl.h"

#include <sys/ioctl.h>

extern int ipnat_fd;

void
walk_live_ipnat(walker)
	ipf_ipnat_t_walk_func_t walker;
{
	ipfgeniter_t iter;
	ipfobj_t obj;
	ipnat_t ipn;
	int n;

	obj.ipfo_rev = IPFILTER_VERSION;
	obj.ipfo_type = IPFOBJ_GENITER;
	obj.ipfo_size = sizeof(iter);
	obj.ipfo_ptr = &iter;

	iter.igi_type = IPFGENITER_IPNAT;
	iter.igi_nitems = 1;
	iter.igi_data = &ipn;

	while (ioctl(ipnat_fd, SIOCGENITER, &obj) == 0) {
		/*
		 * This allows the walking function to know that there
		 * are no groups by checking for the name being NULL.
		 */
		walker(&ipn);
		if (ipn.in_next == NULL)
			break;
	}

	n = IPFGENITER_IPNAT;
	(void) ioctl(ipnat_fd, SIOCIPFDELTOK, &n);
}
