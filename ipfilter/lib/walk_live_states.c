#include "ipf.h"
#include "ipl.h"

extern int ipstate_fd;

void
walk_live_states(ticks, filter, walker)
	u_long ticks;
	int *filter;
	ipf_state_walk_func_t walker;
{
	ipfgeniter_t iter;
	ipstate_t info;
	ipfobj_t obj;
	int n;

	obj.ipfo_rev = IPFILTER_VERSION;
	obj.ipfo_type = IPFOBJ_GENITER;
	obj.ipfo_size = sizeof(iter);
	obj.ipfo_ptr = &iter;

	iter.igi_type = IPFGENITER_STATE;
	iter.igi_nitems = 1;
	iter.igi_data = &info;

	while (ioctl(ipstate_fd, SIOCGENITER, &obj) == 0) {
		if (info.is_sti.tqe_parent == NULL)
			break;
		walker(ticks, filter, &info);
	}

	n = IPFGENITER_STATE;
	(void) ioctl(ipstate_fd, SIOCIPFDELTOK, &n);
}
