#include "ipf.h"
#include "ipl.h"

#include <sys/ioctl.h>

extern int ipf_fd;

void
walk_live_groups(unit, set, walker)
	int unit;
	int set;
	ipf_group_walk_func_t walker;
{
	frgroupiter_t info;
	ipfgeniter_t iter;
	ipfobj_t obj;
	int i;

	obj.ipfo_rev = IPFILTER_VERSION;
	obj.ipfo_type = IPFOBJ_GENITER;
	obj.ipfo_size = sizeof(iter);
	obj.ipfo_ptr = &iter;

	iter.igi_type = IPFGENITER_GROUP;
	iter.igi_nitems = 1;
	iter.igi_data = &info;

	for (i = 0; i < IPL_LOGSIZE; i++) {
		if (unit != -1 && unit != i)
			continue;
		info.gi_unit = i;
		info.gi_set = set;
		info.gi_flags = 0;
		info.gi_name[0] = '\0';
		while (ioctl(ipf_fd, SIOCGENITER, &iter) == 0) {
			/*
			 * This allows the walking function to know that there
			 * are no groups by checking for the name being NULL.
			 */
			walker(&info);
			if (info.gi_name[0] == '\0')
				break;
		}
	}
}
