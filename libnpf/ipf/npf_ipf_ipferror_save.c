#include <npf.h>
#include "npf_ipf.h"
#include "netinet/ip_compat.h"
#include "netinet/ip_fil.h"

void
npf_ipf_ipferror_save(npf_handle_t *npf)
{
	npf_ipf_t *ipf;

	ipf = npf_get_private(npf);
	if (ipf != NULL) {
		/*
		 * If getting the IPFilter internal error results in a failure
		 * then set it to -1 so that we know we tried to get it but
		 * failed.
		 */
		if (ioctl(ipf->npfi_fd, SIOCIPFINTERROR,
			  &ipf->npfi_ipferror) == -1)
			ipf->npfi_ipferror = -1;
	}
}
