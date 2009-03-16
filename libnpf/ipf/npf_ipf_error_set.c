#include <npf.h>
#include "npf_ipf.h"

void
npf_ipf_error_set(npf_handle_t *npf, int error)
{
	npf_ipf_t *ipf;

	ipf = npf_get_private(npf);
	if (ipf != NULL)
		ipf->npfi_liberror = error;
}
