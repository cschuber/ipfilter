#include <string.h>
#include <npf.h>
#include "npf_ipf.h"
#include "netinet/ip_compat.h"
#include "netinet/ip_fil.h"
#include "netinet/ip_pool.h"

int
npf_ipf_option_timeout(npf_handle_t *handle, const char *opts, int *rval)
{
	char *options = NULL;
	int timeout = -1;
	char *s;

	if (opts != NULL && *opts != '\0') {
		options = strdup(opts);
		if (options == NULL) {
			npf_ipf_seterror(handle, 99999);
			return (-1);
		}

		for (s = strtok(options, ";"); s != NULL;
		     s = strtok(NULL, ";")) {
			/*
			 * The idea is to check if any option we recognise
			 * is present. No errors are returned for unrecognised
			 * options.
			 */
			(void) sscanf(s, "timeout=%d", *rval);
		}
	}

	if (options != NULL) {
		free(options);
		options = NULL;
	}

	return (0);
}
