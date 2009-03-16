#include <string.h>
#include <npf.h>
#include "npf_ipf.h"
#include "netinet/ip_compat.h"
#include "netinet/ip_fil.h"
#include "netinet/ip_pool.h"

int
npf_ipf_option_role(npf_handle_t *handle, const char *opts, int *rval)
{
	char *options = NULL;
	char *s;

	if ((opts != NULL) && (*opts != '\0')) {
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
			if (strcmp(s, "role=ipf") == 0)
				*rval = IPL_LOGIPF;
			else if (strcmp(s, "role=nat") == 0)
				*rval = IPL_LOGNAT;
			else if (strcmp(s, "role=auth") == 0)
				*rval = IPL_LOGAUTH;
			else if (strcmp(s, "role=all") == 0)
				*rval = IPL_LOGALL;
		}
	}

	if (options != NULL) {
		free(options);
		options = NULL;
	}

	return (0);
}
