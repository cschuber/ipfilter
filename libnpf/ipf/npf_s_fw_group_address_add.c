#include <string.h>
#include <npf.h>
#include "npf_ipf.h"
#include "netinet/ip_compat.h"
#include "netinet/ip_fil.h"
#include "netinet/ip_pool.h"

int
npf_s_fw_group_address_add(npf_handle_t *handle, void *param, const char *opts)
{
	npf_group_addr_t *grp = param;
	ip_pool_node_t node;
	iplookupop_t op;
	int timeout = 0;
	npf_ipf_t *ipf;
	int added = 0;
	int role;
	char *s;
	char *options;
	int i;

	if (grp->nga_naddr < 0) {
		npf_ipf_seterror(handle, 99999);
		return (-1);
	}

	if (grp->nga_group[0] == '\0') {
		npf_ipf_seterror(handle, 99999);
		return (-1);
	}

	if (grp->nga_naddr == 0)
		return (0);

	role = IPL_LOGALL;

	if (npf_ipf_option_role(handle, opts, &role) == -1)
		return (-1);

	if (npf_ipf_option_timeout(handle, opts, &timeout) == -1)
		return (-1);

	ipf = npf_get_private(handle);

	op.iplo_unit = role;
	op.iplo_type = IPLT_POOL;
	op.iplo_arg = 0;
	op.iplo_struct = &node;
	op.iplo_size = sizeof(node);
	strncpy(op.iplo_name, grp->nga_group, sizeof(op.iplo_name));

	for (i = 0; i < grp->nga_naddr; i++) {
		memset(&node, 0, sizeof(node));
		memcpy(node.ipn_name, grp->nga_group, FR_GROUPLEN);
		node.ipn_addr.adf_family = grp->nga_addr[i]->sa_family;
		node.ipn_mask.adf_family = grp->nga_addr[i]->sa_family;
		node.ipn_die = timeout;

		if (grp->nga_addr[i]->sa_family == AF_INET) {
			struct sockaddr_in *sin;

			sin = (struct sockaddr_in *)grp->nga_addr[i];

			node.ipn_addr.adf_len = 8;
			node.ipn_mask.adf_len = 8;
			node.ipn_addr.adf_addr.in4 = sin->sin_addr;
			node.ipn_mask.adf_addr.in4.s_addr = 0xffffffff;
		} else if (grp->nga_addr[i]->sa_family == AF_INET6) {
			struct sockaddr_in6 *sin6;

			sin6 = (struct sockaddr_in6 *)grp->nga_addr[i];

			node.ipn_addr.adf_len = 20;
			node.ipn_mask.adf_len = 20;
			node.ipn_addr.adf_addr.in6 = sin6->sin6_addr;
			node.ipn_mask.adf_addr.i6[0] = 0xffffffff;
			node.ipn_mask.adf_addr.i6[1] = 0xffffffff;
			node.ipn_mask.adf_addr.i6[2] = 0xffffffff;
			node.ipn_mask.adf_addr.i6[3] = 0xffffffff;
		}

		if (ioctl(ipf->npfi_poolfd, SIOCLOOKUPADDNODE, &op) == 0) {
			added++;
		} else {
			npf_ipf_ipferror_save(handle);
			npf_ipf_error_set(handle, 99999);
		}
	}

	return (added);
}
