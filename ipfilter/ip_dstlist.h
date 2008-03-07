typedef struct ipf_dstnode {
	struct ipf_dstnode	*ipfd_next;
	struct ipf_dstnode	**ipfd_pnext;
	ipfmutex_t		ipfd_lock;
	frdest_t		ipfd_dest;
	U_QUAD_T		ipfd_bytes;
	int			ipfd_states;
	int			ipfd_ref;
	ipfmutex_t		*ipfd_plock;
} ipf_dstnode_t;

typedef enum ippool_policy_e {
	IPLDP_NONE = 0,
	IPLDP_ROUNDROBIN,
	IPLDP_CONNECTION,
	IPLDP_BYTES
} ippool_policy_t;

typedef struct ippool_dst {
	struct ippool_dst	*ipld_next;
	struct ippool_dst	**ipld_pnext;
	ipfmutex_t		ipld_lock;
	char			*ipld_name;
	int			ipld_unit;
	int			ipld_ref;
	int			ipld_flags;
	ippool_policy_t		ipld_policy;
	ipf_dstnode_t		*ipld_dests;
	ipf_dstnode_t		*ipld_selected;
} ippool_dst_t;

#define	IPDST_DELETE		0x01

extern ipf_lookup_t ipf_dstlist_backend;
