
#ifndef __IP_LOOKUP_H__
#define __IP_LOOKUP_H__

#if defined(__STDC__) || defined(__GNUC__) || defined(_AIX51)
# define	SIOCLOOKUPADDTABLE	_IOWR('r', 60, struct iplookupop)
# define	SIOCLOOKUPDELTABLE	_IOWR('r', 61, struct iplookupop)
# define	SIOCLOOKUPSTAT		_IOWR('r', 64, struct iplookupop)
# define	SIOCLOOKUPSTATW		_IOW('r', 64, struct iplookupop)
# define	SIOCLOOKUPFLUSH		_IOWR('r', 65, struct iplookupflush)
# define	SIOCLOOKUPADDNODE	_IOWR('r', 67, struct iplookupop)
# define	SIOCLOOKUPADDNODEW	_IOW('r', 67, struct iplookupop)
# define	SIOCLOOKUPDELNODE	_IOWR('r', 68, struct iplookupop)
# define	SIOCLOOKUPDELNODEW	_IOW('r', 68, struct iplookupop)
#else
# define	SIOCLOOKUPADDTABLE	_IOWR(r, 60, struct iplookupop)
# define	SIOCLOOKUPDELTABLE	_IOWR(r, 61, struct iplookupop)
# define	SIOCLOOKUPSTAT		_IOWR(r, 64, struct iplookupop)
# define	SIOCLOOKUPSTATW		_IOW(r, 64, struct iplookupop)
# define	SIOCLOOKUPFLUSH		_IOWR(r, 65, struct iplookupflush)
# define	SIOCLOOKUPADDNODE	_IOWR(r, 67, struct iplookupop)
# define	SIOCLOOKUPADDNODEW	_IOW(r, 67, struct iplookupop)
# define	SIOCLOOKUPDELNODE	_IOWR(r, 68, struct iplookupop)
# define	SIOCLOOKUPDELNODEW	_IOW(r, 68, struct iplookupop)
#endif

typedef	struct	iplookupop	{
	int	iplo_type;	/* IPLT_* */
	int	iplo_unit;	/* IPL_LOG* */
	u_int	iplo_arg;
	char	iplo_name[FR_GROUPLEN];
	size_t	iplo_size;	/* sizeof struct at iplo_struct */
	void	*iplo_struct;
} iplookupop_t;

#define	LOOKUP_ANON	0x80000000


typedef	struct	iplookupflush	{
	int	iplf_type;	/* IPLT_* */
	int	iplf_unit;	/* IPL_LOG* */
	u_int	iplf_arg;
	size_t	iplf_count;
	char	iplf_name[FR_GROUPLEN];
} iplookupflush_t;

typedef	struct	iplookuplink	{
	int	ipll_type;	/* IPLT_* */
	int	ipll_unit;	/* IPL_LOG* */
	u_int	ipll_num;
	char	ipll_group[FR_GROUPLEN];
} iplookuplink_t;

#define	IPLT_ALL	-1
#define	IPLT_NONE	0
#define	IPLT_POOL	1
#define	IPLT_HASH	2
#define	IPLT_DSTLIST	3


#define	IPLT_ANON	0x80000000


typedef	union	{
	struct	iplookupiterkey {
		u_char	ilik_ival;
		u_char	ilik_type;	/* IPLT_* */
		u_char	ilik_otype;
		u_char	ilik_unit;	/* IPL_LOG* */
	} ilik_unstr;
	u_32_t	ilik_key;
} iplookupiterkey_t;

typedef	struct	ipflookupiter	{
	int			ili_nitems;
	iplookupiterkey_t	ili_lkey;
	char			ili_name[FR_GROUPLEN];
	void			*ili_data;
} ipflookupiter_t;

#define	ili_key		ili_lkey.ilik_key
#define	ili_ival	ili_lkey.ilik_unstr.ilik_ival
#define	ili_unit	ili_lkey.ilik_unstr.ilik_unit
#define	ili_type	ili_lkey.ilik_unstr.ilik_type
#define	ili_otype	ili_lkey.ilik_unstr.ilik_otype

#define	IPFLOOKUPITER_LIST	0
#define	IPFLOOKUPITER_NODE	1


typedef struct ipf_lookup {
	int	ipfl_type;
	int	(*ipfl_init) __P((void));
	void	(*ipfl_fini) __P((void));
	int	(*ipfl_addr_find) __P((void *, int, void *));
	size_t	(*ipfl_flush) __P((iplookupflush_t *));
	int	(*ipfl_iter_deref) __P((int, int, void *));
	int	(*ipfl_iter_next) __P((ipftoken_t *, ipflookupiter_t *));
	int	(*ipfl_node_add) __P((iplookupop_t *));
	int	(*ipfl_node_del) __P((iplookupop_t *));
	int	(*ipfl_stats_get) __P((iplookupop_t *));
	int	(*ipfl_table_add) __P((iplookupop_t *));
	int	(*ipfl_table_del) __P((iplookupop_t *));
	int	(*ipfl_table_deref) __P((void *));
	void	*(*ipfl_table_find) __P((int, char *));
	void	*(*ipfl_select_add_ref) __P((int, char *));
} ipf_lookup_t;

extern int ipf_lookup_init __P((void));
extern int ipf_lookup_ioctl __P((caddr_t, ioctlcmd_t, int, int, void *));
extern void ipf_lookup_unload __P((void));
extern void ipf_lookup_deref __P((int, void *));
extern void ipf_lookup_iterderef __P((u_32_t, void *));
extern void *ipf_lookup_res_name __P((u_int, int, char *, lookupfunc_t *));
extern void *ipf_lookup_res_num __P((u_int, int, u_int, lookupfunc_t *));

#endif /* __IP_LOOKUP_H__ */
