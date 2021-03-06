/*
 * Copyright (C) 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 */

#ifdef sun
# include <sys/dditypes.h> 
# include <sys/ptms.h>
#endif


#ifdef	IRE_ILL_CN
typedef	union	{
	struct sockaddr_in qfa_in;
	struct sockaddr_in6 qfa_in6;
} qfa_t;
# define	qfa_family	qfa_in.sin_family
# define	qfa_v4addr	qfa_in.sin_addr
# define	qfa_v6addr	qfa_in6.sin6_addr
#else
# define	QF_IPIF(x)	((ill_t *)(x)->qf_ill)->ill_ipif
# define	qf_netmask	QF_IPIF->ipif_net_mask
#  define	qf_dstaddr	QF_IPIF->ipif_pp_dst_addr
# if SOLARIS2 <= 7
#  define	qf_localaddr	QF_IPIF->ipif_local_addr
#  define	qf_broadaddr	QF_IPIF->ipif_broadcast_addr
# else
#  define	qf_localaddr	QF_IPIF->ipif_lcl_addr
#  define	qf_broadaddr	QF_IPIF->ipif_brd_addr
# endif
# ifdef	USE_INET6
#  define	qf_v6netmask	QF_IPIF->ipif_v6net_mask
#  define	qf_v6broadaddr	QF_IPIF->ipif_v6brd_addr
#  define	qf_v6dstaddr	QF_IPIF->ipif_v6pp_dst_addr
# endif
#endif

typedef	struct	qif	{
	/* for alignment reasons, the lock is first. */
	kmutex_t	qf_lock;
	struct qifplock {
		kmutex_t	pt_lock;
#ifdef sun
		kcondvar_t	pt_cv;
#endif
		int		pt_refcnt;
		int		pt_access;
	} qf_ptl;
	struct	qif	*qf_next;
	struct	qif	*qf_ipmp;	/* Pointer to group qif */
	void		*qf_ill;
	queue_t		*qf_q;
	queue_t		*qf_oq;
	/* statistical data */
	u_long		qf_nr;
	u_long		qf_nw;
	u_long		qf_bad;
	u_long		qf_copy;
	u_long		qf_copyfail;
	u_long		qf_drop;
	u_long		qf_notip;
	u_long		qf_nodata;
	u_long		qf_notdata;
	/* other data for the NIC on this queue */
	size_t		qf_qifsz;
	size_t		qf_hl;		/* header length */
	u_int		qf_num;
	u_int		qf_ppa;		/* Physical Point of Attachment */
	int		qf_sap;		/* Service Access Point */
	int		qf_bound;
	int		qf_flags;
	int		qf_waitack;
	int		qf_max_frag;	/* MTU for interface */
	char		qf_name[LIFNAMSIZ];
	char		*qf_members;
} qif_t;

typedef	struct	qpktinfo	{
	/* data that changes per-packet */
	qif_t		*qpi_real;	/* the real one on the STREAM */
	void		*qpi_ill;	/* COPIED */
	mblk_t		*qpi_m;
	queue_t		*qpi_q;
	char		*qpi_name;	/* points to qf_real->qf_name */
	void		*qpi_data;	/* where layer 3 header starts */
	size_t		qpi_off;
	size_t		qpi_hl;		/* COPIED */
	u_int		qpi_ppa;	/* COPIED */
	u_int		qpi_num;	/* COPIED */
	int		qpi_flags;	/* COPIED */
	int		qpi_max_frag;	/* COPIED */
} qpktinfo_t;


#ifdef sun
# ifndef	V4_PART_OF_V6
#  define	V4_PART_OF_V6(v6)	v6.s6_addr32[3]
# endif

# if SOLARIS2 <= 7
#  define	QF_V4_ADDR(x)	\
			((ill_t *)(x)->qf_ill)->ill_ipif->ipif_local_addr
#  define	QF_V4_BROADCAST(x)	\
			((ill_t *)(x)->qf_ill)->ill_ipif->ipif_broadcast_addr
# else
#  define	QF_V4_ADDR(x)	\
			((ill_t *)(x)->qf_ill)->ill_ipif->ipif_lcl_addr
#  define	QF_V4_BROADCAST(x)	\
			((ill_t *)(x)->qf_ill)->ill_ipif->ipif_brd_addr
# endif
# define	QF_V4_NETMASK(x)	\
			((ill_t *)(x)->qf_ill)->ill_ipif->ipif_net_mask
# define	QF_V4_PEERADDR(x)	\
			((ill_t *)(x)->qf_ill)->ill_ipif->ipif_pp_dst_addr
# ifdef	USE_INET6
#  define	QF_V6_BROADCAST(x)	\
			((ill_t *)(x)->qf_ill)->ill_ipif->ipif_v6brd_addr
#  define	QF_V6_NETMASK(x)	\
			((ill_t *)(x)->qf_ill)->ill_ipif->ipif_v6net_mask
#  define	QF_V6_PEERADDR(x)	\
			((ill_t *)(x)->qf_ill)->ill_ipif->ipif_v6pp_dst_addr
# endif
#endif

#ifdef __hpux
# define	QF_V4_ADDR(x)		((ifinfo_t *)(x)->qf_ill)->ifi_addr[0]
# define	QF_V4_BROADCAST(x)	0
# define	QF_V4_NETMASK(x)	0xffffffff
# define	QF_V4_PEERADDR(x)	0
# ifdef	USE_INET6
#  define	QF_V6_BROADCAST(x)	0
#  define	QF_V6_NETMASK(x)	0
#  define	QF_V6_PEERADDR(x)	0
# endif
#endif


#define	QF_GROUP	0x0001
#define	QF_IPMP		0x0002


typedef struct qifpkt {
	struct qifpkt	*qp_next;
	char		qp_ifname[LIFNAMSIZ];
	int		qp_sap;
	mblk_t		*qp_mb;
	int		qp_inout;
} qifpkt_t;


extern void *q_to_ill(queue_t *);
extern struct qif *qif_new(queue_t *, int);
extern int qif_attach(queue_t *);
extern void qif_delete(struct qif *, queue_t *);
extern int qif_startup(void);
extern void qif_stop(void);
extern void *qif_iflookup(char *, int);

#ifdef __hpux
struct irinfo_s;
extern void *ir_to_ill(struct irinfo_s *ir);
#endif
extern qif_t *qif_fromill(ill_t *);
extern void qif_addinject(qifpkt_t *qp);
extern struct qif *qif_walk(struct qif **);
extern struct qif *qif_head;
extern int qif_verbose;
extern void qif_update(struct qif *, mblk_t *);
extern void qif_nd_init(void);
extern void qif_hl_set(char *);
extern void qif_ipmp_delete(char *);
extern void qif_ipmp_update(char *);
extern void qif_ipmp_syncmaster(struct qif *, const int);
extern void qif_ipmp_syncslave(struct qif *, const int);
extern qif_t *qif_illrouteto(int, void *);
