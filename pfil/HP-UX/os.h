/*
 * Copyright (C) 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 */
#define	kmutex_t		lock_t
#define	krwlock_t		struct rw_lock
#define	MUTEX_ENTER(x)		spinlock(x)
#define	MUTEX_EXIT(x)		spinunlock(x)
#define	READ_ENTER(x)		lock_read(x)
#define	WRITE_ENTER(x)		lock_write(x)
#define	RW_DOWNGRADE(x)		lock_write_to_read(x)
#define	RW_EXIT(x)		lock_done(x)
#define	KMALLOC(v,t,z,w)	do { MALLOC(v, t, z, M_IOSYS, w); \
				     if ((v) != NULL) \
					bzero((void *)(v), (z)); \
				} while (0)
#define	KMFREE(v,z)		FREE(v, M_IOSYS)

extern	char	*pfil_nd;


#define	nd_load			x_nd_load
#define	nd_free			x_nd_free
#define	nd_getset		x_nd_getset
#define	mi_strtol		x_mi_strtol

#ifndef	IPPROTO_GRE
# define	IPPROTO_GRE	47
#endif
#ifndef	IPPROTO_ESP
# define	IPPROTO_ESP	50
#endif
#ifndef	ETHERTYPE_IP
# define	ETHERTYPE_IP	0x800
#endif

typedef	int	(*pfi_t)();

#define	atomic_add_long(x,y)	*(x) += y

#ifdef ETHERTYPE_IPV6
typedef	struct	ip6_hdr	ip6_t;
#endif
