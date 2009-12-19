/*
 * Copyright (c) 1988, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)radix.h	8.2 (Berkeley) 10/31/94
 */

#if !defined(_RADIX_IPF_H_)
#define	_RADIX_IPF_H_

/*
 * Radix search tree node layout.
 */

struct ipf_radix_node {
	struct	ipf_radix_mask *rn_mklist;	/* list of masks contained in subtree */
	struct	ipf_radix_node *rn_p;	/* parent */
	short	rn_b;			/* bit offset; -1-index(netmask) */
	char	rn_bmask;		/* node: mask for bit test*/
	u_char	rn_flags;		/* enumerated next */
#define RNF_NORMAL	1		/* leaf contains normal route */
#define RNF_ROOT	2		/* leaf is root leaf for tree */
#define RNF_ACTIVE	4		/* This node is alive (for rtfree) */
	union {
		struct {			/* leaf only data: */
			u_char	*rn_Key;		/* object of search */
			u_char	*rn_Mask;	/* netmask, if present */
			struct	ipf_radix_node *rn_Dupedkey;
		} rn_leaf;
		struct {			/* node only data: */
			int	rn_Off;		/* where to start compare */
			struct	ipf_radix_node *rn_L;/* progeny */
			struct	ipf_radix_node *rn_R;/* progeny */
		} rn_node;
	} rn_u;
#ifdef RN_DEBUG
	int rn_info;
	struct ipf_radix_node *rn_twin;
	struct ipf_radix_node *rn_ybro;
#endif
};

#undef rn_dupedkey
#define rn_dupedkey rn_u.rn_leaf.rn_Dupedkey
#undef rn_key
#define rn_key rn_u.rn_leaf.rn_Key
#undef rn_mask
#define rn_mask rn_u.rn_leaf.rn_Mask
#undef rn_off
#define rn_off rn_u.rn_node.rn_Off
#undef rn_l
#define rn_l rn_u.rn_node.rn_L
#undef rn_r
#define rn_r rn_u.rn_node.rn_R

/*
 * Annotations to tree concerning potential routes applying to subtrees.
 */

struct ipf_radix_mask {
	short	rm_b;			/* bit offset; -1-index(netmask) */
	char	rm_unused;		/* cf. rn_bmask */
	u_char	rm_flags;		/* cf. rn_flags */
	struct	ipf_radix_mask *rm_mklist;	/* more masks to try */
	union	{
		u_char	*rmu_mask;		/* the mask */
		struct	ipf_radix_node *rmu_leaf;	/* for normal routes */
	}	rm_rmu;
	int	rm_refs;		/* # of references to this struct */
};

#define rm_mask rm_rmu.rmu_mask
#define rm_leaf rm_rmu.rmu_leaf		/* extra field would make 32 bytes */

#undef	MKGet
#define MKGet(x,m) {\
	if ((x)->rn_mkfreelist) {\
		m = (x)->rn_mkfreelist; \
		(x)->rn_mkfreelist = (m)->rm_mklist; \
	} else \
		KMALLOCS(m, struct ipf_radix_mask *, sizeof (*(m))); }\

#undef	MKFree
#define MKFree(x,m) { (m)->rm_mklist = (x)->rn_mkfreelist; (x)->rn_mkfreelist = (m);}

struct ipf_radix_node_head {
	struct	ipf_radix_node *rnh_treetop;
	struct	ipf_radix_node *rnh_leaflist;
	u_long	rnh_hits;
	u_int	rnh_number;
	u_int	rnh_ref;
	int	rnh_addrsize;		/* permit, but not require fixed keys */
	int	rnh_pktsize;		/* permit, but not require fixed keys */
	struct	ipf_radix_node *(*rnh_addaddr)	/* add based on sockaddr */
		(void *soft, void *v, void *mask,
		 struct ipf_radix_node_head *head,
		 struct ipf_radix_node nodes[]);
	struct	ipf_radix_node *(*rnh_addpkt)	/* add based on packet hdr */
		(void *v, void *mask,
		 struct ipf_radix_node_head *head,
		 struct ipf_radix_node nodes[]);
	struct	ipf_radix_node *(*rnh_deladdr)	/* remove based on sockaddr */
		(void *, void *v, void *mask, struct ipf_radix_node_head *);
	struct	ipf_radix_node *(*rnh_delpkt)	/* remove based on packet hdr */
		(void *v, void *mask, struct ipf_radix_node_head *head);
	struct	ipf_radix_node *(*rnh_matchaddr)	/* locate based on sockaddr */
		(void *soft, void *v, struct ipf_radix_node_head *head);
	struct	ipf_radix_node *(*rnh_lookup)	/* locate based on sockaddr */
		(void *, void *v, void *mask, struct ipf_radix_node_head *);
	struct	ipf_radix_node *(*rnh_matchpkt)	/* locate based on packet hdr */
		(void *v, struct ipf_radix_node_head *head);
	int	(*rnh_walktree)			/* traverse tree */
		(void *, struct ipf_radix_node_head *,
		 int (*)(void *, struct ipf_radix_node *, void *), void *);
	struct	ipf_radix_node rnh_nodes[3];	/* empty tree for common case */
};


#if defined(AIX)
# undef Bcmp
# undef Bzero
#endif
#if defined(linux) && defined(_KERNEL)
# define Bcopy(a, b, n)	memmove(((caddr_t)(b)), ((caddr_t)(a)), (unsigned)(n))
#else
# if !defined(Bcopy)
#  define Bcopy(a, b, n) bcopy(((caddr_t)(a)), ((caddr_t)(b)), (unsigned)(n))
# endif
#endif

void	 *ipf_rn_create(void);
void	 ipf_rn_destroy(void *);
void	 ipf_rn_init(void *);
void	 ipf_rn_fini(void *);
int	 ipf_rn_inithead(void *, void **, int);
void	 ipf_rn_freehead(void *, struct ipf_radix_node_head *);
int	 ipf_rn_inithead0(void *, struct ipf_radix_node_head *, int);
int	 ipf_rn_refines(void *, void *);
int	 ipf_rn_walktree(void *, struct ipf_radix_node_head *,
			 int (*)(void *, struct ipf_radix_node *, void *),
			 void *);
struct ipf_radix_node
	 *ipf_rn_addmask(void *, void *, int, int),
	 *ipf_rn_addroute(void *, void *, void *, struct ipf_radix_node_head *,
			  struct ipf_radix_node [2]),
	 *ipf_rn_delete(void *, void *, void *, struct ipf_radix_node_head *),
	 *ipf_rn_insert(void *, void *, struct ipf_radix_node_head *, int *,
			struct ipf_radix_node [2]),
	 *ipf_rn_lookup(void *, void *, void *, struct ipf_radix_node_head *),
	 *ipf_rn_match(void *, void *, struct ipf_radix_node_head *),
	 *ipf_rn_newpair(void *, int, struct ipf_radix_node[2]),
	 *ipf_rn_search(void *, struct ipf_radix_node *),
	 *ipf_rn_search_m(void *, struct ipf_radix_node *, void *);

#endif /* _RADIX_IPF_H_ */
