/*
 * Copyright (C) 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 */

struct uio;
#include <sys/conf.h>
#include <sys/stream.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/cmn_err.h>
#include <sys/dlpi.h>
#include <sys/io.h>
#include <sys/moddefs.h>

#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/mtcp.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#undef IPOPT_EOL
#undef IPOPT_NOP
#undef IPOPT_RR
#undef IPOPT_LSRR
#undef IPOPT_SSRR
#include <netinet/ip.h>
#ifdef ETHERTYPE_IPV6
# include <netinet/ip6.h>
#endif
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include "compat.h"
#include "qif.h"
#include "pfil.h"


#undef	USE_SERVICE_ROUTINE

#define MINSDUSZ 1
#define MAXSDUSZ INFPSZ


krwlock_t	pfil_rw;

/****************************************************************************/
/* pfil Streams Module Definition */

#define PFIL_NAME   "pfil"


static int pfilmodopen(queue_t *q, dev_t *devp, int flag, int sflag,
			  cred_t *crp);
static int pfilmodclose(queue_t *q, int flag, cred_t *crp);

static struct module_info pfil_info =
	{ 5051, "pfil driver module "/**/PFIL_RELEASE, 0, 65535, 65536, 1};

static struct qinit pfilmod_rinit = {
	(pfi_t)pfilmodrput, NULL, pfilmodopen, pfilmodclose,
	NULL, &pfil_info, NULL
};

static struct qinit pfilmod_winit = {
	(pfi_t)pfilmodwput, NULL, NULL, NULL, NULL, &pfil_info, NULL
};

struct streamtab pfilmodinfo = {
	&pfilmod_rinit, &pfilmod_winit, NULL, NULL
};


static streams_info_t pfil_str_info = {
	PFIL_NAME,				/* name */
	-1,				/* major number */
	{ NULL, NULL, NULL, NULL },	/* streamtab */
	STR_IS_MODULE | MGR_IS_MP |	/* streams flags */
	STR_SYSV4_OPEN | STR_MP_OPEN_CLOSE,
	SQLVL_QUEUE,			/* sync level */
	"",				/* elsewhere sync name */
};


/* End of pfil Streams Module initialization */


/**********************************************************************/
/* DLKM specific structures for the pfil Streams Module */

extern	struct	mod_operations	str_mod_ops;
extern	struct	mod_conf_data	pfil_conf_data;
static int pfil_load __P((void *));
static int pfil_unload __P((void *));

static struct mod_type_data     pfil_drv_link = {
	"pfilm STREAMS module "/**/PFIL_RELEASE, &pfil_str_info 
};

static  struct  modlink pfil_mod_link[] = {
	{ &str_mod_ops, (void *)&pfil_drv_link },
	{ NULL, (void *)NULL }
};

struct  modwrapper      pfil_wrapper = {
	MODREV,
	pfil_load,
	pfil_unload,
	(void (*)())NULL,
	(void *)&pfil_conf_data,
	(struct modlink*)&pfil_mod_link
};


/************************************************************************
 * STREAMS module functions
 */
/* ------------------------------------------------------------------------ */
/* Function:    pfilmodopen                                                 */
/* Returns:     int      - 0 == success, else error                         */
/* Parameters:  q(I)     - pointer to read-side STREAMS queue               */
/*              devp(I)  - pointer to a device number                       */
/*              oflag(I) - file status open flags (always 0 for module open)*/
/*              sflag(I) - flag indicating how the open is being made       */
/*              crp(I)   - pointer to message credentials from the user     */
/*                                                                          */
/* open() entry hook for the STREAMS module.                                */
/* ------------------------------------------------------------------------ */
static int pfilmodopen(queue_t *q, dev_t *devp, int flag, int sflag,
			cred_t *crp)
{
	PRINT(3,(CE_CONT, "pfilmodopen(%lx,%lx,%x,%x,%lx) [%s]\n",
	      q, devp, flag, sflag, crp, QTONM(q)));

	if (sflag != MODOPEN)
		return ENXIO;

	q->q_ptr = qif_new(q, KM_SLEEP);
	WR(q)->q_ptr = q->q_ptr;
	qprocson(q);
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    pfilmodclose                                                */
/* Returns:     int     - always returns 0.                                 */
/* Parameters:  q(I)    - pointer to read-side STREAMS queue                */
/*              flag(I) - file status flag                                  */
/*              crp(I)  - pointer to message credentials from the user      */
/*                                                                          */
/* close() entry hook for the STREAMS module. qif_delete() takes care of    */
/* setting q_ptr back to NULL for both this and the write side queue.       */
/* ------------------------------------------------------------------------ */
static int pfilmodclose(queue_t *q, int flag, cred_t *crp)
{
	PRINT(3,(CE_CONT, "pfilmodclose(%lx,%x,%lx) [%s]\n",
	      q, flag, crp, QTONM(q)));

	qprocsoff(q);

	qif_delete(q->q_ptr, q);
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    pfil_precheck                                               */
/* Returns:     int - < 0 pass packet because it's not a type subject to    */
/*                    firewall rules (i.e. internal STREAMS messages),      */
/*                    0 == pass packet, else > 0 indicates passing          */
/*                    prohibited (possibly due to an error occuring in      */
/*                    this function.)                                       */
/* Parameters:  q(I)   - pointer to STREAMS queue                           */
/*              mp(I)  - pointer to STREAMS message                         */
/*              qif(I) - pointer to per-queue interface information         */
/* Locks:       pfil_rw                                                     */
/*                                                                          */
/* In here we attempt to determine if there is an IP packet within an mblk  */
/* that is being passed along and if there is, ensure that it falls on a 32 */
/* bit aligned address and at least all of the layer 3 header is in one     */
/* buffer, preferably all the layer 4 too if we recognise it.  Finally, if  */
/* we can be sure that the buffer passes some sanity checks, pass it on to  */
/* the registered callbacks for the particular protocol/direction.          */
/* ------------------------------------------------------------------------ */
int pfil_precheck(queue_t *q, mblk_t **mp, int flags, qif_t *qif)
{
	register struct ip *ip;
#ifdef ETHERTYPE_IPV6
	register ip6_t *ip6;
#endif
	size_t hlen, len, off, mlen, iphlen, plen, p;
	int err, out, sap, realigned = 0;
	packet_filter_hook_t *pfh;
	qpktinfo_t qpkt, *qpi;
	struct pfil_head *ph;
	mblk_t *m, *mt = *mp;
	struct tcphdr *tcp;
	u_char *bp, *s;
	int cko = 0;
	mblk_t *mi = *mp;

	qpi = &qpkt;
	qpi->qpi_q = q;
	qpi->qpi_off = 0;
	qpi->qpi_name = qif->qf_name;
	qpi->qpi_real = qif;
	qpi->qpi_ill = qif->qf_ill;
	qpi->qpi_hl = qif->qf_hl;
	qpi->qpi_ppa = qif->qf_ppa;
	qpi->qpi_num = qif->qf_num;
	qpi->qpi_flags = qif->qf_flags;
	qpi->qpi_max_frag = qif->qf_max_frag;
	if ((flags & PFIL_GROUP) != 0)
		qpi->qpi_flags |= QF_GROUP;

	/*
	 * If there is only M_DATA for a packet going out, then any header
	 * information (which would otherwise appear in an M_PROTO mblk before
	 * the M_DATA) is prepended before the IP header.  We need to set the
	 * offset to account for this. - see MMM
	 */
	out = (flags & PFIL_OUT) ? 1 : 0;
	cko = (mt->b_flag & MSGCKO);
	if (out != 0) {
		/*
		 * If outbound, set offset to qif->qf_hl as it will include
		 * the cko length if cko is present.
		 */
		off = qpi->qpi_hl;
	} else {
		/*
		 * unlike before,in the IN path,  we need to set the offset
		 * as there maybe cko information we need to take care of.
		 * If inbound, then the offset is:
		 *      0 in nonfastpath/no cko
		 *      8 in cko
		 */
		if (cko)
			off = 8;
		else
			off = 0;
	}
tryagain:
	ip = NULL;
	m = NULL;

	cko = (mt->b_flag & MSGCKO);
	PRINT(9,(CE_CONT, "pfil_precheck(%lx,%lx,%x,%lx) sz %d %d hl %d\n",
		 q, mp, flags, qif,
		mt->b_wptr - mt->b_rptr, msgdsize(mt), qif->qf_hl));

	/*
	 * If the message protocol block indicates that there isn't a data
	 * block following it, just return back.
	 */
	bp = (u_char *)ALIGN32(mt->b_rptr);

	switch (MTYPE(mt))
	{
	case M_PROTO :
	case M_PCPROTO :
	    {
		dl_unitdata_ind_t *dl = (dl_unitdata_ind_t *)bp;
		if ((dl->dl_primitive != DL_UNITDATA_IND) &&
		    (dl->dl_primitive != DL_UNITDATA_REQ)) {
			ip = (struct ip *)dl;
			if ((ip->ip_v == IPVERSION) &&
			    (ip->ip_hl == (sizeof(*ip) >> 2)) &&
			    (ntohs(ip->ip_len) == mt->b_wptr - mt->b_rptr)) {
				off = 0;
				m = mt;
			} else {
				qif->qf_notdata++;
				return -1;
			}
		} else {
			m = mt->b_cont;
			if (m == NULL) {
				qif->qf_notdata++;
				return -3;	/* No data blocks */
			}
		}
		break;
	    }
	case M_DATA :
		m = mt;
		break;
	default :
		qif->qf_notdata++;
		return -2;
	}

	/*
	 * Find the first data block, count the data blocks in this chain and
	 * the total amount of data.
	 */
	if (ip == NULL)
		for (m = mt; m && (MTYPE(m) != M_DATA); m = m->b_cont)
			off = 0;	/* Any non-M_DATA cancels the offset */

	if (m == NULL) {
		qif->qf_nodata++;
		return -3;	/* No data blocks */
	}

	/*
	 * This is a complete kludge to try and work around some bizarre
	 * packets which drop through into fr_donotip.
	 */
	if ((mt != m) && (MTYPE(mt) == M_PROTO || MTYPE(mt) == M_PCPROTO)) {
		dl_unitdata_ind_t *dl = (dl_unitdata_ind_t *)bp;

		if ((dl->dl_primitive == DL_UNITDATA_IND) &&
		    (dl->dl_group_address == 1)) {
			qpi->qpi_flags |= QF_GROUP;
			if (((*((u_char *)m->b_rptr) == 0x0) &&
			    ((*((u_char *)m->b_rptr + 2) == 0x45))))
				off += 2;
		}

	}

	/*       
	 * We might have a 1st data block which is really M_PROTO, i.e. it is
	 * only big enough for the link layer header
	 */     
	while ((len = m->b_wptr - m->b_rptr) <= off) {
		off -= len;
		m = m->b_cont;  
		if (m == NULL) {
			qif->qf_nodata++;
			return -4;      /* not enough data for IP */
		}       
	}

	ip = (struct ip *)(m->b_rptr + off);
	len = m->b_wptr - m->b_rptr - off;
	mlen = msgdsize(m);
	sap = qif->qf_sap;
	if (mlen == 0) 
		mlen = mt->b_wptr - mt->b_rptr;
	mlen -= off;

	/* 
	 * Ok, the IP header isn't on a 32bit aligned address so junk it.
	 */       
	if (((u_int)ip & 0x3) || (len < sizeof(*ip)) || (sap == -1) ||
	    (m->b_datap->db_ref > 1)) { 
		mblk_t *b;
		mblk_t *nm;
		mblk_t *nmt;
		mblk_t *previous_nm;

fixalign:                   
		nmt = NULL;     
		previous_nm = NULL;

		/*
		 * Duplicate the message block descriptors up to (and
		 * including if the offset is non-zero) the block where
		 * IP begins.
		 */ 
		for (b = mt; b != m || off; b = b->b_cont) {
			nm = dupb(b);
			if (nm == NULL) {
				qif->qf_copyfail++;
				if (nmt)
					freemsg(nmt);
				return ENOBUFS; 
			}

			nm->b_cont = NULL;
			if (nmt)
				linkb(previous_nm, nm);
			else
				nmt = nm;
			previous_nm = nm;

			/*
			 * Set the length so the block only contains what
			 * apperas before IP.
			 */
			if (b == m) {
				nm->b_wptr = nm->b_rptr + off;
				break;  
			} 
		}

		m->b_rptr += off;
		nm = msgpullup(m, -1);
		m->b_rptr -= pff;

		if (nm == NULL)
			qif->qf_copyfail++;
			if (nmt)
				freemsg(nmt);
			return -e;
		}
		 
		if (nmt) 
			linkb(previous_nm, nm);
		else    
			nmt = nm;
		freemsg(mt);    

		*mp = nmt;      
		mt = nmt;
		m = nm;

		ip = (struct ip *)m->b_rptr;
		len = m->b_wptr - m->b_rptr;
		mlen = len; 
		off = 0;        
        }               

	if (sap == ETHERTYPE_IP) {
		u_short tlen;

		hlen = sizeof(*ip);

		/* XXX - might not be aligned (from ppp?) */
		((char *)&tlen)[0] = ((char *)&ip->ip_len)[0];
		((char *)&tlen)[1] = ((char *)&ip->ip_len)[1];
		plen = ntohs(tlen);
		ph = &pfh_inet4;
#ifdef ETHERTYPE_IPV6
	} else if (sap == ETHERTYPE_IPV6) {
		u_short tlen;

		hlen = sizeof(ip6_t);
		ip6 = (ip6_t *)ip;

		/* XXX - might not be aligned (from ppp?) */
		((char *)&tlen)[0] = ((char *)&ip6->ip6_plen)[0];
		((char *)&tlen)[1] = ((char *)&ip6->ip6_plen)[1];
		plen = ntohs(tlen);
		if (plen == 0)
			return EMSGSIZE;	/* Jumbo gram */
		plen += sizeof(*ip6);
		ph = &pfh_inet6;
#endif
	} else {
		hlen = 0;
		sap = -1;
	}

	if (((sap == ETHERTYPE_IP) && (ip->ip_v != IPVERSION)) || (sap == -1)) {
		qif->qf_notip++;
		return -5; 
	}                       

	if (sap == ETHERTYPE_IP)
		iphlen = ip->ip_hl << 2;

	len = m->b_wptr - m->b_rptr - off;

	if ((iphlen < hlen) || (iphlen > plen) || (mlen < plen)) {
		if ((m->b_datap->db_ref > 1) && (pfil_delayed_copy == 0))
			goto forced_copy;
		if (!pullupmsg(m, (int)iphlen + off)) {
			qif->qf_nodata++;
			return ENOBUFS;
		}
		ip = (ip_t *)(m->b_rptr + off);
	}

	/*
	 * If we don't have enough data in the mblk or we haven't yet copied
	 * enough (above), then copy some more.
	 */
	if ((iphlen > len)) {
		if (m->b_datap->db_ref > 1)
			goto forced_copy;
		if (!pullupmsg(m, (int)iphlen + off)) {
			qif->qf_nodata++;
			return -6;
		}
		ip = (struct ip *)ALIGN32(m->b_rptr + off);
	}

#if !defined(__hppa)
	if (sap == ETHERTYPE_IP) {
		__ipoff = (u_short)ip->ip_off;
		ip->ip_len = plen;
		ip->ip_off = ntohs(__ipoff);
	}
#endif

	if ((len > plen) && (off == 0))
		m->b_wptr -= len - plen;

	qpi->qpi_m = m;
	qpi->qpi_off = off;
	qpi->qpi_data = ip;

	if (qif->qf_ipmp != NULL)
		qif = qif->qf_ipmp;

	READ_ENTER(&ph->ph_lock);

	pfh = pfil_hook_get(flags & PFIL_INOUT, ph);
	err = 0;

	PRINT(8,(CE_CONT, "pfil_hook_get(%x,%lx) = %lx\n", flags, ph, pfh));
	for (pfh = pfil_hook_get(flags, ph); pfh; pfh = pfh->pfil_next)
		if (pfh->pfil_func) {
			err = (*pfh->pfil_func)(ip, iphlen, qif, out, qpi, mp);
			if (err || !*mp)
				break;
			ip = qpi->qpi_data;
		}
	RW_EXIT(&ph->ph_lock);

        /*
	 * Functions called via pfil_func should only return values >= 0, so
	 * convert any that are < 0 to be > 0 and preserve the absolute value.
	 */
	if (err < 0)
		err = -err;

	/*
	 * Copy back the ip header data if it was changed, we haven't yet
	 * freed the message and we aren't going to drop the packet.
	 * BUT only do this if there were no changes to the buffer, else
	 * we can't be sure that the ip pointer is still correct!
	 */
#if !defined(__hppa)
	if ((err == 0) && (*mp != NULL) && (sap == ETHERTYPE_IP)) {
		__iplen = (u_short)ip->ip_len;
		__ipoff = (u_short)ip->ip_off;
		ip->ip_len = htons(__iplen);
		ip->ip_off = htons(__ipoff);
	}
#endif 
	return err;
}



/************************************************************************/

static int pfil_load (void *arg)
{
	int result;

	result = pfil_install();
	PRINT(3,(CE_CONT, "pfil_install() = %d\n", result));
	if (result != 0)
		return ENXIO;
	result = pfil_nd_init();
	PRINT(3,(CE_CONT, "pfil_nd_init() = %d\n", result));
	if (result != 0)
		return ENXIO;
	if (qif_startup() == -1)
		return ENXIO;
	pfil_startup();
	return 0;
}


static int pfil_unload(void *arg)
{
	int retval;

	if (qif_head != NULL)
		return EBUSY;

	retval = str_uninstall(&pfil_str_info);
	if (retval == 0) {
		pfil_nd_fini();
		qif_stop();
	}
	return retval;

}

int pfil_install(void)
{
	int retval;

	initlock(&pfil_rw, 0, 0, "pfil_rw"); 

	pfil_str_info.inst_str_tab.st_rdinit = pfilmodinfo.st_rdinit;
	pfil_str_info.inst_str_tab.st_wrinit = pfilmodinfo.st_wrinit;
	pfil_str_info.inst_str_tab.st_muxrinit = NULL;
	pfil_str_info.inst_str_tab.st_muxwinit = NULL; 

	retval = str_install(&pfil_str_info); 
	return retval;

}


void miocnak(queue_t *q, mblk_t *m, int i, int err)
{
	struct iocblk *iocp;

	iocp = (struct iocblk *)m->b_rptr;
	iocp->ioc_error = err;
	iocp->ioc_count = i;
	m->b_datap->db_type = M_IOCNAK;
	qreply(q, m);
}


void miocack(queue_t *q, mblk_t *m, int i, int err)
{
	struct iocblk *iocp;

	iocp = (struct iocblk *)m->b_rptr;
	iocp->ioc_error = err;
	iocp->ioc_count = i;
	m->b_datap->db_type = M_IOCACK;
	qreply(q, m);
}


int miocpullup(mblk_t *m, size_t len)
{
	if (m->b_cont == NULL)
		return 0;
	return pullupmsg(m->b_cont, len);
}
