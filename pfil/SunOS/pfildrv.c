/*
 * Copyright (C) 2000, 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/atomic.h>
#include <sys/ethernet.h>
#include <sys/stream.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/cred.h>
#include <sys/modctl.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stat.h>
#include <sys/cmn_err.h>
#include <sys/dlpi.h>
#include <sys/kmem.h>
#include <sys/strsun.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <inet/common.h>
#include <inet/nd.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#if SOLARIS2 >= 8
# include <netinet/ip6.h>
#endif
#undef IPOPT_EOL
#undef IPOPT_NOP
#undef IPOPT_RR
#undef IPOPT_LSRR
#undef IPOPT_SSRR
#include <inet/ip.h>
#include <inet/ip_if.h>

#include "compat.h"
#include "qif.h"
#include "pfil.h"


#undef	USE_SERVICE_ROUTINE

#define MINSDUSZ 1
#define MAXSDUSZ INFPSZ

char _depends_on[] = "drv/ip";

static struct module_info pfil_minfo = {
	0x534b, "pfil", MINSDUSZ, MAXSDUSZ, 0, 0
};

krwlock_t	pfil_rw;
int		pfildebug = 0;


/************************************************************************
 * STREAMS device information (/dev/pfil)
 */
static int pfildevopen(queue_t *, dev_t *, int, int, cred_t *);
static int pfildevclose(queue_t *, int, cred_t *);

static struct qinit pfil_rinit = {
	NULL, NULL, pfildevopen, pfildevclose, NULL, &pfil_minfo, NULL
};

static struct qinit pfil_winit = {
	(pfi_t)pfilwput, NULL, NULL, NULL, NULL, &pfil_minfo, NULL
};

struct streamtab pfil_dev_strtab = {
	&pfil_rinit, &pfil_winit
};

extern int nulldev();
extern int nodev();

void pfil_donotip(int, qif_t *, queue_t *, mblk_t *, mblk_t *, struct ip *, size_t);
static int pfil_info(dev_info_t *, ddi_info_cmd_t , void *, void **);
static int pfil_attach(dev_info_t *,  ddi_attach_cmd_t);
#if SOLARIS2 < 10
static int pfil_identify(dev_info_t *);
#endif
static int pfil_detach(dev_info_t *,  ddi_detach_cmd_t);

#ifdef DDI_DEFINE_STREAM_OPS
DDI_DEFINE_STREAM_OPS(pfil_devops, nulldev, nulldev, pfil_attach, pfil_detach,
		      nulldev, pfil_info, D_MP, &pfil_dev_strtab);

#else
static struct cb_ops pfil_ops = {
	nodev,		/* cb_open */
	nodev,		/* cb_close */
	nodev,		/* cb_strategy */
	nodev,		/* cb_print */
	nodev,		/* cb_dump */
	nodev,		/* cb_read */
	nodev,		/* cb_write */
	nodev,		/* cb_ioctl */
	nodev,		/* cb_devmap */
	nodev,		/* cb_mmap */
	nodev,		/* cb_segmap */
	nochpoll,	/* cb_chpoll */
	ddi_prop_op,	/* cb_prop_op */
	&pfilinfo,	/* cb_stream */
	D_MP		/* cb_flag */
};

static struct dev_ops pfil_devops = 
{
	DEVO_REV,	/* devo_rev */
	0,		/* devo_refcnt */
	pfil_info,	/* devo_getinfo */
#if SOLARIS2 >= 10
	nulldev,
#else
	pfil_identify,	/* devo_identify */
#endif
	nulldev,	/* devo_probe */
	pfil_attach,	/* devo_attach */
	pfil_detach,	/* devo_detach */
	nodev,		/* devo_reset */
	&pfil_ops,	/* devo_cb_ops */
	NULL		/* devo_bus_ops */
};
#endif

static struct modldrv modldrv = {
	&mod_driverops, "pfil Streams driver "/**/PFIL_RELEASE, &pfil_devops
};

/************************************************************************
 * STREAMS module information
 */
static int pfilmodopen(queue_t *, dev_t *, int, int, cred_t *);
static int pfilmodclose(queue_t *, int, cred_t *);

static struct qinit pfilmod_rinit = {
	(pfi_t)pfilmodrput, NULL, pfilmodopen, pfilmodclose,
	NULL, &pfil_minfo, NULL
};

static struct qinit pfilmod_winit = {
	(pfi_t)pfilmodwput, NULL, NULL, NULL, NULL, &pfil_minfo, NULL
};

struct streamtab pfil_mod_strtab = {
	&pfilmod_rinit, &pfilmod_winit
};

static struct fmodsw fsw = {
	"pfil", &pfil_mod_strtab, D_MP
};

static struct modlstrmod modlstrmod = {
	&mod_strmodops, "pfil Streams module "/**/PFIL_RELEASE,
	&fsw
};

/************************************************************************
 * STREAMS externally visible information for _init() and _info ()
 */
static struct modlinkage modlinkage = {
	MODREV_1,
	{ (void *)&modlstrmod, (void *)&modldrv, NULL }
};

/************************************************************************
 * STREAMS device functions
 */
static dev_info_t *pfil_dev_info;


/* ------------------------------------------------------------------------ */
/* Function:    pfil_attach                                                 */
/* Returns:     int     - DDI_SUCCESS for success, otherwise DDI_FAILURE    */
/* Parameters:  devi(I) - pointer to packet information                     */
/*              cmd(I)  - DDI command to process                            */
/*                                                                          */
/* Called when the driver has been attached, just create the device file.   */
/* ------------------------------------------------------------------------ */
/*ARGUSED*/
static int pfil_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	/* LINTED: E_CONSTANT_CONDITION */
	PRINT(3,(CE_CONT, "!pfil_attach(%p,%x)\n", (void *)devi, cmd));

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	pfil_dev_info = devi;

	return (ddi_create_minor_node(devi, "pfil", S_IFCHR, 0, NULL, 0));
}


/* ------------------------------------------------------------------------ */
/* Function:    pfil_detach                                                 */
/* Returns:     int     - DDI_SUCCESS for success, otherwise DDI_FAILURE    */
/* Parameters:  devi(I) - pointer to device information                     */
/*              cmd(I)  - DDI command to process                            */
/*                                                                          */
/* Nothing to do here(?) except return that everything is ok.               */
/* ------------------------------------------------------------------------ */
/*ARGUSED*/
static int pfil_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	/* LINTED: E_CONSTANT_CONDITION */
	PRINT(3,(CE_CONT, "!pfil_detach(%p,%x)\n", (void *)devi, cmd));

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ASSERT(devi == pfil_dev_info);

	ddi_remove_minor_node(devi, NULL);
	return (DDI_SUCCESS);
}


/* ------------------------------------------------------------------------ */
/* Function:    pfil_info                                                   */
/* Returns:     int - DDI_SUCCESS (success), DDI_FAILURE (failure)          */
/* Parameters:  dip(I) - pointer to device information                      */
/*              cmd(I) - DDI command to process                             */
/*              arg(I) - paramter to the command to be processed            */
/*              res(O) - pointer to storage for returning results           */
/*                                                                          */
/* Handles information queries made by the kernel of the STREAMS device.    */
/* ------------------------------------------------------------------------ */
/*ARGUSED*/
static int pfil_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
			 void **res)
{
	int result = DDI_FAILURE;

	/* LINTED: E_CONSTANT_CONDITION */
	PRINT(3,(CE_CONT, "!pfil_info(%p,%x,%p,%p)\n", (void *)dip, infocmd,
		 arg, (void *)res));

	switch (infocmd)
	{
	case DDI_INFO_DEVT2DEVINFO:
		if (pfil_dev_info != NULL) {
			*res = (void *)pfil_dev_info;
			result = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*res = NULL;
		result = DDI_SUCCESS;
		break;
	default :
		break;
	}
	return result;
}


#if SOLARIS2 < 10
/* ------------------------------------------------------------------------ */
/* Function:    pfil_identify                                               */
/* Returns:     int - DDI_IDENTIFIED (success), DDI_NOT_IDENTIFIED (failure)*/
/* Parameters:  devi(I) -  pointer to a dev_info structure                  */
/*                                                                          */
/* Check to see if this module is correctly associated with the device info */
/* structure passed in.                                                     */
/* ------------------------------------------------------------------------ */
static int pfil_identify(dev_info_t *devi)
{
	int result = DDI_NOT_IDENTIFIED;

	/*LINTED: E_CONSTANT_CONDITION*/
	PRINT(3,(CE_CONT, "!pfil_identify(%p)\n", (void *)devi));
	if (strcmp((char *)ddi_get_name(devi), "!pfil") == 0)
		result = DDI_IDENTIFIED;

	return result;
}
#endif


/* ------------------------------------------------------------------------ */
/* Function:    pfildevopen                                                 */
/* Returns:     int      - 0 == sucess, else failure                        */
/* Parameters:  q(I)     - pointer to STREAMS queue                         */
/*              devp(I)  - pointer to a device number                       */
/*              oflag(I) - file mode open flags (always 0 for module opens) */
/*              sflag(I) - flag indicating how the open is being made       */
/*              crp(I)   - pointer to message credentials from the user     */
/*                                                                          */
/* Perform any action required to open the STREAMS device, supporting it    */
/* being opened in a cloning fashion.                                       */
/* ------------------------------------------------------------------------ */
/*ARGSUSED*/
static int pfildevopen(queue_t *q, dev_t *devp, int oflag, int sflag,
		       cred_t *crp)
{
	int result = 0;

	/* LINTED: E_CONSTANT_CONDITION */
	PRINT(3,(CE_CONT, "!pfildevopen(%p,%p,%x,%x,%p) [%s]\n",
		 (void *)q, (void *)devp, oflag, sflag, (void *)crp, QTONM(q)));
	/*
	 * As per recommendation on man page open(9e)
	 */
	if ((sflag & MODOPEN) != 0)
		result = ENXIO;

	if (result == 0)
		qprocson(q);

	return result;
}


/* ------------------------------------------------------------------------ */
/* Function:    pfildevclose                                                */
/* Returns:     int      - always returns 0.                                */
/* Parameters:  q(I)     - pointer to STREAMS queue                         */
/*              flag(I)  - file status flag                                 */
/*              crp(I)   - pointer to message credentials from the user     */
/*                                                                          */
/* Perform any action required to close the STREAMS device.                 */
/* ------------------------------------------------------------------------ */
/*ARGSUSED*/
static int pfildevclose(queue_t *q, int flag, cred_t *crp)
{

	/* LINTED: E_CONSTANT_CONDITION */
	PRINT(3,(CE_CONT, "!pfildevclose(%p,%x,%p) [%s]\n",
		 (void *)q, flag, (void *)crp, QTONM(q)));
	qprocsoff(q);

	return 0;
}

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
/*ARGSUSED*/
static int pfilmodopen(queue_t *q, dev_t *devp, int oflag, int sflag,
		       cred_t *crp)
{

	/* LINTED: E_CONSTANT_CONDITION */
	PRINT(3,(CE_CONT, "!pfilmodopen(%p,%p,%x,%x,%p) [%s]\n",
		 (void *)q, (void *)devp, oflag, sflag, (void *)crp, QTONM(q)));

	/*
	 * As per recommendation on man page open(9e)
	 */
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
/*ARGSUSED*/
static int pfilmodclose(queue_t *q, int flag, cred_t *crp)
{

	/* LINTED: E_CONSTANT_CONDITION */
	PRINT(3,(CE_CONT, "!pfilmodclose(%p,%x,%p) [%s]\n",
		 (void *)q, flag, (void *)crp, QTONM(q)));

	qprocsoff(q);

	qif_delete(q->q_ptr, q);
	return 0;
}

/************************************************************************
 * other support functions
 */

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
/*ARGSUSED*/
int pfil_precheck(queue_t *q, mblk_t **mp, int flags, qif_t *qif)
{
	register struct ip *ip;
	size_t hlen, len, off, mlen, iphlen, plen;
	packet_filter_hook_t *pfh;
	qpktinfo_t qpkt, *qpi;
	struct pfil_head *ph;
	mblk_t *m, *mt = *mp;
	int err, out, sap;
	u_char *bp;
#if SOLARIS2 >= 8
	ip6_t *ip6;
#endif
#ifndef	sparc
	u_short __ipoff, __iplen;
#endif

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
	 * offset to account for this.
	 */
	out = (flags & PFIL_OUT) ? 1 : 0;
	off = (out) ? qpi->qpi_hl : 0;

	ip = NULL;
	m = NULL;

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
				PRINT(5,(CE_CONT, "mp:%p not data", mt));
#ifdef PFILDEBUG
				pfil_printmchain(mt);
#endif
				atomic_add_long(&qif->qf_notdata, 1);
				return -1;
			}
		} else {
			m = mt->b_cont;
			if (m == NULL) {
				PRINT(5,(CE_CONT, "mp:%p no data", mt));
#ifdef PFILDEBUG
				pfil_printmchain(mt);
#endif
				atomic_add_long(&qif->qf_nodata, 1);
				return -3;	/* No data blocks */
			}
		}
		break;
	    }
	case M_DATA :
		m = mt;
		break;
	default :
		atomic_add_long(&qif->qf_notdata, 1);
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
		PRINT(5,(CE_CONT, "mp:%p no data", mt));
#ifdef PFILDEBUG
		pfil_printmchain(mt);
#endif
		atomic_add_long(&qif->qf_nodata, 1);
		return -3;	/* No data blocks */
	}

	/*
	 * This is a complete kludge to try and work around some bizarre
	 * packets which drop through into pfil_donotip.
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
			PRINT(5,(CE_CONT, "mp:%p no data", mt));
#ifdef PFILDEBUG
			pfil_printmchain(mt);
#endif
			atomic_add_long(&qif->qf_nodata, 1);
			return -4;	/* not enough data for IP */
		}
	}

	ip = (struct ip *)(m->b_rptr + off);
	len = m->b_wptr - m->b_rptr - off;
	mlen = msgdsize(m);
	sap = qif->qf_sap;
	if (mlen == 0)
		mlen = m->b_wptr - m->b_rptr;
	mlen -= off;

#ifdef PFILDEBUG
	/*LINTED: E_CONSTANT_CONDITION*/
	PRINT(10,(CE_CONT,
		  "!IP Filter[%s]: out %d len %ld/%ld sap %d ip %p b_rptr %p off %ld m %p/%d/%ld/%p mt %p/%d/%ld/%p\n",
		  qif->qf_name, out, len, mlen, sap,
		  (void *)ip, (void *)m->b_rptr, off, 
		  (void *)m, MTYPE(m), MLEN(m), (void *)m->b_cont,
		  (void *)mt, MTYPE(mt), MLEN(mt), (void *)mt->b_cont));
#endif

	/*
	 * If there is more than one copy of this message traversing the
	 * STREAMS stack (ie the packet is being used for snoop data), the
	 * IP header isn't on a 32bit aligned address, or the IP header
	 * isn't contain within a single block, then make a copy which
	 * meets our requirements and do a freemsg on the one passed in
	 * since we're no longer using it or passing it up.
	 */

	if ((pfil_delayed_copy == 0 && m->b_datap->db_ref > 1)
	    || ((u_int)ip & 0x3) || len < sizeof(*ip)
	    || (sap != ETHERTYPE_IP
#if SOLARIS2 >= 8
		&& sap != IP6_DL_SAP
#endif
	        )) {
		mblk_t *b;
		mblk_t *nm;
		mblk_t *nmt;
		mblk_t *previous_nm;

forced_copy:
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
				atomic_add_long(&qif->qf_copyfail, 1);
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
			 * appears before IP.
			 */
			if (b == m) {
				nm->b_wptr = nm->b_rptr + off;
				break;
			}
		}

		m->b_rptr += off;
		nm = msgpullup(m, -1);
		m->b_rptr -= off;

		if (nm == NULL) {
			atomic_add_long(&qif->qf_copyfail, 1);
			if (nmt)
				freemsg(nmt);
			return ENOBUFS;
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
	}
#if SOLARIS2 >= 8
	else if (sap == IP6_DL_SAP) {
		u_short tlen;

		hlen = sizeof(ip6_t);
		ip6 = (ip6_t *)ip;

		/* XXX - might not be aligned (from ppp?) */
		((char *)&tlen)[0] = ((char *)&ip6->ip6_plen)[0];
		((char *)&tlen)[1] = ((char *)&ip6->ip6_plen)[1];
		plen = ntohs(tlen);
		if (plen == 0)
			return EMSGSIZE;	/* Jumbo gram */

		ph = &pfh_inet6;
	}
#endif 
	else {
		sap = -1;
	}

	if (((sap == ETHERTYPE_IP) && (ip->ip_v != IPVERSION))
#if SOLARIS2 >= 8
	    || ((sap == IP6_DL_SAP) && (((ip6->ip6_vfc) & 0xf0) != 0x60))
#endif
	    || sap == -1
	   ) {
		atomic_add_long(&qif->qf_notip, 1);
#ifdef PFILDEBUG
		pfil_donotip(out, qif, q, m, mt, ip, off);
#endif
		return EINVAL;
	}

	if (sap == ETHERTYPE_IP)
		iphlen = ip->ip_hl << 2;
#if SOLARIS2 >= 8
	else if (sap == IP6_DL_SAP)
		iphlen = sizeof(ip6_t);
#endif

	if ((
#if SOLARIS2 >= 8
	     (sap == IP6_DL_SAP) && (mlen < plen)) ||
	    ((sap == ETHERTYPE_IP) &&
#endif 
	     ((iphlen < hlen) || (iphlen > plen) || (mlen < plen)))) {
		/*
		 * Bad IP packet or not enough data/data length mismatches
		 */
		atomic_add_long(&qif->qf_bad, 1);
		return EINVAL;
	}

	/*
	 * If we don't have enough data in the mblk or we haven't yet copied
	 * enough (above), then copy some more.
	 */
	if ((iphlen > len)) {
		if (m->b_datap->db_ref > 1)
			goto forced_copy;
		if (!pullupmsg(m, (int)iphlen + off)) {
			atomic_add_long(&qif->qf_nodata, 1);
			return ENOBUFS;
		}
		ip = (struct ip *)ALIGN32(m->b_rptr + off);
	}

	/*
	 * Discard any excess data.
	 */
	if (len > plen)
		m->b_wptr = m->b_rptr + off + plen;

	/*
	 * The code in IPFilter assumes that both the ip_off and ip_len
	 * fields are in host byte order, so convert them here to fulfill
	 * that expectation.
	 *
	 * If the target compile host is non-SPARC, assume it is a little
	 * endian machine, requiring the conversion of offset/length fields
	 * to both be host byte ordered.
	 */
#ifndef sparc
	if (sap == ETHERTYPE_IP) {
		__ipoff = (u_short)ip->ip_off;
		ip->ip_len = plen;
		ip->ip_off = ntohs(__ipoff);
	}
#endif

	qpi->qpi_m = m;
	qpi->qpi_off = off;
	qpi->qpi_data = ip;

	if (qif->qf_ipmp != NULL)
		qif = qif->qf_ipmp;

	READ_ENTER(&ph->ph_lock);

	pfh = pfil_hook_get(flags & PFIL_INOUT, ph);
	err = 0;

	/*LINTED: E_CONSTANT_CONDITION*/
	PRINT(8,(CE_CONT, "!pfil_hook_get(%x,%p) = %p\n",
		 flags, (void *)ph, (void *)pfh));
	for (; pfh; pfh = pfh->pfil_next)
		if (pfh->pfil_func) {
			err = (*pfh->pfil_func)(ip, iphlen, qif, out, qpi, mp);
			if (err || !*mp)
				break;
			/*
			 * fr_pullup may have allocated a new buffer.
			 */
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
	 * If we still have a STREAMS message after calling the filtering
	 * hooks, return the byte order of the fields changed above on
	 * platforms where this is required.  They are refetched from the
	 * packet headers because the callback (pfil_func) may have changed
	 * them in some way.
	 */
#ifndef sparc
	if ((err == 0) && (*mp != NULL)) {
		if (sap == ETHERTYPE_IP) {
			__iplen = (u_short)ip->ip_len;
			__ipoff = (u_short)ip->ip_off;
			ip->ip_len = htons(__iplen);
			ip->ip_off = htons(__ipoff);
		}
	}
#endif 
	return err;
}


/************************************************************************
 * kernel module initialization
 */


/* ------------------------------------------------------------------------ */
/* Function:    _init                                                       */
/* Returns:     int - DDI_SUCCESS == success, else failure                  */
/* Parameters:  Nil.                                                        */
/*                                                                          */
/* Initialise the kernel module and if that succeeds, call other init       */
/* routines, elsewhere, that handle initialisation of the more generic      */
/* components.                                                              */
/* ------------------------------------------------------------------------ */
int _init(void)
{
	int result;

	result = pfil_nd_init();
	/* LINTED: E_CONSTANT_CONDITION */
	PRINT(2,(CE_CONT, "pfil_nd_init():%d\n", result));
	if (result != 0)
		return DDI_FAILURE;

	if (qif_startup() == -1)
		return DDI_FAILURE;

	rw_init(&pfil_rw, "pfil_rw", RW_DRIVER, 0);
	pfil_startup();

	result = mod_install(&modlinkage);
	/* LINTED: E_CONSTANT_CONDITION */
	PRINT(1,(CE_CONT, "_init():%d\n", result));

	return result;
}


/* ------------------------------------------------------------------------ */
/* Function:    _fini                                                       */
/* Returns:     int - DDI_SUCCESS == success, else failure                  */
/* Parameters:  Nil.                                                        */
/*                                                                          */
/* Called when the OS attempts to unload the module, it should only be      */
/* allowed to succeed if pfil is not currently in the middle of any STREAMS */
/* "connections".  If it isn't then turn ourselves off and remove the module*/
/* ------------------------------------------------------------------------ */
int _fini(void)
{
	int result;

	if (qif_head != NULL)
		return EBUSY;

	/*
	 * Signalling to tell the timeout to exit.
	 */
	if (qif_timeout != NULL) {
		qif_addinject((void*)-1);
		mutex_enter(&qif_timemtx);
		cv_signal(&qif_timewait);
		mutex_exit(&qif_timemtx);
		untimeout(qif_timeout);
		qif_timeout = NULL;
	}

	result = mod_remove(&modlinkage);
	if (result != DDI_SUCCESS)
		return result;

	/* LINTED: E_CONSTANT_CONDITION */
	PRINT(1,(CE_CONT, "_fini():%d\n", result));

	if (result == DDI_SUCCESS) {
		pfil_nd_fini();
		qif_stop();
	}
	return result;
}


/* ------------------------------------------------------------------------ */
/* Function:    _info                                                       */
/* Returns:     int - DDI_SUCCESS == success, else failure                  */
/* Parameters:  modinfop(I) - pointer to module informatio buffer           */
/*                                                                          */
/* Standard _info() implementation that just calls mod_info on its linkage  */
/* structure so information can be copied back into the modinfop struct.    */
/* ------------------------------------------------------------------------ */
int _info(struct modinfo *modinfop)
{
	int result;

	result = mod_info(&modlinkage, modinfop);
	/* LINTED: E_CONSTANT_CONDITION */
	PRINT(3,(CE_CONT, "_info(%p):%x\n", (void *)modinfop, result));
	return result;
}


/************************************************************************
 *
 */
#ifdef PFILDEBUG
/* ------------------------------------------------------------------------ */
/* Function:    pfil_donotip                                                */
/* Returns:     Nil                                                         */
/* Parameters:  out(I) - in(0)/out(1) flag for direction of message         */
/*              qif(I) - pointer to per-queue interface information         */
/*              q(I)   - pointer to STREAMS queue                           */
/*              m(I)   - pointer to STREAMS message block where IP starts   */
/*              mt(I)  - pointer to the start of the STREAMS message        */
/*              ip(I)  - pointer to the start of the IP header              */
/*              off(I) - offset from start of message to start of IP header */
/*                                                                          */
/* This function is here solely for dumping out the contents of an mblk and */
/* showing what related information is known about it, to aid in debugging  */
/* processing of messages going by that fail to be recognised properly.     */
/* ------------------------------------------------------------------------ */
void pfil_donotip(int out, qif_t *qif, queue_t *q, mblk_t *m, mblk_t *mt, struct ip *ip, size_t off)
{
	u_char *s, outb[256], *t;
	int i;

	outb[0] = '\0';
	outb[1] = '\0';
	outb[2] = '\0';
	outb[3] = '\0';
	s = ip ? (u_char *)ip : outb;
	if (!ip && (m == mt) && m->b_cont && (MTYPE(m) != M_DATA))
		m = m->b_cont;

	/*LINTED: E_CONSTANT_CONDITION*/
	PRINT(9,(CE_CONT, 
		 "!IP %s:%d %ld %p %p %p ip %p b_rptr %p off %ld m %p/%d/%ld/%p mt %p/%d/%ld/%p\n",
		  qif ? qif->qf_name : "?", out, qif ? qif->qf_hl : -1, 
		  (void *)q, q ? q->q_ptr : NULL, q ? (void *)q->q_qinfo : NULL,
		  (void *)ip, (void *)m->b_rptr, off, 
		  (void *)m, MTYPE(m), MLEN(m), (void *)m->b_cont,
		  (void *)mt, MTYPE(mt), MLEN(mt), (void *)mt->b_cont));
	/*LINTED: E_CONSTANT_CONDITION*/
	PRINT(9,(CE_CONT, "%02x%02x%02x%02x\n", *s, *(s+1), *(s+2), *(s+3)));
	while (m != mt) {
		i = 0;
		t = outb;

		s = mt->b_rptr;
		(void)sprintf((char *)t, "%d:", MTYPE(mt));
		t += strlen((char *)t);
		for (; (i < 100) && (s < mt->b_wptr); i++) {
			(void)sprintf((char *)t, "%02x%s", *s++,
				((i & 3) == 3) ? " " : "");
			t += ((i & 3) == 3) ? 3 : 2;
		}
		*t++ = '\n';
		*t = '\0';
		/*LINTED: E_CONSTANT_CONDITION*/
		PRINT(50,(CE_CONT, "%s", outb));
		mt = mt->b_cont;
	}
	i = 0;
	t = outb;
	s = m->b_rptr;
	(void)sprintf((char *)t, "%d:", MTYPE(m));
	t += strlen((char *)t);
	for (; (i < 100) && (s < m->b_wptr); i++) {
		(void)sprintf((char *)t, "%02x%s", *s++,
			      ((i & 3) == 3) ? " " : "");
		t += ((i & 3) == 3) ? 3 : 2;
	}
	*t++ = '\n';
	*t = '\0';
	/*LINTED: E_CONSTANT_CONDITION*/
	PRINT(50,(CE_CONT, "%s", outb));
}
#endif


/* ------------------------------------------------------------------------ */
/* Function:    pfil_property_update                                        */
/* Returns:     int - DDI_SUCCESS == success, else failure                  */
/* Parameters:  modinfop(I) - pointer to module informatio buffer           */
/*                                                                          */
/* Fetch configuration file values that have been entered into the          */
/* pfil.conf driver file.                                                   */
/* ------------------------------------------------------------------------ */
static int pfil_property_update(dev_info_t *dip)
{
	char *list, *s, *t;
	int err;

	if (ddi_prop_update_int(DDI_DEV_T_ANY, dip,
				"ddi-no-autodetach", 1) == -1) {
		cmn_err(CE_WARN, "!updating ddi-no-authdetach failed");
		return DDI_FAILURE;
	}

	list = NULL;
	err = ddi_prop_lookup_string(DDI_DEV_T_ANY, dip,
				     0, "qif_ipmp_set", &list);
#ifdef	IPFDEBUG
	cmn_err(CE_CONT, "IP Filter: lookup_string(pfil_ipmp_list) = %d\n",
		err);
#endif
	if (err == DDI_SUCCESS) {
		t = NULL;
		s = list;
		do {
			if (t != NULL)
				s = t + 1;
			t = strchr(s, ';');
			if (t != NULL)
				*t = '\0';
			qif_ipmp_update(s);
		} while (t != NULL);

		ddi_prop_free(list);
	}

	return DDI_SUCCESS;
}


#ifdef NEED_MIOCPULLUP
int miocpullup(mblk_t *m, size_t len)
{
	if (m->b_cont == NULL)
		return 0;
	return pullupmsg(m->b_cont, len);
}
#endif
