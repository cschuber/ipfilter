/*
 * Copyright (C) 2000, 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
struct uio;
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/stream.h>
#ifdef HPUX_1111
# include <sys/cred.h>
#endif
#include <sys/dlpi.h>
#include <sys/cmn_err.h>
#ifdef sun
# include <sys/atomic.h>
# include <sys/sockio.h>
# include <sys/ksynch.h>
# include <sys/strsubr.h>
# include <sys/strsun.h>
#endif
#ifdef __hpux
# include <sys/dlpi_ext.h>
# include <net/mtcp.h>
#endif
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#ifdef sun
# include <inet/common.h>
# if SOLARIS2 >= 8
#  include <netinet/ip6.h>
# else
#  include <net/if_dl.h>
# endif
# if SOLARIS2 >= 10
#  include <sys/policy.h>
# endif
# undef IPOPT_EOL
# undef IPOPT_NOP
# undef IPOPT_LSRR
# undef IPOPT_SSRR
# undef IPOPT_RR
# include <inet/ip.h>
# include <inet/ip_if.h>
#endif

#include "compat.h"
#include "qif.h"
#include "pfil.h"


#undef	IEEESAP_SNAP
#define	IEEESAP_SNAP		0xAA	/* SNAP SAP */

#ifdef	PFILDEBUG
# define	PRINT(l,x)	do {if ((l) <= pfildebug) cmn_err x; } while (0)
# define	QTONM(x)	(((x) && (x)->q_ptr) ? \
				 ((qif_t *)(x)->q_ptr)->qf_name : "??")
#else
# define	PRINT(l,x)	;
#endif

#ifndef	IP_DL_SAP
# define	IP_DL_SAP	0x800
#endif

static	int	pfil_drv_priv __P((cred_t *));


#ifdef  PFILDEBUG
/* ------------------------------------------------------------------------ */
/* Function:    pfil_printmchain                                            */
/* Returns:     void                                                        */
/* Parameters:  mp(I) - pointer to mblk message                             */
/*                                                                          */
/* This is primarly for debugging purposes - print out the contents of a    */
/* STREAMS mblk message, just by data block type or also contents (in hex)  */
/* if the value of pfil_debug has been turned up enough.                    */
/* ------------------------------------------------------------------------ */
void pfil_printmchain(mblk_t *mp)
{
	char buf[80], cbuf[17], *t;
	u_char c, *s, *r;
	mblk_t *mc;
	int i;

	if (pfildebug < 50)
		return;

	for (mc = mp; mc; mc = mc->b_cont) {
		i = mc->b_wptr - mc->b_rptr;
		/*LINTED: E_CONSTANT_CONDITION*/
		PRINT(50,(CE_CONT, "m(0x%lx):%d len %d cont 0x%lx\n",
			(u_long)mc, MTYPE(mc), i, (u_long)mc->b_cont));
		s = (u_char *)mc->b_rptr;
		r = (u_char *)cbuf;
		*buf = '\0';
		*cbuf = '\0';
		for (i = 0, t = buf; s < mc->b_wptr; ) {
			c = *s++;
			if (c >= 0x20  && c < 0x7f)
				*r++ = c;
			else
				*r++ = '.';
			*r = '\0';
#ifdef	__hpux
			sprintf(t, 4, "%02x", c);
#else
			(void)sprintf(t, "%02x", c);
#endif
			t += 2;
			i++;
			if ((i & 15) == 0) {
				/*LINTED: E_CONSTANT_CONDITION*/
				PRINT(99,(CE_CONT, "%03d:%s [%s]\n", i - 16,
					buf, cbuf));
				t = buf;
				r = (u_char *)cbuf;
			} else if ((i & 3) == 0) {
				*t++ = ' ';
				*t = '\0';
			}
		}
		if (t > buf) {
			/*LINTED: E_CONSTANT_CONDITION*/
			PRINT(99,(CE_CONT, "%03d:%s [%s]\n", i - (i & 15), buf,
				cbuf));
		}
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    pfil_printioctl                                             */
/* Returns:     void                                                        */
/* Parameters:  mp(I) - pointer to mblk message with ioctl                  */
/*                                                                          */
/* This is primarly for debugging purposes - print out in a more legible    */
/* format what an ioctl is.                                                 */
/* ------------------------------------------------------------------------ */
static void pfil_printioctl(mblk_t *mp)
{
	struct iocblk *iocp;
	int cmd, num;
	char buf[80], l;

	if (!mp || !mp->b_datap || !mp->b_datap->db_base)
		return;
	iocp = (struct iocblk *)mp->b_rptr;
	cmd = iocp->ioc_cmd;

#ifdef __hpux
	sprintf(buf, sizeof(buf), "0x%x=_IO", cmd);
#else
	(void)sprintf(buf, "0x%x=_IO", cmd);
#endif
	switch (cmd >> 24)
	{
	case 0x20:
		(void)strcat(buf, "V(");
		break;
	case 0x40:
		(void)strcat(buf, "R(");
		break;
	case 0x80:
		(void)strcat(buf, "W(");
		break;
	case 0xc0:
		(void)strcat(buf, "WR(");
		break;
	default :
#ifdef __hpux
		sprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
			"0x%x(", cmd >> 24);
#else
		(void)sprintf(buf + strlen(buf), "0x%x(", cmd >> 24);
#endif
		break;
	}

	cmd &= 0x00ffffff;
	num = cmd & 0xff;
	l = (cmd >> 8) & 0xff;
#ifdef	__hpux
	sprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
		"%c,%d,%d)", l, num, (cmd >> 16) & 0xff);
#else
	(void)sprintf(buf + strlen(buf), "%c,%d,%d)",
		l, num, (cmd >> 16) & 0xff);
#endif
	/*LINTED: E_CONSTANT_CONDITION*/
	PRINT(3,(CE_CONT,
		 "!pfil_printioctl: %s (%d) cr 0x%lx id %d flag 0x%x count %ld error %d rval %d\n",
		 buf, (int)sizeof(*iocp), (u_long)iocp->ioc_cr, iocp->ioc_id,
		 iocp->ioc_flag, iocp->ioc_count, iocp->ioc_error,
		 iocp->ioc_rval));
	pfil_printmchain(mp);
}
#endif	/* PFILDEBUG */


/* ------------------------------------------------------------------------ */
/* Function:    pfilbind                                                    */
/* Returns:     int  - 0 == success, else error                             */
/* Parameters:  q(I) - pointer to queue                                     */
/*                                                                          */
/* Check to see if a queue (or the otherside of it) is missing a qif_t      */
/* structure.  If neither have one then allocate a new one, else copy the   */
/* q_ptr from one to the other.                                             */
/* ------------------------------------------------------------------------ */
int pfilbind(queue_t *q)
{
	/* LINTED: E_CONSTANT_CONDITION */
	PRINT(3,(CE_CONT, "!pfilbind(0x%lx) ptr 0x%lx O 0x%lx\n",
		 (u_long)q, (u_long)q->q_ptr, (u_long)OTHERQ(q)));
	/* LINTED: E_CONSTANT_CONDITION */
	PRINT(3,(CE_CONT, "!R 0x%lx 0x%lx W 0x%lx 0x%lx\n",
		 (u_long)RD(q), (u_long)RD(q)->q_ptr,
		 (u_long)WR(q), (u_long)WR(q)->q_ptr));

	return qif_attach(q);
}


/* ------------------------------------------------------------------------ */
/* Function:    pfilwput_ioctl                                              */
/* Returns:     void                                                        */
/* Parameters:  q(I)  - pointer to queue                                    */
/*              mp(I) - pointer to STREAMS message                          */
/*                                                                          */
/* Handles ioctls for both the STREAMS module and driver.                   */
/* ------------------------------------------------------------------------ */
void pfilwput_ioctl(queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	qif_t *qif;

	/* LINTED: E_CONSTANT_CONDITION */
	PRINT(3,(CE_CONT,
		 "!pfilwput_ioctl(0x%lx,0x%lx) ioctl(%x,%d,%x,%ld,%d,%d) [%s]\n",
		 (u_long)q, (u_long)mp, iocp->ioc_cmd, iocp->ioc_id,
		 iocp->ioc_flag, iocp->ioc_count, iocp->ioc_rval,
		 iocp->ioc_error, QTONM(q)));
#ifdef	PFILDEBUG
	pfil_printioctl(mp);
#endif

	if (iocp->ioc_cr && pfil_drv_priv(iocp->ioc_cr) != 0 ) {
		putnext(q, mp);
		return;
	}

	switch (iocp->ioc_cmd)
	{
	case DL_IOC_HDR_INFO :
		qif = q->q_ptr;

		/*
		 * Fastpath information ioctl.  Update the expected size for
		 * headers on this queue using to match that in this message.
		 * Whilst this may not be an IOCACK with the header attached,
		 * it can also be an indication that something has changed so
		 * doing an update may not be a bad idea.
		 * If fastpath headers ever have variable length, this will
		 * not work.
		 */
		WRITE_ENTER(&pfil_rw);
		qif_update(qif, mp);
		RW_EXIT(&pfil_rw);
		if (qif->qf_ill != NULL) {
			packet_filter_hook_t *pfh;

			READ_ENTER(&pfh_sync.ph_lock);
			pfh = pfil_hook_get(PFIL_IN, &pfh_sync);
			for (; pfh; pfh = pfh->pfil_next)
				if (pfh->pfil_func)
					(void) (*pfh->pfil_func)(NULL, 0,
								 qif,
								 0, qif, NULL);
			RW_EXIT(&pfh_sync.ph_lock);
		}
		break;

#ifdef SIOCSLIFNAME
	case SIOCSLIFNAME :
		if (miocpullup(mp, sizeof(struct lifreq)) == 0) {
			struct lifreq *lifr;
			int sap;

			lifr = (struct lifreq *)mp->b_cont->b_rptr;
# ifdef ILLF_IPV6
			sap = (lifr->lifr_flags & ILLF_IPV6) ? IP6_DL_SAP :
							       IP_DL_SAP;
# else
			sap = IP_DL_SAP;
# endif

			qif = q->q_ptr;
			qif->qf_sap = sap;
# ifdef sun
			(void) strncpy(qif->qf_name, lifr->lifr_name,
				       sizeof(qif->qf_name));
# endif
# ifdef __hpux
			(void) strncpy(qif->qf_name, lifr->lifr_target,
				       sizeof(qif->qf_name));
# endif
			qif->qf_name[sizeof(qif->qf_name) - 1] = '\0';
			miocack(q, mp, 0, 0);
			return;
		}
		break;
#endif

#ifdef	SIOCGTUNPARAM
	case SIOCGTUNPARAM :
		qif_attach(q);
		break;
#endif

#ifdef __hpux
	case ND_SET :
	case ND_GET :
		if (pfil_ioctl_nd(q, mp)) {
			if (iocp->ioc_error)
				iocp->ioc_count = 0;
			mp->b_datap->db_type = M_IOCACK;
			qreply(q, mp);
		} else {
			miocnak(q, mp, 0, EINVAL);
		}
		return;
		break;
#endif
	default :
		break;
	}

	putnext(q, mp);
	return;
}


/************************************************************************
 * STREAMS device functions
 */
/* ------------------------------------------------------------------------ */
/* Function:    pfilwput                                                    */
/* Returns:     void                                                        */
/* Parameters:  q(I)  - pointer to queue                                    */
/*              mp(I) - pointer to STREAMS message                          */
/*                                                                          */
/* This is only called for interaction with pfil itself, as the driver      */
/* /dev/pfil, not the STREAMS module pushed on another queue.  As it does   */
/* not do any IO, this should never be called except to handle ioctl's and  */
/* so all other messages are free'd and no reply sent back.                 */
/* The only ioctls handled by the driver are ND_GET/ND_SET.                 */
/*                                                                          */
/* NOTE: HP-UX does not need or have pfil implemented as a STREAMS device.  */
/* ------------------------------------------------------------------------ */
#ifdef sun
void pfilwput(queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp;

# ifdef PFILDEBUG
	/* LINTED: E_CONSTANT_CONDITION */
	PRINT(9,(CE_CONT, "!pfilwput(0x%lx,0x%lx) [%s] qif 0x%lx\n",
		 (u_long)q, (u_long)mp, QTONM(q), (u_long)q->q_ptr));
# endif

	switch (MTYPE(mp))
	{
	case M_IOCTL:
		iocp = (struct iocblk *)mp->b_rptr;
		switch (iocp->ioc_cmd)
		{
		case ND_SET :
		case ND_GET :
			if (pfil_ioctl_nd(q, mp)) {
				if (iocp->ioc_error)
					iocp->ioc_count = 0;
				mp->b_datap->db_type = M_IOCACK;
				qreply(q, mp);
			} else {
				miocnak(q, mp, 0, EINVAL);
			}
			break;

		default :
			miocnak(q, mp, 0, EINVAL);
			break;
		}
		return;

	default :
# ifdef PFILDEBUG
		pfil_printmchain(mp);
# endif
		break;
	}

	freemsg(mp);
}
#endif


/************************************************************************
 * STREAMS module functions
 */
/* ------------------------------------------------------------------------ */
/* Function:    pfilmodwput                                                 */
/* Returns:     void                                                        */
/* Parameters:  q(I)  - pointer to queue                                    */
/*              mp(I) - pointer to STREAMS message                          */
/*                                                                          */
/* This function is called as part of the STREAMS module message processing */
/* for messages going down to the device drivers.                           */
/* ------------------------------------------------------------------------ */
void pfilmodwput(queue_t *q, mblk_t *mp)
{
	union DL_primitives *dl;
	qif_t *qif;

	qif = q->q_ptr;

	/* LINTED: E_CONSTANT_CONDITION */
	PRINT(9,(CE_CONT,
		 "!pfilmodwput(0x%lx,0x%lx) T:%d [%s,%s] qif 0x%lx 0x%lx\n",
		 (u_long)q, (u_long)mp, MTYPE(mp), QTONM(q), QTONM(OTHERQ(q)),
		 (u_long)qif, (u_long)qif->qf_ill));

	switch (MTYPE(mp))
	{
	case M_PROTO :
	case M_PCPROTO :
		dl = (union DL_primitives *)mp->b_rptr;

		/* LINTED: E_CONSTANT_CONDITION */
		PRINT(7,(CE_CONT,
			 "!pfilmodwput: 0x%lx dl_primitive:%d qif 0x%lx\n",
			 (u_long)mp, dl->dl_primitive, (u_long)qif));
#ifdef PFILDEBUG
		pfil_printmchain(mp);
#endif

		if ((MLEN(mp) < sizeof(dl_unitdata_req_t)) ||
		    (dl->dl_primitive != DL_UNITDATA_REQ)) {
			break;
		}

		/*FALLTHROUGH*/
	case M_DATA :
		atomic_add_long(&qif->qf_nw, 1);

		if (qif->qf_ill != NULL) {
			int i;

			i = pfil_precheck(q, &mp, PFIL_OUT, qif);

			/* LINTED: E_CONSTANT_CONDITION */
			PRINT(9, (CE_CONT, "!%s: pfil_precheck=%d mp 0x%lx\n",
				  "pfilmodwput", i, (u_long)mp));
			if (mp == NULL)
				return;
			else if (i > 0) {
				freemsg(mp);
				return;
			}
		}
		break;

	case M_IOCTL:
		pfilwput_ioctl(q, mp);
		return;

	default :
#ifdef PFILDEBUG
		pfil_printmchain(mp);
#endif
		break;
	}

	putnext(q, mp);
	return;
}


/* ------------------------------------------------------------------------ */
/* Function:    pfilmodrput                                                 */
/* Returns:     void                                                        */
/* Parameters:  q(I)  - pointer to queue                                    */
/*              mp(I) - pointer to STREAMS message                          */
/*                                                                          */
/* This function is called as part of the STREAMS module message processing */
/* for messages going up to the protocol stack.                             */
/* ------------------------------------------------------------------------ */
void pfilmodrput(queue_t *q, mblk_t *mp)
{
	union DL_primitives *dl;
	dl_bind_ack_t *b;
	int i, flags;
	qif_t *qif;

	flags = 0;
	qif = q->q_ptr;

	/* LINTED: E_CONSTANT_CONDITION */
	PRINT(9,(CE_CONT,
		 "!pfilmodrput(0x%lx,0x%lx) T:%d [%s,%s] qif 0x%lx 0x%lx\n",
		 (u_long)q, (u_long)mp, mp->b_datap->db_type, QTONM(q),
		 QTONM(OTHERQ(q)), (u_long)qif, (u_long)qif->qf_ill));

	switch (MTYPE(mp))
	{
#ifdef	DL_IOC_HDR_INFO
	case M_IOCACK :
	{
		struct iocblk *iocp = (struct iocblk *)mp->b_rptr;

		if (iocp->ioc_cmd == DL_IOC_HDR_INFO) {
			WRITE_ENTER(&pfil_rw);
			qif_update(qif, mp);
			RW_EXIT(&pfil_rw);
		}
		/*FALLTHROUGH*/
	}
#endif	/* DL_IOC_HDR_INFO */
#ifdef	PFILDEBUG
	case M_IOCNAK :
	case M_IOCTL :
		pfil_printioctl(mp);
#endif
		break;

	case M_PROTO :
	case M_PCPROTO :

		dl = (union DL_primitives *)mp->b_rptr;

		/* LINTED: E_CONSTANT_CONDITION */
		PRINT(7,(CE_CONT, "!mp:0x%lx pfilmodrput:dl_primitive:%d\n",
			 (u_long)mp, dl->dl_primitive));
#ifdef PFILDEBUG
		pfil_printmchain(mp);
#endif

		switch (dl->dl_primitive)
		{
		case DL_UNITDATA_IND :
			if ((MLEN(mp) >= sizeof(dl_unitdata_ind_t)) &&
			    (dl->unitdata_ind.dl_group_address))
				flags |= PFIL_GROUP;
			break;

		case DL_SUBS_BIND_ACK :
			if (qif->qf_waitack > 0) { 
				dl_subs_bind_ack_t *c;

				c = (dl_subs_bind_ack_t *)dl;
				if (qif->qf_sap == 0) {
#if 0
					qif->qf_sap = c->dl_sap;
					if (qif->qf_sap < 0)
						qif->qf_sap = -qif->qf_sap;
#else
					cmn_err(CE_NOTE, "c:off %u len %u",
						c->dl_subs_sap_offset,
						c->dl_subs_sap_length);
#endif
				}

				(void) pfilbind(q);
				if (qif->qf_waitack > 0)
					qif->qf_waitack--;
			}
			break;

		case DL_BIND_ACK :
			b = (dl_bind_ack_t *)dl;
			if (qif->qf_sap == 0) {
				qif->qf_sap = b->dl_sap;
				if (qif->qf_sap < 0)
					qif->qf_sap = -qif->qf_sap;
			}

			if (b->dl_sap == IEEESAP_SNAP) {
				qif->qf_waitack++;
				break;
			}

			if (!b->dl_sap || b->dl_sap == IP_DL_SAP)
				(void) pfilbind(q);
			break;

		default :
			break;
		}

		if ((MLEN(mp) < sizeof(dl_unitdata_ind_t)) ||
		    (dl->dl_primitive != DL_UNITDATA_IND)) {
			break;
		}

		/*FALLTHROUGH*/
	case M_DATA :
		atomic_add_long(&qif->qf_nr, 1);

		if (qif->qf_ill != NULL) {
			flags |= PFIL_IN;
			i = pfil_precheck(q, &mp, flags, qif);

			/* LINTED: E_CONSTANT_CONDITION */
			PRINT(9, (CE_CONT,
				  "!pfilmodrput: mp 0x%lx pfil_precheck=%d\n",
				  (u_long)mp, i));
			if (mp == NULL)
				return;
			else if (i > 0) {
				freemsg(mp);
				return;
			}
		}
#ifdef PFILDEBUG
		else {
			pfil_printmchain(mp);
		}
#endif
		break;

	default :
#ifdef PFILDEBUG
		pfil_printmchain(mp);
#endif
		break;
	}

	putnext(q, mp);
}


/* ------------------------------------------------------------------------ */
/* Function:    pfil_drv_priv                                               */
/* Returns:     int   - 0 == success, EPERM for error.                      */
/* Parameters:  cr(I) - pointer to credential information                   */
/*                                                                          */
/* Checks to see if the caller has enough credentials.                      */
/* ------------------------------------------------------------------------ */
static int pfil_drv_priv(cred_t *cr)
{
#if SOLARIS2 >= 10
	return (secpolicy_net_config(cr, B_TRUE));
#else
# ifdef sun
	return (suser(cr) ? 0 : EPERM);
# else
	return (suser() ? 0 : EPERM);
# endif
#endif
}


/************************************************************************
 * kernel module initialization
 */
/* ------------------------------------------------------------------------ */
/* Function:    pfil_startup                                                */
/* Returns:     void                                                        */
/* Parameters:  None.                                                       */
/*                                                                          */
/* Initialise pfil data strutures.                                          */
/* ------------------------------------------------------------------------ */
void pfil_startup()
{
	pfil_init(&pfh_inet4);
	pfil_init(&pfh_inet6);
	pfil_init(&pfh_sync);
}
