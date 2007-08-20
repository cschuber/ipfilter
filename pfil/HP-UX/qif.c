/*
 * Copyright (C) 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 */

struct uio;
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/spinlock.h>
#include <sys/lock.h>
#include <sys/stream.h>
#include <sys/poll.h>
#include <sys/byteorder.h>
#include <sys/socket.h>
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <net/if.h>
#include "../netinet/ip_info.h"

#include "compat.h"
#include "qif.h"
#include "pfil.h"


static kmutex_t qif_mutex;

static char *qifnames[] = {
		"lan", "du", "cip", "el", "ixe", "mfe", "clic", NULL
};

int	qif_num;
qif_t	*qif_head;
int	qif_verbose;


/* ------------------------------------------------------------------------ */
/* Function:    qif_startup                                                 */
/* Returns:     int - 0 == success, -1 == failure                           */
/* Parameters:  None.                                                       */
/*                                                                          */
/* Perform any initialisation of data structures related to managing qif's  */
/* that is deemed necessary.                                                */
/* ------------------------------------------------------------------------ */
int qif_startup()
{

	qif_num = 0;
	qif_head = NULL;
	return 0;
}


void qif_stop()
{
	return;
}


void *q_to_ill(q)
queue_t *q;
{
	ifinfo_t *ifp, *ifn;
	char name[8], **s;
	queue_t *rq;
	int i, j;

	rq = RD(q);

	KMALLOC(ifp, ifinfo_t *, sizeof(ifinfo_t), KM_NOSLEEP);
	if (!ifp)
		return NULL;

	READ_ENTER(&pfil_rw);
	for (s = qifnames; *s; s++)
		for (i = 0; i < 10; i++) {
			sprintf(name, sizeof(name) - 1, "%s%d", *s, i);
			name[sizeof(name) - 1] = '\0';
			if (if_lookup_on_name(ifp, name, strlen(name) + 1)) {
				if (ifp->ifi_rq == RD(q)->q_next) {
					RW_EXIT(&pfil_rw);
					ifp->ifi_name[strlen(name)] = '\0';
					return ifp;
				}
				for (ifn = ifp->ifi_hash_next; ifn;
				     ifn = ifn->ifi_hash_next) {
					if (ifn->ifi_rq == RD(q)->q_next) {
						RW_EXIT(&pfil_rw);
						return ifp;
					}
				}
			}
		}
	RW_EXIT(&pfil_rw);
	KMFREE(ifp, sizeof(*ifp));
	return NULL;
}


int
qif_attach(rq)
	queue_t *rq;
{
	packet_filter_hook_t *pfh;
	ifinfo_t *ifi;
	qif_t *qif;

	ifi = q_to_ill(rq);
	if (ifi == NULL) {
		if (qif_verbose > 0)
			cmn_err(CE_NOTE,
				"PFIL: cannot find interface for rq %p",
				(void *)rq);
		return -1;
	}

	qif = rq->q_ptr;

	if (qif->qf_bound == 1)
		return 0;

	qif->qf_sap = (ifi->ifi_sap[0] << 24) | (ifi->ifi_sap[1] << 16) |
		      (ifi->ifi_sap[2] << 8) | ifi->ifi_sap[3];
	qif->qf_ppa = ifi->ifi_ppa;
	qif->qf_hl = ifi->ifi_hdr_length;
	qif->qf_ill = ifi;
	qif->qf_bound = 1;
	strncpy(qif->qf_name, ifi->ifi_name, sizeof(qif->qf_name));
	qif->qf_name[sizeof(qif->qf_name) - 1] = '\0';

	READ_ENTER(&pfh_sync.ph_lock);

	pfh = pfil_hook_get(PFIL_IN, &pfh_sync);
	for (; pfh; pfh = pfh->pfil_next)
		if (pfh->pfil_func)
			(void) (*pfh->pfil_func)(NULL, 0, qif, 0,
						 qif, NULL);
	RW_EXIT(&pfh_sync.ph_lock);

	if (qif_verbose > 0)
		cmn_err(CE_NOTE, "PFIL: attaching [%s]", qif->qf_name);
	return 0;
}


qif_t *
qif_new(q, mflags)
	queue_t *q;
	int mflags;
{
	qif_t *qif, *qf;
	u_int i, l;

	KMALLOC(qif, qif_t *, sizeof(qif_t), mflags);
	if (qif == NULL) {
		cmn_err(CE_NOTE, "PFIL: malloc(%d) for qif_t failed",
			(int)sizeof(qif_t));
		return NULL;
	}

	bzero((char *)qif, sizeof(qif));
	qif->qf_qifsz = sizeof(*qif);
	qif->qf_q = q;
	qif->qf_oq = OTHERQ(q);
	WRITE_ENTER(&pfil_rw);
	qif->qf_num = qif_num++;
	qif->qf_next = qif_head;
	qif_head = qif;
	RW_EXIT(&pfil_rw);
	(void) sprintf(qif->qf_name, sizeof(qif->qf_name),
		       "QIF%x", qif->qf_num);
	return qif;
}


void qif_delete(qif, q)
qif_t *qif;
queue_t *q;
{
	packet_filter_hook_t *pfh;
	ifinfo_t *ifp;
	qif_t **qp;
	int rm = 0;

	if (qif == NULL)
		return;

	WRITE_ENTER(&pfil_rw);

	if (qif->qf_bound && qif_verbose)
		cmn_err(CE_NOTE, "PFIL: detaching [%s]", qif->qf_name);

	for (qp = &qif_head; *qp; qp = &(*qp)->qf_next)
		if (*qp == qif) {
			*qp = qif->qf_next;
			rm = 1;
			break;
		}

	if (qif->qf_ill) {
		READ_ENTER(&pfh_sync.ph_lock);
		pfh = pfil_hook_get(PFIL_OUT, &pfh_sync);
		for (; pfh; pfh = pfh->pfil_next)
			if (pfh->pfil_func)
				(void) (*pfh->pfil_func)(NULL, 0, qif,
							 1, qif, NULL);
		RW_EXIT(&pfh_sync.ph_lock);
	}

	RW_EXIT(&pfil_rw);

	if (rm) {
		ifp = qif->qf_ill;
		if (ifp != NULL) {
			KMFREE(ifp, sizeof(*ifp));
		}
		KMFREE(qif, qif->qf_qifsz);
	}
	return;
}


void *qif_iflookup(name, sap)
char *name;
int sap;
{
	qif_t *qif;

	for (qif = qif_head; qif; qif = qif->qf_next)
		if ((!sap || (qif->qf_sap == sap)) &&
		    !strcmp(qif->qf_name, name))
			break;
	return qif;
}


void *ir_to_ill(ir)
struct irinfo_s *ir;
{
	queue_t *q;
	qif_t *qf;

	for (qf = qif_head; qf; qf = qf->qf_next) {
		q = qf->qf_q;
		if (q && q->q_next && (RD(q->q_next) == ir->ir_rfq))
			return qf->qf_ill;
	}
	return NULL;
}


void qif_update(qif, mp)
qif_t *qif;
mblk_t *mp;
{
	ifinfo_t ifi;

	if (!qif->qf_ill)
		return;

	if (if_lookup_on_name(&ifi, qif->qf_name, strlen(qif->qf_name) + 1)) {
		qif->qf_sap = (ifi.ifi_sap[0] << 24) | (ifi.ifi_sap[1] << 16) |
			      (ifi.ifi_sap[2] << 8) | ifi.ifi_sap[3];
		qif->qf_hl = ifi.ifi_hdr_length;
		bcopy((char *)&ifi, (char *)qif->qf_ill, sizeof(ifi));
	}
	return;
}


/* ------------------------------------------------------------------------ */
/* Function:    qif_walk                                                    */
/* Returns:     qif_t *  - NULL == search failed, else pointer to qif_t     */
/* Parameters:  qfp(IO) - pointer to the name                               */
/*                                                                          */
/* NOTE: it is assumed the caller has a lock on pfil_rw                     */
/*                                                                          */
/* Provide a function to enable the caller to enumerate through all of the  */
/* qif_t's without being aware of the internal data structure used to store */
/* them in.                                                                 */
/* ------------------------------------------------------------------------ */
qif_t *qif_walk(qif_t **qfp)
{
	struct qif *qf, *qf2;

	if (qfp == NULL)
		return NULL;

	qf = *qfp;
	if (qf == NULL)
		*qfp = qif_head;
	else {
		/*
		 * Make sure the pointer being passed in exists as a current
		 * object before returning its next value.
		 */
		for (qf2 = qif_head; qf2 != NULL; qf2 = qf2->qf_next)
			if (qf2 == qf)
				break;
		if (qf2 == NULL)
			*qfp = NULL;
		else
			*qfp = qf->qf_next;
	}
	return *qfp;
}


/* ------------------------------------------------------------------------ */
/* Function:    qif_ipmp_update                                             */
/* Returns:     void                                                        */
/* Parameters:  ipmpconf(I) - pointer to an ill to match against            */
/*                                                                          */
/* Take an IPMP configuration string passed in to update the pfil config.   */
/* The string may either indicate that an IPMP interface is to be deleted   */
/* ("ipmp0=" - no NICs after the right of the '=') or created/changed if    */
/* there is text after the '='.                                             */
/* ------------------------------------------------------------------------ */
void qif_ipmp_update(char *ipmpconf)
{
	qif_t *qif, *qf;
	int len, sap;
	char *s;

	sap = ETHERTYPE_IP;
	if (!strncmp(ipmpconf, "v4:", 3)) {
		ipmpconf += 3;
	} else if (!strncmp(ipmpconf, "v6:", 3)) {
#ifdef ETHERTYPE_IPV6
		sap = ETHERTYPE_IPV6;
		ipmpconf += 3;
#else
		return;
#endif
	} else
		return;

	s = strchr(ipmpconf, '=');
	if (s != NULL) {
		if (*(s + 1) == '\0')
			*s = '\0';
		else
			*s++ = '\0';
	}
	if (s == NULL || *s == NULL) {
		qif_ipmp_delete(ipmpconf);
		return;
	}

	len = sizeof(qif_t) + strlen(s) + 1;
	KMALLOC(qif, qif_t *, len, KM_NOSLEEP);
	if (qif == NULL) {
		cmn_err(CE_NOTE, "PFIL: malloc(%ld) for qif_t failed", len);
		return;
	}

	WRITE_ENTER(&pfil_rw);
	for (qf = qif_head; qf; qf = qf->qf_next) 
		if (strcmp(qf->qf_name, ipmpconf) == 0)
			break;

	if (qf == NULL) {
		qf = qif;
		qif->qf_next = qif_head;
		qif_head = qif;

		qif->qf_flags |= QF_IPMP;
		qif->qf_qifsz = len;
		qif->qf_members = (char *)qif + sizeof(*qif);
		strcpy(qif->qf_name, ipmpconf);
	} else {
		KMFREE(qif, len);
		qif = qf;
	}
	RW_DOWNGRADE(&pfil_rw);

	strcpy(qif->qf_members, s);

	qif_ipmp_syncmaster(qif);

	RW_EXIT(&pfil_rw);
}


/* ------------------------------------------------------------------------ */
/* Function:    qif_ipmp_delete                                             */
/* Returns:     void                                                        */
/* Parameters:  qifname(I) - pointer to name of qif to delete               */
/*                                                                          */
/* Search for a qif structure that is named to match qifname, remove all    */
/* references to it by others, delink and free it.                          */
/* ------------------------------------------------------------------------ */
void qif_ipmp_delete(char *qifname)
{
	packet_filter_hook_t *pfh;
	qif_t *qf, **qfp, *qif;

	WRITE_ENTER(&pfil_rw);
	for (qfp = &qif_head; (qif = *qfp) != NULL; qfp = &qif->qf_next) {
		if ((qif->qf_flags & QF_IPMP) == 0)
			continue;
		if (strcmp(qif->qf_name, qifname) == 0) {
			*qfp = qif->qf_next;
			for (qf = qif_head; qf != NULL; qf = qf->qf_next)
				if (qf->qf_ipmp == qif)
					qf->qf_ipmp = NULL;
			break;
		}
	}
	RW_EXIT(&pfil_rw);

	if (qif != NULL) {
		pfh = pfil_hook_get(PFIL_OUT, &pfh_sync);
		for (; pfh; pfh = pfh->pfil_next)
			if (pfh->pfil_func)
				(void) (*pfh->pfil_func)(NULL, 0, qif, 1,
							 qif, NULL);

		KMFREE(qif, qif->qf_qifsz);
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    qif_ipmp_syncmaster                                         */
/* Returns:     void                                                        */
/* Parameters:  updated(I) - pointer to updated qif structure               */
/* Locks:       pfil_rw                                                     */
/*                                                                          */
/* This function rechecks all the qif structures that aren't defined for    */
/* IPMP to see if they are indeed members of the group pointed to by        */
/* updated.  Ones that currently claim to be in updated are reset and       */
/* rechecked in case they have become excluded. This function should be     */
/* called for any new IPMP qif's created or when an IPMP qif changes.       */
/* ------------------------------------------------------------------------ */
void qif_ipmp_syncmaster(qif_t *updated, const int sap)
{
	char *s, *t;
	qif_t *qf;

	for (qf = qif_head; qf != NULL; qf = qf->qf_next)  {
		if ((qf->qf_flags & QF_IPMP) != 0)
			continue;
		if (qf->qf_sap != sap)
			continue;
		if (qf->qf_ipmp == updated)
			qf->qf_ipmp = NULL;
		for (s = updated->qf_members; s != NULL; ) {
			t = strchr(s, ',');
			if (t != NULL)
				*t = '\0';
			if (strcmp(qf->qf_name, s) == 0)
				qf->qf_ipmp = updated;
			if (t != NULL)
				*t++ = ',';
			s = t;
		}
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    qif_ipmp_syncslave                                          */
/* Returns:     void                                                        */
/* Parameters:  target(I) - pointer to updated qif structure                */
/* Locks:       pfil_rw                                                     */
/*                                                                          */
/* Check through the list of qif's to see if there is an IPMP with a member */
/* list that includes the one named by target.                              */
/* ------------------------------------------------------------------------ */
void qif_ipmp_syncslave(qif_t *target, const int sap)
{
	char *s, *t;
	qif_t *qf;

	target->qf_ipmp = NULL;

	/*
	 * Recheck the entire list of qif's for any references to the one
	 * we have just created/updated (updated).
	 */
	for (qf = qif_head; qf != NULL; qf = qf->qf_next)  {
		if ((qf->qf_flags & QF_IPMP) == 0)
			continue;
		if (qf->qf_sap != sap)
			continue;
		for (s = qf->qf_members; s != NULL; ) {
			t = strchr(s, ',');
			if (t != NULL)
				*t = '\0';
			if (strcmp(target->qf_name, s) == 0)
				target->qf_ipmp = qf;
			if (t != NULL)
				*t++ = ',';
			s = t;
			if (target->qf_ipmp == qf)
				break;
		}
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    qif_hl_set                                                  */
/* Returns:     void                                                        */
/* Parameters:  ipmpconf(I) - string with header length setting for NIC     */
/*                                                                          */
/* For NICs that we cannot automatically determine the MAC header length of */
/* we provide a manual crook to achieve that with.  The input syntax for    */
/* the string is "[v4:|v6:]<ifname>=<length>"                               */
/* ------------------------------------------------------------------------ */
void qif_hl_set(char *ipmpconf)
{
	qif_t *qif, *qf;
	int len, sap;
	char *s;

	sap = ETHERTYPE_IP;
	if (!strncmp(ipmpconf, "v4:", 3)) {
		ipmpconf += 3;
	} else if (!strncmp(ipmpconf, "v6:", 3)) {
#ifdef ETHERTYPE_IPV6
		sap = IP6_DL_SAP;
		ipmpconf += 3;
#else
		return;
#endif
	}

	s = strchr(ipmpconf, '=');
	if (s != NULL) {
		if (*(s + 1) == '\0')
			*s = '\0';
		else
			*s++ = '\0';
	}
	if (s == NULL || *s == NULL)
		return;

	READ_ENTER(&pfil_rw);
	for (qf = qif_head; qf; qf = qf->qf_next) 
		if (strcmp(qf->qf_name, ipmpconf) == 0)
			break;

	if (qf != NULL) {
		int hl = 0;

		for (; *s != '\0'; s++) {
			char c = *s;

			if (c < '0' || c > '9')
				return;
			hl *= 10;
			hl += c - '0'; 
		}
		qf->qf_hl = hl;
	}

	RW_EXIT(&pfil_rw);
}
