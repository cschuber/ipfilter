/*
 * Copyright (C) 2002-2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 */
#if defined(KERNEL) || defined(_KERNEL)
# undef KERNEL
# undef _KERNEL
# define        KERNEL	1
# define        _KERNEL	1
#endif
#if defined(__osf__)
# define _PROTO_NET_H_
#endif
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/file.h>
#if __FreeBSD_version >= 220000 && defined(_KERNEL)
# include <sys/fcntl.h>
# include <sys/filio.h>
#else
# include <sys/ioctl.h>
#endif
#if !defined(_KERNEL)
# include <stdio.h>
# include <string.h>
# define _KERNEL
# ifdef __OpenBSD__
struct file;
# endif
# include <sys/uio.h>
# undef _KERNEL
#endif
#include <sys/socket.h>
#if (defined(__osf__) || defined(AIX) || defined(__hpux) || defined(__sgi)) && defined(_KERNEL)
# include "radix_ipf_local.h"
# define _RADIX_H_
#endif
#include <net/if.h>
#if defined(__FreeBSD__)
#  include <sys/cdefs.h>
#  include <sys/proc.h>
#endif
#if defined(_KERNEL)
# include <sys/systm.h>
# if !defined(__SVR4) && !defined(__svr4__)
#  include <sys/mbuf.h>
# endif
#endif
#include <netinet/in.h>

#include "netinet/ip_compat.h"
#include "netinet/ip_fil.h"
#include "netinet/ip_lookup.h"
#include "netinet/ip_pool.h"
#include "netinet/ip_htable.h"
/* END OF INCLUDES */

#if !defined(lint)
static const char rcsid[] = "@(#)$Id$";
#endif

#ifdef	IPFILTER_LOOKUP
int	ipf_lookup_inited = 0;

static int ipf_lookup_addnode __P((caddr_t));
static int ipf_lookup_delnode __P((caddr_t data));
static int ipf_lookup_addtable __P((caddr_t));
static int ipf_lookup_deltable __P((caddr_t));
static int ipf_lookup_stats __P((caddr_t));
static int ipf_lookup_flush __P((caddr_t));
static int ipf_lookup_iterate __P((void *, int, void *));
static int ipf_lookup_deltok __P((void *, int, void *));

static ipf_lookup_t *backends[] = {
	&ipf_pool_backend,
	&ipf_htable_backend,
#ifdef STES
	&ipf_dstlist_backend
#endif
};

#define	MAX_BACKENDS	(sizeof(backends)/sizeof(backends[0]))

/* ------------------------------------------------------------------------ */
/* Function:    ipf_lookup_init                                             */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  Nil                                                         */
/*                                                                          */
/* Initialise all of the subcomponents of the lookup infrstructure.         */
/* ------------------------------------------------------------------------ */
int
ipf_lookup_init()
{

	int i;

	RWLOCK_INIT(&ipf_poolrw, "ip pool rwlock");
	ipf_lookup_inited = 1;

	for (i = 0; i < MAX_BACKENDS; i++) {
		if (backends[i]->ipfl_init != NULL) {
			if ((*backends[i]->ipfl_init)() == -1)
				return -1;
		}
	}

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_lookup_unload                                           */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  Nil                                                         */
/*                                                                          */
/* Free up all pool related memory that has been allocated whilst IPFilter  */
/* has been running.  Also, do any other deinitialisation required such     */
/* ipf_lookup_init() can be called again, safely.                           */
/* ------------------------------------------------------------------------ */
void
ipf_lookup_unload()
{
	int i;

	for (i = 0; i < MAX_BACKENDS; i++) {
		(*backends[i]->ipfl_fini)();
	}

	if (ipf_lookup_inited == 1) {
		RW_DESTROY(&ipf_poolrw);
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_lookup_ioctl                                            */
/* Returns:     int      - 0 = success, else error                          */
/* Parameters:  data(IO) - pointer to ioctl data to be copied to/from user  */
/*                         space.                                           */
/*              cmd(I)   - ioctl command number                             */
/*              mode(I)  - file mode bits used with open                    */
/*                                                                          */
/* Handle ioctl commands sent to the ioctl device.  For the most part, this */
/* involves just calling another function to handle the specifics of each   */
/* command.                                                                 */
/* ------------------------------------------------------------------------ */
int
ipf_lookup_ioctl(data, cmd, mode, uid, ctx)
	caddr_t data;
	ioctlcmd_t cmd;
	int mode, uid;
	void *ctx;
{
	int err;
	SPL_INT(s);

	mode = mode;	/* LINT */

	SPL_NET(s);

	switch (cmd)
	{
	case SIOCLOOKUPADDNODE :
	case SIOCLOOKUPADDNODEW :
		WRITE_ENTER(&ipf_poolrw);
		err = ipf_lookup_addnode(data);
		RWLOCK_EXIT(&ipf_poolrw);
		break;

	case SIOCLOOKUPDELNODE :
	case SIOCLOOKUPDELNODEW :
		WRITE_ENTER(&ipf_poolrw);
		err = ipf_lookup_delnode(data);
		RWLOCK_EXIT(&ipf_poolrw);
		break;

	case SIOCLOOKUPADDTABLE :
		WRITE_ENTER(&ipf_poolrw);
		err = ipf_lookup_addtable(data);
		RWLOCK_EXIT(&ipf_poolrw);
		break;

	case SIOCLOOKUPDELTABLE :
		WRITE_ENTER(&ipf_poolrw);
		err = ipf_lookup_deltable(data);
		RWLOCK_EXIT(&ipf_poolrw);
		break;

	case SIOCLOOKUPSTAT :
	case SIOCLOOKUPSTATW :
		WRITE_ENTER(&ipf_poolrw);
		err = ipf_lookup_stats(data);
		RWLOCK_EXIT(&ipf_poolrw);
		break;

	case SIOCLOOKUPFLUSH :
		WRITE_ENTER(&ipf_poolrw);
		err = ipf_lookup_flush(data);
		RWLOCK_EXIT(&ipf_poolrw);
		break;

	case SIOCLOOKUPITER :
		err = ipf_lookup_iterate(data, uid, ctx);
		break;

	case SIOCIPFDELTOK :
		err = ipf_lookup_deltok(data, uid, ctx);
		break;

	default :
		ipf_interror = 50001;
		err = EINVAL;
		break;
	}
	SPL_X(s);
	return err;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_lookup_addnode                                          */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  data(I) - pointer to data from ioctl call                   */
/*                                                                          */
/* Add a new data node to a lookup structure.  First, check to see if the   */
/* parent structure refered to by name exists and if it does, then go on to */
/* add a node to it.                                                        */
/* ------------------------------------------------------------------------ */
static int
ipf_lookup_addnode(data)
	caddr_t data;
{
	iplookupop_t op;
	int err;
	int i;

	err = BCOPYIN(data, &op, sizeof(op));
	if (err != 0) {
		ipf_interror = 50002;
		return EFAULT;
	}

	if (op.iplo_unit < 0 || op.iplo_unit > IPL_LOGMAX) {
		ipf_interror = 50003;
		return EINVAL;
	}

	op.iplo_name[sizeof(op.iplo_name) - 1] = '\0';

	for (i = 0; i < MAX_BACKENDS; i++) {
		if (op.iplo_type == backends[i]->ipfl_type) {
			err = (*backends[i]->ipfl_node_add)(&op);
			break;
		}
	}

	if (i == MAX_BACKENDS) {
		ipf_interror = 50012;
		err = EINVAL;
	}

	return err;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_lookup_delnode                                          */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  data(I) - pointer to data from ioctl call                   */
/*                                                                          */
/* Delete a node from a lookup table by first looking for the table it is   */
/* in and then deleting the entry that gets found.                          */
/* ------------------------------------------------------------------------ */
static int
ipf_lookup_delnode(data)
	caddr_t data;
{
	iplookupop_t op;
	int err;
	int i;

	err = BCOPYIN(data, &op, sizeof(op));
	if (err != 0) {
		ipf_interror = 50042;
		return EFAULT;
	}

	if (op.iplo_unit < 0 || op.iplo_unit > IPL_LOGMAX) {
		ipf_interror = 50013;
		return EINVAL;
	}

	op.iplo_name[sizeof(op.iplo_name) - 1] = '\0';

	for (i = 0; i < MAX_BACKENDS; i++) {
		if (op.iplo_type == backends[i]->ipfl_type) {
			err = (*backends[i]->ipfl_node_del)(&op);
			break;
		}
	}

	if (i == MAX_BACKENDS) {
		ipf_interror = 50021;
		err = EINVAL;
	}
	return err;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_lookup_addtable                                         */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  data(I) - pointer to data from ioctl call                   */
/*                                                                          */
/* Create a new lookup table, if one doesn't already exist using the name   */
/* for this one.                                                            */
/* ------------------------------------------------------------------------ */
static int
ipf_lookup_addtable(data)
	caddr_t data;
{
	iplookupop_t op;
	int err, i;

	err = BCOPYIN(data, &op, sizeof(op));
	if (err != 0) {
		ipf_interror = 50022;
		return EFAULT;
	}

	if (op.iplo_unit < 0 || op.iplo_unit > IPL_LOGMAX) {
		ipf_interror = 50023;
		return EINVAL;
	}

	op.iplo_name[sizeof(op.iplo_name) - 1] = '\0';

	for (i = 0; i < MAX_BACKENDS; i++) {
		if (op.iplo_type == backends[i]->ipfl_type) {
			err = (*backends[i]->ipfl_table_add)(&op);
			break;
		}
	}

	if (i == MAX_BACKENDS) {
		ipf_interror = 50026;
		err = EINVAL;
	}

	/*
	 * For anonymous pools, copy back the operation struct because in the
	 * case of success it will contain the new table's name.
	 */
	if ((err == 0) && ((op.iplo_arg & LOOKUP_ANON) != 0)) {
		err = BCOPYOUT(&op, data, sizeof(op));
		if (err != 0) {
			ipf_interror = 50027;
			err = EFAULT;
		}
	}

	return err;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_lookup_deltable                                         */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  data(I) - pointer to data from ioctl call                   */
/*                                                                          */
/* Decodes ioctl request to remove a particular hash table or pool and      */
/* calls the relevant function to do the cleanup.                           */
/* ------------------------------------------------------------------------ */
static int
ipf_lookup_deltable(data)
	caddr_t data;
{
	iplookupop_t op;
	int err, i;

	err = BCOPYIN(data, &op, sizeof(op));
	if (err != 0) {
		ipf_interror = 50028;
		return EFAULT;
	}

	if (op.iplo_unit < 0 || op.iplo_unit > IPL_LOGMAX) {
		ipf_interror = 50029;
		return EINVAL;
	}

	op.iplo_name[sizeof(op.iplo_name) - 1] = '\0';

	for (i = 0; i < MAX_BACKENDS; i++) {
		if (op.iplo_type == backends[i]->ipfl_type) {
			err = (*backends[i]->ipfl_table_del)(&op);
			break;
		}
	}

	if (i == MAX_BACKENDS) {
		ipf_interror = 50030;
		err = EINVAL;
	}
	return err;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_lookup_stats                                            */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  data(I) - pointer to data from ioctl call                   */
/*                                                                          */
/* Copy statistical information from inside the kernel back to user space.  */
/* ------------------------------------------------------------------------ */
static int
ipf_lookup_stats(data)
	caddr_t data;
{
	iplookupop_t op;
	int err;
	int i;

	err = BCOPYIN(data, &op, sizeof(op));
	if (err != 0) {
		ipf_interror = 50031;
		return EFAULT;
	}

	if (op.iplo_unit < 0 || op.iplo_unit > IPL_LOGMAX) {
		ipf_interror = 50032;
		return EINVAL;
	}

	for (i = 0; i < MAX_BACKENDS; i++) {
		if (op.iplo_type == backends[i]->ipfl_type) {
			err = (*backends[i]->ipfl_stats_get)(&op);
			break;
		}
	}

	if (i == MAX_BACKENDS) {
		ipf_interror = 50033;
		err = EINVAL;
	}

	return err;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_lookup_flush                                            */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  data(I) - pointer to data from ioctl call                   */
/*                                                                          */
/* A flush is called when we want to flush all the nodes from a particular  */
/* entry in the hash table/pool or want to remove all groups from those.    */
/* ------------------------------------------------------------------------ */
static int
ipf_lookup_flush(data)
	caddr_t data;
{
	int err, unit, num, type, i;
	iplookupflush_t flush;

	err = BCOPYIN(data, &flush, sizeof(flush));
	if (err != 0) {
		ipf_interror = 50034;
		return EFAULT;
	}

	unit = flush.iplf_unit;
	if ((unit < 0 || unit > IPL_LOGMAX) && (unit != IPLT_ALL)) {
		ipf_interror = 50035;
		return EINVAL;
	}

	flush.iplf_name[sizeof(flush.iplf_name) - 1] = '\0';

	type = flush.iplf_type;
	ipf_interror = 50036;
	err = EINVAL;
	num = 0;

	for (i = 0; i < MAX_BACKENDS; i++) {
		if (type == backends[i]->ipfl_type || type == IPLT_ALL) {
			err = 0;
			num += (*backends[i]->ipfl_flush)(&flush);
		}
	}

	if (err == 0) {
		flush.iplf_count = num;
		err = BCOPYOUT(&flush, data, sizeof(flush));
		if (err != 0) {
			ipf_interror = 50037;
			err = EFAULT;
		}
	}
	return err;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_lookup_delref                                           */
/* Returns:     void                                                        */
/* Parameters:  type(I) - table type to operate on                          */
/*              ptr(I)  - pointer to object to remove reference for         */
/*                                                                          */
/* This function organises calling the correct deref function for a given   */
/* type of object being passed into it.                                     */
/* ------------------------------------------------------------------------ */
void
ipf_lookup_deref(type, ptr)
	int type;
	void *ptr;
{
	int i;

	if (ptr == NULL)
		return;

	for (i = 0; i < MAX_BACKENDS; i++) {
		if (type == backends[i]->ipfl_type) {
			WRITE_ENTER(&ipf_poolrw);
			(*backends[i]->ipfl_table_deref)(ptr);
			RWLOCK_EXIT(&ipf_poolrw);
			break;
		}
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_lookup_iterate                                          */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  data(I) - pointer to data from ioctl call                   */
/*              uid(I)  - uid of caller                                     */
/*              ctx(I)  - pointer to give the uid context                   */
/*                                                                          */
/* Decodes ioctl request to step through either hash tables or pools.       */
/* ------------------------------------------------------------------------ */
static int
ipf_lookup_iterate(data, uid, ctx)
	void *data;
	int uid;
	void *ctx;
{
	ipflookupiter_t iter;
	ipftoken_t *token;
	int err, i;
	SPL_INT(s);

	err = ipf_inobj(data, &iter, IPFOBJ_LOOKUPITER);
	if (err != 0)
		return err;

	if (iter.ili_unit > IPL_LOGMAX) {
		ipf_interror = 50038;
		return EINVAL;
	}

	if (iter.ili_ival != IPFGENITER_LOOKUP) {
		ipf_interror = 50039;
		return EINVAL;
	}

	SPL_SCHED(s);
	token = ipf_findtoken(iter.ili_key, uid, ctx);
	if (token == NULL) {
		RWLOCK_EXIT(&ipf_tokens);
		SPL_X(s);
		ipf_interror = 50040;
		return ESRCH;
	}

	for (i = 0; i < MAX_BACKENDS; i++) {
		if (iter.ili_type == backends[i]->ipfl_type) {
			err = (*backends[i]->ipfl_iter_next)(token, &iter);
			break;
		}
	}
	RWLOCK_EXIT(&ipf_tokens);
	SPL_X(s);

	if (i == MAX_BACKENDS) {
		ipf_interror = 50041;
		err = EINVAL;
	}

	return err;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_lookup_iterderef                                        */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  data(I) - pointer to data from ioctl call                   */
/*                                                                          */
/* Decodes ioctl request to remove a particular hash table or pool and      */
/* calls the relevant function to do the cleanup.                           */
/* ------------------------------------------------------------------------ */
void
ipf_lookup_iterderef(type, data)
	u_32_t type;
	void *data;
{
	struct iplookupiterkey *lkey;
	iplookupiterkey_t key;
	int i;

	key.ilik_key = type;
	lkey = &key.ilik_unstr;

	if (lkey->ilik_ival != IPFGENITER_LOOKUP)
		return;

	WRITE_ENTER(&ipf_poolrw);

	for (i = 0; i < MAX_BACKENDS; i++) {
		if (type == backends[i]->ipfl_type) {
			(*backends[i]->ipfl_iter_deref)(lkey->ilik_otype,
							lkey->ilik_unit,
							data);
			break;
		}
	}
	RWLOCK_EXIT(&ipf_poolrw);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_lookup_deltok                                           */
/* Returns:     int     - 0 = success, else error                           */
/* Parameters:  data(I) - pointer to data from ioctl call                   */
/*              uid(I)  - uid of caller                                     */
/*              ctx(I)  - pointer to give the uid context                   */
/*                                                                          */
/* Deletes the token identified by the combination of (type,uid,ctx)        */
/* "key" is a combination of the table type, iterator type and the unit for */
/* which the token was being used.                                          */
/* ------------------------------------------------------------------------ */
int
ipf_lookup_deltok(data, uid, ctx)
	void *data;
	int uid;
	void *ctx;
{
	int error, key;
	SPL_INT(s);

	SPL_SCHED(s);
	error = BCOPYIN(data, &key, sizeof(key));
	if (error == 0)
		error = ipf_deltoken(key, uid, ctx);
	SPL_X(s);
	return error;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_lookup_res_num                                          */
/* Returns:     void * - NULL = failure, else success.                      */
/* Parameters:  unit(I)     - device for which this is for                  */
/*              type(I)     - type of lookup these parameters are for.      */
/*              number(I)   - table number to use when searching            */
/*              funcptr(IO) - pointer to pointer for storing IP address     */
/*                            searching function.                           */
/*                                                                          */
/* Search for the "table" number passed in amongst those configured for     */
/* that particular type.  If the type is recognised then the function to    */
/* call to do the IP address search will be change, regardless of whether   */
/* or not the "table" number exists.                                        */
/* ------------------------------------------------------------------------ */
void *
ipf_lookup_res_num(type, unit, number, funcptr)
	u_int type;
	int unit;
	u_int number;
	lookupfunc_t *funcptr;
{
	char name[FR_GROUPLEN];

#if defined(SNPRINTF) && defined(_KERNEL)
	SNPRINTF(name, sizeof(name), "%u", number);
#else
	(void) sprintf(name, "%u", number);
#endif

	return ipf_lookup_res_name(type, unit, name, funcptr);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_lookup_res_name                                         */
/* Returns:     void * - NULL = failure, else success.                      */
/* Parameters:  unit(I)     - device for which this is for                  */
/*              type(I)     - type of lookup these parameters are for.      */
/*              name(I)     - table name to use when searching              */
/*              funcptr(IO) - pointer to pointer for storing IP address     */
/*                            searching function.                           */
/*                                                                          */
/* Search for the "table" number passed in amongst those configured for     */
/* that particular type.  If the type is recognised then the function to    */
/* call to do the IP address search will be change, regardless of whether   */
/* or not the "table" number exists.                                        */
/* ------------------------------------------------------------------------ */
void *
ipf_lookup_res_name(type, unit, name, funcptr)
	u_int type;
	int unit;
	char *name;
	lookupfunc_t *funcptr;
{
	void *ptr = NULL;
	int i;

	READ_ENTER(&ipf_poolrw);

	for (i = 0; i < MAX_BACKENDS; i++) {
		if (type == backends[i]->ipfl_type) {
			ptr = (*backends[i]->ipfl_select_add_ref)(unit, name);
			if (ptr != NULL && funcptr != NULL) {
				*funcptr = backends[i]->ipfl_addr_find;
			}
			break;
		}
	}

	if (i == MAX_BACKENDS) {
		ptr = NULL;
		if (funcptr != NULL)
			*funcptr = NULL;
	}

	RWLOCK_EXIT(&ipf_poolrw);

	return ptr;
}


#endif /* IPFILTER_LOOKUP */

