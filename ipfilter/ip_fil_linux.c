#include "ipf-linux.h"

extern int sysctl_ip_default_ttl;

static	int	frzerostats __P((caddr_t));
static	int	fr_send_ip __P((fr_info_t *, struct sk_buff *, struct sk_buff **));

ipfmutex_t	ipl_mutex, ipf_authmx, ipf_rw, ipf_stinsert;
ipfmutex_t	ipf_nat_new, ipf_natio, ipf_timeoutlock;
ipfrwlock_t	ipf_mutex, ipf_global, ipf_ipidfrag;
ipfrwlock_t	ipf_frag, ipf_state, ipf_nat, ipf_natfrag, ipf_auth;

static u_int ipf_linux_inout __P((u_int, struct sk_buff **, const struct net_device *, const struct net_device *, int (*okfn)(struct sk_buff *)));

static struct	nf_hook_ops	ipf_hooks[] = {
	{
		{ NULL, NULL },		/* list */
		ipf_linux_inout,	/* hook */
		PF_INET,		/* pf */
		NF_IP_PRE_ROUTING,	/* hooknum */
		200			/* priority */
	},
	{
		{ NULL, NULL},		/* list */
		ipf_linux_inout,	/* hook */
		PF_INET,		/* pf */
		NF_IP_POST_ROUTING,	/* hooknum */
		200			/* priority */
	},
#ifdef USE_INET6
	{
		{ NULL, NULL },		/* list */
		ipf_linux_inout,	/* hook */
		PF_INET6,		/* pf */
		NF_IP_PRE_ROUTING,	/* hooknum */
		200			/* priority */
	},
	{
		{ NULL, NULL},		/* list */
		ipf_linux_inout,	/* hook */
		PF_INET6,		/* pf */
		NF_IP_POST_ROUTING,	/* hooknum */
		200			/* priority */
	}
#endif
};


/*
 * Filter ioctl interface.
 */
int ipf_ioctl(struct inode *in, struct file *fp, u_int cmd, u_long arg)
{
	int error = 0, unit = 0, tmp;
	friostat_t fio;
	caddr_t data;
	mode_t mode;

	unit = MINOR(in->i_rdev);
	if (unit < 0 || unit > IPL_LOGMAX)
		return -ENXIO;

	if (fr_running <= 0) {
		if (unit != IPL_LOGIPF)
			return -EIO;
		if (cmd != SIOCIPFGETNEXT && cmd != SIOCIPFGET &&
		    cmd != SIOCIPFSET && cmd != SIOCFRENB && cmd != SIOCGETFS)
			return -EIO;
	}

	mode = fp->f_mode;
	data = (caddr_t)arg;

	error = fr_ioctlswitch(unit, data, cmd, mode);
	if (error != -1) {
		SPL_X(s);
		if (error > 0)
			error = -error;
		return error;
	}

	error = 0;

	switch (cmd)
	{
	case FIONREAD :
#ifdef IPFILTER_LOG
		bcopy(&iplused[IPL_LOGIPF], (caddr_t)data,
		         sizeof(iplused[IPL_LOGIPF]));
#endif
		break;
	case SIOCFRENB :
		if (!(mode & FWRITE))
			error = EPERM;
		else {
			bcopy(data, &tmp, sizeof(tmp));
			if (tmp) {
				if (fr_running > 0)
					error = 0;
				else
					error = iplattach();
				if (error == 0)
					fr_running = 1;
				else
					(void) ipldetach();
			} else {
				error = ipldetach();
				if (error == 0)
					fr_running = -1;
			}
		}
		break;
	case SIOCIPFSET :
		if (!(mode & FWRITE)) {
			error = EPERM;
			break;
		}
	case SIOCIPFGETNEXT :
	case SIOCIPFGET :
		error = fr_ipftune(cmd, data);
		break;
	case SIOCSETFF :
		if (!(mode & FWRITE))
			error = EPERM;
		else
			bcopy(data, &fr_flags, sizeof(fr_flags));
		break;
	case SIOCGETFF :
		bcopy(&fr_flags, data, sizeof(fr_flags));
		break;
	case SIOCFUNCL :
		error = fr_resolvefunc(data);
		break;
	case SIOCINAFR :
	case SIOCRMAFR :
	case SIOCADAFR :
	case SIOCZRLST :
		if (!(mode & FWRITE))
			error = EPERM;
		else
			error = frrequest(unit, cmd, data, fr_active, 1);
		break;
	case SIOCINIFR :
	case SIOCRMIFR :
	case SIOCADIFR :
		if (!(mode & FWRITE))
			error = EPERM;
		else
			error = frrequest(unit, cmd, data, 1 - fr_active, 1);
		break;
	case SIOCSWAPA :
		if (!(mode & FWRITE))
			error = EPERM;
		else {
			bzero((char *)frcache, sizeof(frcache[0]) * 2);
			*(u_int *)data = fr_active;
			fr_active = 1 - fr_active;
		}
		break;
	case SIOCGETFS :
		fr_getstat(&fio);
		error = fr_outobj(data, &fio, IPFOBJ_IPFSTAT);
		break;
	case	SIOCFRZST :
		if (!(mode & FWRITE))
			error = EPERM;
		else
			error = frzerostats(data);
		break;
	case	SIOCIPFFL :
		if (!(mode & FWRITE))
			error = EPERM;
		else {
			bcopy(data, &tmp, sizeof(tmp));
			tmp = frflush(unit, tmp);
			bcopy(&tmp, data, sizeof(tmp));
		}
		break;
	case SIOCSTLCK :
		error = COPYIN(data, &tmp, sizeof(tmp));
		if (error == 0) {
			fr_state_lock = tmp;
			fr_nat_lock = tmp;
			fr_frag_lock = tmp;
			fr_auth_lock = tmp;
		} else
			error = EFAULT;
		break;
#ifdef	IPFILTER_LOG
	case	SIOCIPFFB :
		if (!(mode & FWRITE))
			error = EPERM;
		else
			*(int *)data = ipflog_clear(unit);
		break;
#endif /* IPFILTER_LOG */
	case SIOCGFRST :
		error = fr_outobj(data, fr_fragstats(), IPFOBJ_FRAGSTAT);
		break;
	case SIOCFRSYN :
		if (!(mode & FWRITE))
			error = EPERM;
		else {
			frsync();
		}
		break;
	default :
		error = EINVAL;
		break;
	}
	SPL_X(s);
	if (error > 0)
		error = -error;
	return error;
}


u_32_t fr_newisn(fin)
fr_info_t *fin;
{
	u_32_t isn;

	isn = secure_tcp_sequence_number(fin->fin_daddr, fin->fin_saddr,
					 fin->fin_dport, fin->fin_sport);
	return isn;
}


int fr_send_reset(fin)
fr_info_t *fin;
{
	tcphdr_t *tcp, *tcp2;
	int tlen, hlen;
#ifdef	USE_INET6
	ip6_t *ip6;
#endif
	ip_t *ip;
	mb_t *m;

	tcp = fin->fin_dp;
	if (tcp->th_flags & TH_RST)
		return -1;

#ifndef	IPFILTER_CKSUM
	if (fr_checkl4sum(fin) == -1)
		return -1;
#endif

	tlen = (tcp->th_flags & (TH_SYN|TH_FIN)) ? 1 : 0;
#ifdef	USE_INET6
	if (fin->fin_v == 6)
		hlen = sizeof(ip6_t);
	else
#endif
		hlen = sizeof(ip_t);
	hlen += sizeof(*tcp2);
	m = alloc_skb(hlen + 16, GFP_ATOMIC);
	if (m == NULL)
		return -1;

	m->data += 16;
	bzero(MTOD(m, char *), hlen);
	tcp2 = (struct tcphdr *)(MTOD(m, char *) + hlen - sizeof(*tcp2));
	tcp2->th_dport = tcp->th_sport;
	tcp2->th_sport = tcp->th_dport;
	if (tcp->th_flags & TH_ACK) {
		tcp2->th_seq = tcp->th_ack;
		tcp2->th_flags = TH_RST;
	} else {
		tcp2->th_ack = ntohl(tcp->th_seq);
		tcp2->th_ack += tlen;
		tcp2->th_ack = htonl(tcp2->th_ack);
		tcp2->th_flags = TH_RST|TH_ACK;
	}
	tcp2->th_off = sizeof(struct tcphdr) >> 2;

	/*
	 * This is to get around a bug in the Solaris 2.4/2.5 TCP checksum
	 * computation that is done by their put routine.
	 */
#ifdef	USE_INET6
	if (fin->fin_v == 6) {
		ip6 = MTOD(m, ip6_t *);
		ip6->ip6_src = fin->fin_dst6;
		ip6->ip6_dst = fin->fin_src6;
		ip6->ip6_plen = htons(sizeof(*tcp));
		ip6->ip6_nxt = IPPROTO_TCP;
	} else
#endif
	{
		ip = MTOD(m, ip_t *);
		ip->ip_src.s_addr = fin->fin_daddr;
		ip->ip_dst.s_addr = fin->fin_saddr;
		ip->ip_id = fr_nextipid(fin);
		ip->ip_hl = sizeof(*ip) >> 2;
		ip->ip_p = IPPROTO_TCP;
		ip->ip_len = htons(sizeof(*ip) + sizeof(*tcp));
		ip->ip_tos = fin->fin_ip->ip_tos;
		tcp2->th_sum = fr_cksum(m, ip, IPPROTO_TCP, tcp2);
	}
	return fr_send_ip(fin, m, &m);
}


static int fr_send_ip(fin, sk, skp)
fr_info_t *fin;
struct sk_buff *sk, **skp;
{
	ip_t *ip, *oip;

	ip = MTOD(sk, ip_t *);
	oip = fin->fin_ip;

	ip->ip_v = fin->fin_v;
	switch (fin->fin_v)
	{
	case 4 :
		ip->ip_hl = sizeof(*oip) >> 2;
		ip->ip_tos = oip->ip_tos;
		ip->ip_id = oip->ip_id;
		ip->ip_off = 0;
		ip->ip_ttl = sysctl_ip_default_ttl;
		ip->ip_sum = 0;
		break;
	default :
		return EINVAL;
	}
	return fr_fastroute(sk, skp, fin, NULL);
}


int fr_verifysrc(fin)
fr_info_t *fin;
{
	return 0;
}


void fr_checkv4sum(fin)
fr_info_t *fin;
{
	/*
	 * Linux 2.4.20-8smp (RedHat 9)
	 * Because ip_input() on linux clears the checksum flag in the sk_buff
	 * before calling the netfilter hook, it is not possible to take
	 * advantage of the work already done by the hardware.
	 */
#ifdef IPFILTER_CKSUM
	if (fr_checkl4sum(fin) == -1)
		fin->fin_flx |= FI_BAD;
#endif
}


int fr_send_icmp_err(type, fin, isdst)
int type;
fr_info_t *fin;
int isdst;
{
	struct in_addr dst4;
	struct icmp *icmp;
	int hlen, code;
	u_short sz;
#ifdef	USE_INET6
	ip6_t *ip6;
	mb_t *mb;
#endif
	ip_t *ip;
	mb_t *m;

	if ((type < 0) || (type > ICMP_MAXTYPE))
		return -1;

	code = fin->fin_icode;
#ifdef USE_INET6
	if ((code < 0) || (code > sizeof(icmptoicmp6unreach)/sizeof(int)))
		return -1;
#endif

#ifndef	IPFILTER_CKSUM
	if (fr_checkl4sum(fin) == -1)
		return -1;
#endif

#ifdef	USE_INET6
	mb = fin->fin_qfm;

	if (fin->fin_v == 6) {
		sz = sizeof(ip6_t);
		sz += MIN(mb->b_wptr - mb->b_rptr, 512);
		hlen = sizeof(ip6_t);
		type = icmptoicmp6types[type];
		if (type == ICMP6_DST_UNREACH)
			code = icmptoicmp6unreach[code];
	} else
#endif
	{
		if ((fin->fin_p == IPPROTO_ICMP) && !(fin->fin_flx & FI_SHORT))
			switch (ntohs(fin->fin_data[0]) >> 8)
			{
			case ICMP_ECHO :
			case ICMP_TSTAMP :
			case ICMP_IREQ :
			case ICMP_MASKREQ :
				break;
			default :
				return 0;
			}

		sz = sizeof(ip_t) * 2;
		sz += 8;		/* 64 bits of data */
		hlen = sizeof(ip_t);
	}

	sz += offsetof(struct icmp, icmp_ip);
	m = alloc_skb(hlen + 16, GFP_ATOMIC);
	if (m == NULL)
		return -1;
	m->data += 16;
	bzero(MTOD(m, char *), (size_t)sz);
	icmp = (struct icmp *)(MTOD(m, char *) + hlen);
	icmp->icmp_type = type & 0xff;
	icmp->icmp_code = code & 0xff;
#ifdef	icmp_nextmtu
	if (type == ICMP_UNREACH && (qif->qf_max_frag != 0) &&
	    fin->fin_icode == ICMP_UNREACH_NEEDFRAG)
		icmp->icmp_nextmtu = htons(qif->qf_max_frag);
#endif

#ifdef	USE_INET6
	if (fin->fin_v == 6) {
		struct in6_addr dst6;
		int csz;

		if (isdst == 0) {
			if (fr_ifpaddr(6, FRI_NORMAL, qif->qf_ill,
				       (struct in_addr *)&dst6, NULL) == -1)
				return -1;
		} else
			dst6 = fin->fin_dst6;

		csz = sz;
		sz -= sizeof(ip6_t);
		ip6 = (ip6_t *)m->b_rptr;
		ip6->ip6_plen = htons((u_short)sz);
		ip6->ip6_nxt = IPPROTO_ICMPV6;
		ip6->ip6_src = dst6;
		ip6->ip6_dst = fin->fin_src6;
		sz -= offsetof(struct icmp, icmp_ip);
		bcopy((char *)mb->b_rptr, (char *)&icmp->icmp_ip, sz);
		icmp->icmp_cksum = csz - sizeof(ip6_t);
	} else
#endif
	{
		ip = MTOD(m, ip_t *);
		ip->ip_hl = sizeof(*ip) >> 2;
		ip->ip_p = IPPROTO_ICMP;
		ip->ip_id = fin->fin_ip->ip_id;
		ip->ip_tos = fin->fin_ip->ip_tos;
		ip->ip_len = htons((u_short)sz);
		if (isdst == 0) {
			if (fr_ifpaddr(4, FRI_NORMAL, fin->fin_ifp,
				       &dst4, NULL) == -1)
				return -1;
		} else
			dst4 = fin->fin_dst;
		ip->ip_src = dst4;
		ip->ip_dst = fin->fin_src;
		bcopy((char *)fin->fin_ip, (char *)&icmp->icmp_ip,
		      sizeof(*fin->fin_ip));
		bcopy((char *)fin->fin_ip + fin->fin_hlen,
		      (char *)&icmp->icmp_ip + sizeof(*fin->fin_ip), 8);
		icmp->icmp_cksum = ipf_cksum((u_short *)icmp,
					     sz - sizeof(ip_t));
	}

	/*
	 * Need to exit out of these so we don't recursively call rw_enter
	 * from fr_qout.
	 */
	return fr_send_ip(fin, m, &m);
}


u_short fr_nextipid(fin)
fr_info_t *fin;
{
	ip_t ip;

	__ip_select_ident(&ip, NULL);
	return ip.ip_id;
}


/*ARGSUSED*/
int fr_fastroute(min, mp, fin, dst)
mb_t *min, **mp;
fr_info_t *fin;
frdest_t *dst;
{
	int result;

	result = ip_queue_xmit(min);
	return result;
}


int fr_ifpaddr(v, atype, ifptr, inp, inpmask)
int v, atype;
void *ifptr;
struct in_addr *inp, *inpmask;
{
	struct sockaddr_in sin, sinmask;
	struct in_ifaddr *ifa;
	struct net_device *dev;
	struct in_device *ifp;

	dev = ifptr;
	ifp = __in_dev_get(dev);

	if (v == 4)
		inp->s_addr = 0;
#ifdef USE_INET6
	else if (v == 6)
		return -1;
#endif

	ifa = ifp->ifa_list;
	while (ifa != NULL) {
		if (ifa->ifa_flags & IFA_F_SECONDARY)
			continue;
		break;
	}

	if (ifa == NULL)
		return -1;

	sin.sin_family = AF_INET;
	sinmask.sin_addr.s_addr = ifa->ifa_mask;
	if (atype == FRI_BROADCAST)
		sin.sin_addr.s_addr = ifa->ifa_broadcast;
	else if (atype == FRI_PEERADDR)
		sin.sin_addr.s_addr = ifa->ifa_address;
	else
		sin.sin_addr.s_addr = ifa->ifa_local;

	return fr_ifpfillv4addr(atype, (struct sockaddr_in *)&sin,
				(struct sockaddr_in *)&sinmask, inp, inpmask);
}


void m_copydata(m, off, len, cp)
mb_t *m;
int off, len;
caddr_t cp;
{
	bcopy(MTOD(m, char *) + off, cp, len);
}


static	int	frzerostats(data)
caddr_t	data;
{
	friostat_t fio;
	int error;

	fr_getstat(&fio);
	error = copyoutptr(&fio, data, sizeof(fio));
	if (error)
		return EFAULT;

	bzero((char *)frstats, sizeof(*frstats) * 2);

	return 0;
}


int iplattach()
{
	int err, i;

	SPL_NET(s);
	if (fr_running > 0) {
		SPL_X(s);
		return -EBUSY;
	}

	bzero((char *)frcache, sizeof(frcache));
	MUTEX_INIT(&ipf_rw, "ipf rw mutex");
	MUTEX_INIT(&ipl_mutex, "ipf log mutex");
	MUTEX_INIT(&ipf_timeoutlock, "ipf timeout lock mutex");
	RWLOCK_INIT(&ipf_global, "ipf global rwlock");
	RWLOCK_INIT(&ipf_mutex, "ipf global mutex rwlock");
	RWLOCK_INIT(&ipf_ipidfrag, "ipf IP NAT-Frag rwlock");

	for (i = 0; i < sizeof(ipf_hooks)/sizeof(ipf_hooks[0]); i++) {
		err = nf_register_hook(&ipf_hooks[i]);
		if (err != 0)
			return err;
	}

	if (fr_initialise() == -1) {
		for (i = 0; i < sizeof(ipf_hooks)/sizeof(ipf_hooks[0]); i++)
			nf_unregister_hook(&ipf_hooks[i]);
		SPL_X(s);
		return EIO;
	}

	bzero((char *)frcache, sizeof(frcache));
#ifdef notyet
	if (fr_control_forwarding & 1)
		ipv4_devconf.forwarding = 1;
#endif

	SPL_X(s);
	/* timeout(fr_slowtimer, NULL, (hz / IPF_HZ_DIVIDE) * IPF_HZ_MULT); */
	return 0;
}


int ipldetach()
{
	int i;

	if (fr_refcnt)
		return EBUSY;
	SPL_NET(s);

	for (i = 0; i < sizeof(ipf_hooks)/sizeof(ipf_hooks[0]); i++)
		nf_unregister_hook(&ipf_hooks[i]);
	/* untimeout(fr_slowtimer, NULL); */

#ifdef notyet
	if (fr_control_forwarding & 2)
		ipv4_devconf.forwarding = 0;
#endif

	fr_deinitialise();

	(void) frflush(IPL_LOGIPF, FR_INQUE|FR_OUTQUE|FR_INACTIVE);
	(void) frflush(IPL_LOGIPF, FR_INQUE|FR_OUTQUE);

	MUTEX_DESTROY(&ipf_timeoutlock);
	MUTEX_DESTROY(&ipl_mutex);
	MUTEX_DESTROY(&ipf_rw);
	RW_DESTROY(&ipf_mutex);
	RW_DESTROY(&ipf_global);
	RW_DESTROY(&ipf_ipidfrag);

	SPL_X(s);

	return 0;
}


static u_int ipf_linux_inout(hooknum, skbp, inifp, outifp, okfn)
u_int hooknum;
struct sk_buff **skbp;
const struct net_device *inifp, *outifp;
int (*okfn)(struct sk_buff *);
{
	int result, hlen, dir;
	void *ifp;
	ip_t *ip;
	mb_t *sk;

	if (inifp == NULL && outifp != NULL) {
		dir = IPF_OUT;
		ifp = (void *)outifp;
	} else if (inifp != NULL && outifp == NULL) {
		dir = IPF_IN;
		ifp = (void *)inifp;
	} else
		return NF_DROP;

	sk = *skbp;
	ip = MTOD(sk, ip_t *);
	if (ip->ip_v == 4) {
		hlen = ip->ip_hl << 2;
		ip->ip_len = ntohs(ip->ip_len);
		ip->ip_off = ntohs(ip->ip_off);
#ifdef USE_INET6
	} else if (ip->ip_v == 6) {
		hlen = sizeof(ip6_t);
#endif
	} else
		return NF_DROP;
	result = fr_check(ip, hlen, (struct net_device *)ifp, dir, skbp);

	/*
	 * This is kind of not always right...*skbp == NULL might really be
	 * a drop but Linux expects *skbp != NULL for NF_DROP.
	 */
	if (*skbp == NULL)
		return NF_STOLEN;

	if (result != 0)
		return NF_DROP;
	if (ip->ip_v == 4) {
		ip->ip_len = htons(ip->ip_len);
		ip->ip_off = htons(ip->ip_off);
	}
	return NF_ACCEPT;
}


INLINE void ipf_read_enter(rwlk)
ipfrwlock_t *rwlk;
{
#ifdef IPFDEBUG
	if (rwlk->ipf_magic != 0x97dd8b3a) {
		printk("ipf_read_enter:rwlk %p ipf_magic 0x%x\n",
			rwlk, rwlk->ipf_magic);
		rwlk->ipf_magic = 0;
		*((int *)rwlk->ipf_magic) = 1;
	}
#endif
	read_lock(&rwlk->ipf_lk);
	ATOMIC_INC32(rwlk->ipf_isr);
}


INLINE void ipf_write_enter(rwlk)
ipfrwlock_t *rwlk;
{
#ifdef IPFDEBUG
	if (rwlk->ipf_magic != 0x97dd8b3a) {
		printk("ipf_write_enter:rwlk %p ipf_magic 0x%x\n",
			rwlk, rwlk->ipf_magic);
		rwlk->ipf_magic = 0;
		*((int *)rwlk->ipf_magic) = 1;
	}
#endif
	write_lock(&rwlk->ipf_lk);
	rwlk->ipf_isw = 1;
}


INLINE void ipf_rw_exit(rwlk)
ipfrwlock_t *rwlk;
{
#ifdef IPFDEBUG
	if (rwlk->ipf_magic != 0x97dd8b3a) {
		printk("ipf_rw_exit:rwlk %p ipf_magic 0x%x\n",
			rwlk, rwlk->ipf_magic);
		rwlk->ipf_magic = 0;
		*((int *)rwlk->ipf_magic) = 1;
	}
#endif
	if (rwlk->ipf_isw > 0) {
		rwlk->ipf_isw = 0;
		write_unlock(&rwlk->ipf_lk);
	} else if (rwlk->ipf_isr > 0) {
		ATOMIC_DEC32(rwlk->ipf_isr);
		read_unlock(&rwlk->ipf_lk);
	} else {
		panic("rwlk->ipf_isw %d isr %d rwlk %p name [%s]\n",
		      rwlk->ipf_isw, rwlk->ipf_isr, rwlk, rwlk->ipf_lname);
	}
}


/*
 * This is not a perfect solution for a downgrade because we can lose the lock
 * on the object of desire.
 */
INLINE void ipf_rw_downgrade(rwlk)
ipfrwlock_t *rwlk;
{
	ipf_rw_exit(rwlk);
	ipf_write_enter(rwlk);
}
