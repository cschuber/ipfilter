/*
 * Copyright (C) 2002-2008 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 */
#include "ipf.h"
#include "ipt.h"
#include <sys/ioctl.h>
#include <sys/file.h>

#if !defined(lint)
static const char sccsid[] = "@(#)ipt.c	1.19 6/3/96 (C) 1993-2000 Darren Reed";
static const char rcsid[] = "@(#)$Id$";
#endif

extern	char	*optarg;
extern	struct ipread	pcap, iptext, iphex;
extern	struct ifnet	*get_unit(char *, int);
extern	void	init_ifp(void);
extern	ipnat_t	*natparse(char *, int);
extern	hostmap_t **ipf_hm_maptable;
extern	hostmap_t *ipf_hm_maplist;

ipfmutex_t	ipl_mutex, ipf_auth_mx, ipf_rw, ipf_stinsert;
ipfmutex_t	ipf_nat_new, ipf_natio, ipf_timeoutlock;
ipfrwlock_t	ipf_mutex, ipf_global, ipf_ipidfrag, ip_poolrw, ipf_frcache;
ipfrwlock_t	ipf_frag, ipf_state, ipf_nat, ipf_natfrag, ipf_authlk;
ipfrwlock_t	ipf_tokens;
int	ipf_fd = -1;
int	ipnat_fd = -1;
int	ipstate_fd = -1;
int	ippool_fd = -1;
int	opts = OPT_DONTOPEN;
int	use_inet6 = 0;
int	docksum = 0;
int	pfil_delayed_copy = 0;
int	main(int, char *[]);
int	loadrules(char *, int);
int	kmemcpy(char *, long, int);
int     kstrncpy(char *, long, int n);
int	ipf_check_result(u_32_t);
	int pass;
int	blockreason;
int	testmode = 0;
void	dumpnat(void *);
void	dumpstate(ipf_main_softc_t *, void *);
void	dumpgroups_test(ipf_main_softc_t *);
void	dumprules_test(frentry_t *);
void	dumpnat_live();
void	dumpstate_live();
void	dumplookup_live();
void	dumpgroups_live();
void	drain_log(char *);
void	fixv4sums(mb_t *, ip_t *);
void	test_usermode();
void	test_kernmode();
void	print_result(int, int, mb_t *, mb_t *);
void	user_init(ioctlcmd_t);
void	ipf_walker(frentry_t *);

#if defined(__NetBSD__) || defined(__OpenBSD__) || SOLARIS || \
	(_BSDI_VERSION >= 199701) || (__FreeBSD_version >= 300000) || \
	defined(__osf__) || defined(linux)
int ipftestioctl(int, ioctlcmd_t, ...);
int ipnattestioctl(int, ioctlcmd_t, ...);
int ipstatetestioctl(int, ioctlcmd_t, ...);
int ipauthtestioctl(int, ioctlcmd_t, ...);
int ipscantestioctl(int, ioctlcmd_t, ...);
int ipsynctestioctl(int, ioctlcmd_t, ...);
int ipooltestioctl(int, ioctlcmd_t, ...);
#else
int ipftestioctl(dev_t, ioctlcmd_t, void *);
int ipnattestioctl(dev_t, ioctlcmd_t, void *);
int ipstatetestioctl(dev_t, ioctlcmd_t, void *);
int ipauthtestioctl(dev_t, ioctlcmd_t, void *);
int ipsynctestioctl(dev_t, ioctlcmd_t, void *);
int ipscantestioctl(dev_t, ioctlcmd_t, void *);
int ipooltestioctl(dev_t, ioctlcmd_t, void *);
#endif

static	ioctlfunc_t	iocfunctions[IPL_LOGSIZE] = { ipftestioctl,
						      ipnattestioctl,
						      ipstatetestioctl,
						      ipauthtestioctl,
						      ipsynctestioctl,
						      ipscantestioctl,
						      ipooltestioctl,
						      NULL };
static	ipf_main_softc_t	*softc = NULL;

static struct ipread *r;
static char *ifname;
static char *datain;
static char *logout;
struct in_addr sip;
static int loaded;
static int dump;

int
main(argc,argv)
	int argc;
	char *argv[];
{
	int c, i;

	dump = 0;
	logout = NULL;
	sip.s_addr = 0;
	loaded = 0;
	r = &iptext;
	datain = NULL;
	ifname = "anon0";

	initparse();

	while ((c = getopt(argc, argv, "6bCdDF:i:I:l:M:N:P:or:RS:T:vxX")) != -1)
		switch (c)
		{
		case '6' :
#ifdef	USE_INET6
			use_inet6 = 1;
#else
			fprintf(stderr, "IPv6 not supported\n");
			exit(1);
#endif
			break;
		case 'b' :
			opts |= OPT_BRIEF;
			break;
		case 'd' :
			opts |= OPT_DEBUG;
			break;
		case 'C' :
			docksum = 1;
			break;
		case 'D' :
			dump = 1;
			break;
		case 'F' :
			if (strcasecmp(optarg, "pcap") == 0)
				r = &pcap;
			else if (strcasecmp(optarg, "hex") == 0)
				r = &iphex;
			else if (strcasecmp(optarg, "text") == 0)
				r = &iptext;
			break;
		case 'i' :
			datain = optarg;
			break;
		case 'I' :
			ifname = optarg;
			break;
		case 'l' :
			logout = optarg;
			break;
		case 'M' :
			if (strcmp(optarg, "kern") == 0) {
				ipf_fd = open(IPL_NAME, O_RDWR);
				if (ipf_fd == -1) {
					perror("open(IPL_NAME)");
					exit(1);
				}
				ipnat_fd = open(IPNAT_NAME, O_RDWR);
				if (ipnat_fd == -1) {
					perror("open(IPNAT_NAME)");
					exit(1);
				}
				ipstate_fd = open(IPSTATE_NAME, O_RDWR);
				if (ipstate_fd == -1) {
					perror("open(IPSTATE_NAME)");
					exit(1);
				}
				ippool_fd = open(IPLOOKUP_NAME, O_RDWR);
				if (ippool_fd == -1) {
					perror("open(IPLOOKUP_NAME)");
					exit(1);
				}
				testmode = 1;
				for (i = 0; i < IPL_LOGSIZE; i++)
					iocfunctions[i] = ioctl;
			}
			break;
		case 'N' :
			if (ipnat_parsefile(ipnat_fd, ipnat_addrule,
					    iocfunctions[IPL_LOGNAT],
					    optarg) == -1)
				return -1;
			loaded = 1;
			opts |= OPT_NAT;
			break;
		case 'o' :
			opts |= OPT_SAVEOUT;
			break;
		case 'P' :
			if (ippool_parsefile(ippool_fd, optarg,
					     iocfunctions[IPL_LOGLOOKUP]) == -1)
				return -1;
			loaded = 1;
			break;
		case 'r' :
			if (ipf_parsefile(ipf_fd, ipf_addrule, iocfunctions,
					  optarg) == -1)
				return -1;
			loaded = 1;
			break;
		case 'S' :
			sip.s_addr = inet_addr(optarg);
			break;
		case 'R' :
			opts |= OPT_NORESOLVE;
			break;
		case 'T' :
			ipf_dotuning(ipf_fd, optarg, iocfunctions[IPL_LOGIPF]);
			break;
		case 'v' :
			opts |= OPT_VERBOSE;
			break;
		case 'x' :
			opts |= OPT_HEX;
			break;
		}

	if (testmode == 0)
		test_usermode(r);
	else
		test_kernmode(r);
	return 0;
}


#if defined(__NetBSD__) || defined(__OpenBSD__) || SOLARIS || \
	(_BSDI_VERSION >= 199701) || (__FreeBSD_version >= 300000) || \
	defined(__osf__) || defined(linux)
int
ipftestioctl(int dev, ioctlcmd_t cmd, ...)
{
	caddr_t data;
	va_list ap;
	int i;

	if (softc == NULL)
		user_init(cmd);

	va_start(ap, cmd);
	data = va_arg(ap, caddr_t);
	va_end(ap);

	i = ipfioctl(softc, IPL_LOGIPF, cmd, data, FWRITE|FREAD);
	if (opts & OPT_DEBUG)
		fprintf(stderr, "ipfioctl(IPF,%#x,%p) = %d (%d)\n",
			(u_int)cmd, data, i, softc->ipf_interror);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int
ipnattestioctl(int dev, ioctlcmd_t cmd, ...)
{
	caddr_t data;
	va_list ap;
	int i;

	if (softc == NULL)
		user_init(cmd);

	va_start(ap, cmd);
	data = va_arg(ap, caddr_t);
	va_end(ap);

	i = ipfioctl(softc, IPL_LOGNAT, cmd, data, FWRITE|FREAD);
	if (opts & OPT_DEBUG)
		fprintf(stderr, "ipfioctl(NAT,%#x,%p) = %d\n",
			(u_int)cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int
ipstatetestioctl(int dev, ioctlcmd_t cmd, ...)
{
	caddr_t data;
	va_list ap;
	int i;

	if (softc == NULL)
		user_init(cmd);

	va_start(ap, cmd);
	data = va_arg(ap, caddr_t);
	va_end(ap);

	i = ipfioctl(softc, IPL_LOGSTATE, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "ipfioctl(STATE,%#x,%p) = %d\n",
			(u_int)cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int
ipauthtestioctl(int dev, ioctlcmd_t cmd, ...)
{
	caddr_t data;
	va_list ap;
	int i;

	if (softc == NULL)
		user_init(cmd);

	va_start(ap, cmd);
	data = va_arg(ap, caddr_t);
	va_end(ap);

	i = ipfioctl(softc, IPL_LOGAUTH, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "ipfioctl(AUTH,%#x,%p) = %d\n",
			(u_int)cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int
ipscantestioctl(int dev, ioctlcmd_t cmd, ...)
{
	caddr_t data;
	va_list ap;
	int i;

	if (softc == NULL)
		user_init(cmd);

	va_start(ap, cmd);
	data = va_arg(ap, caddr_t);
	va_end(ap);

	i = ipfioctl(softc, IPL_LOGSCAN, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "ipfioctl(SCAN,%#x,%p) = %d\n",
			(u_int)cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int
ipsynctestioctl(int dev, ioctlcmd_t cmd, ...)
{
	caddr_t data;
	va_list ap;
	int i;

	if (softc == NULL)
		user_init(cmd);

	va_start(ap, cmd);
	data = va_arg(ap, caddr_t);
	va_end(ap);

	i = ipfioctl(softc, IPL_LOGSYNC, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "ipfioctl(SYNC,%#x,%p) = %d\n",
			(u_int)cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int
ipooltestioctl(int dev, ioctlcmd_t cmd, ...)
{
	caddr_t data;
	va_list ap;
	int i;

	if (softc == NULL)
		user_init(cmd);

	va_start(ap, cmd);
	data = va_arg(ap, caddr_t);
	va_end(ap);

	i = ipfioctl(softc, IPL_LOGLOOKUP, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "ipfioctl(POOL,%#x,%p) = %d (%d)\n",
			(u_int)cmd, data, i, softc->ipf_interror);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}
#else
int
ipftestioctl(dev, cmd, data)
	dev_t dev;
	ioctlcmd_t cmd;
	void *data;
{
	int i;

	if (softc == NULL)
		user_init(cmd);

	i = ipfioctl(softc, IPL_LOGIPF, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "ipfioctl(IPF,%#x,%p) = %d (%d)\n",
			cmd, data, i, softc->ipf_interror);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int
ipnattestioctl(dev, cmd, data)
	dev_t dev;
	ioctlcmd_t cmd;
	void *data;
{
	int i;

	if (softc == NULL)
		user_init(cmd);

	i = ipfioctl(softc, IPL_LOGNAT, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "ipfioctl(NAT,%#x,%p) = %d\n", cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int
ipstatetestioctl(dev, cmd, data)
	dev_t dev;
	ioctlcmd_t cmd;
	void *data;
{
	int i;

	if (softc == NULL)
		user_init(cmd);

	i = ipfioctl(softc, IPL_LOGSTATE, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "ipfioctl(STATE,%#x,%p) = %d\n", cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int
ipauthtestioctl(dev, cmd, data)
	dev_t dev;
	ioctlcmd_t cmd;
	void *data;
{
	int i;

	if (softc == NULL)
		user_init(cmd);

	i = ipfioctl(softc, IPL_LOGAUTH, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "ipfioctl(AUTH,%#x,%p) = %d\n", cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int
ipsynctestioctl(dev, cmd, data)
	dev_t dev;
	ioctlcmd_t cmd;
	void *data;
{
	int i;

	if (softc == NULL)
		user_init(cmd);

	i = ipfioctl(softc, IPL_LOGSYNC, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "ipfioctl(SYNC,%#x,%p) = %d\n", cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int
ipscantestioctl(dev, cmd, data)
	dev_t dev;
	ioctlcmd_t cmd;
	void *data;
{
	int i;

	if (softc == NULL)
		user_init(cmd);

	i = ipfioctl(softc, IPL_LOGSCAN, cmd, data, FWRITE|FREAD);
	if ((opts & OPT_DEBUG) || (i != 0))
		fprintf(stderr, "ipfioctl(SCAN,%#x,%p) = %d\n", cmd, data, i);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}


int
ipooltestioctl(dev, cmd, data)
	dev_t dev;
	ioctlcmd_t cmd;
	void *data;
{
	int i;

	if (softc == NULL)
		user_init(cmd);

	i = ipfioctl(softc, IPL_LOGLOOKUP, cmd, data, FWRITE|FREAD);
	if (opts & OPT_DEBUG)
		fprintf(stderr, "ipfioctl(POOL,%#x,%p) = %d (%d)\n",
			cmd, data, i, softc->ipf_interror);
	if (i != 0) {
		errno = i;
		return -1;
	}
	return 0;
}
#endif


int
kmemcpy(addr, offset, size)
	char *addr;
	long offset;
	int size;
{
	bcopy((char *)offset, addr, size);
	return 0;
}


int
kstrncpy(buf, pos, n)
	char *buf;
	long pos;
	int n;
{
	char *ptr;

	ptr = (char *)pos;

	while ((n > 0) && (*buf++ = *ptr++))
		;
	return 0;
}


/*
 * Display the built up NAT table rules and mapping entries.
 */
void
dumpnat(arg)
	void *arg;
{
	ipf_nat_softc_t *softn = arg;
	hostmap_t *hm;
	ipnat_t	*ipn;
	nat_t *nat;

	printf("List of active MAP/Redirect filters:\n");
	for (ipn = softn->ipf_nat_list; ipn != NULL; ipn = ipn->in_next)
		printnat(ipn, opts & (OPT_DEBUG|OPT_VERBOSE));
	printf("\nList of active sessions:\n");
	for (nat = softn->ipf_nat_instances; nat; nat = nat->nat_next) {
		printactivenat(nat, opts, 0);
		if (nat->nat_aps)
			printf("\tproxy active\n");
	}

	printf("\nHostmap table:\n");
	for (hm = softn->ipf_hm_maplist; hm != NULL; hm = hm->hm_next)
		printhostmap(hm, hm->hm_hv);
}


void
dumpgroups_test(softc)
	ipf_main_softc_t *softc;
{
	frgroup_t *fg;
	int i;

	printf("List of groups configured (set 0)\n");
	for (i = 0; i < IPL_LOGSIZE; i++)
		for (fg =  softc->ipf_groups[i][0]; fg != NULL;
		     fg = fg->fg_next) {
			printf("Dev.%d. Group %s Ref %d Flags %#x\n",
				i, fg->fg_name, fg->fg_ref, fg->fg_flags);
			dumprules_test(fg->fg_start);
		}

	printf("List of groups configured (set 1)\n");
	for (i = 0; i < IPL_LOGSIZE; i++)
		for (fg =  softc->ipf_groups[i][1]; fg != NULL;
		     fg = fg->fg_next) {
			printf("Dev.%d. Group %s Ref %d Flags %#x\n",
				i, fg->fg_name, fg->fg_ref, fg->fg_flags);
			dumprules_test(fg->fg_start);
		}

	printf("Rules configured (set 0, in)\n");
	dumprules_test(softc->ipf_rules[0][0]);
	printf("Rules configured (set 0, out)\n");
	dumprules_test(softc->ipf_rules[1][0]);
	printf("Rules configured (set 1, in)\n");
	dumprules_test(softc->ipf_rules[0][1]);
	printf("Rules configured (set 1, out)\n");
	dumprules_test(softc->ipf_rules[1][1]);

	printf("Accounting rules configured (set 0, in)\n");
	dumprules_test(softc->ipf_acct[0][0]);
	printf("Accounting rules configured (set 0, out)\n");
	dumprules_test(softc->ipf_acct[1][0]);
	printf("Accounting rules configured (set 1, in)\n");
	dumprules_test(softc->ipf_acct[0][1]);
	printf("Accounting rules configured (set 1, out)\n");
	dumprules_test(softc->ipf_acct[1][1]);
}

void
dumprules_test(rulehead)
	frentry_t *rulehead;
{
	frentry_t *fr;

	for (fr = rulehead; fr != NULL; fr = fr->fr_next) {
		int sopts = opts;

		opts |= OPT_HITS;
		printfr(fr, ipftestioctl);
		opts = sopts;
	}
}


void
drain_log(filename)
	char *filename;
{
	char buffer[DEFAULT_IPFLOGSIZE];
	struct iovec iov;
	struct uio uio;
	size_t resid;
	int fd, i;

	fd = open(filename, O_CREAT|O_TRUNC|O_WRONLY, 0644);
	if (fd == -1) {
		perror("drain_log:open");
		return;
	}

	for (i = 0; i <= IPL_LOGMAX; i++)
		while (1) {
			bzero((char *)&iov, sizeof(iov));
			iov.iov_base = buffer;
			iov.iov_len = sizeof(buffer);

			bzero((char *)&uio, sizeof(uio));
			uio.uio_iov = &iov;
			uio.uio_iovcnt = 1;
			uio.uio_resid = iov.iov_len;
			resid = uio.uio_resid;

			if (ipf_log_read(softc, i, &uio) == 0) {
				/*
				 * If nothing was read then break out.
				 */
				if (uio.uio_resid == resid)
					break;
				write(fd, buffer, resid - uio.uio_resid);
			} else
				break;
	}

	close(fd);
}


void
fixv4sums(m, ip)
	mb_t *m;
	ip_t *ip;
{
	u_char *csump, *hdr, p;
	fr_info_t tmp;
	int len;

	p = 0;
	len = 0;
	bzero((char *)&tmp, sizeof(tmp));

	csump = (u_char *)ip;
	if (IP_V(ip) == 4) {
		ip->ip_sum = 0;
		ip->ip_sum = ipf_cksum((u_short *)ip, IP_HL(ip) << 2);
		tmp.fin_hlen = IP_HL(ip) << 2;
		csump += IP_HL(ip) << 2;
		p = ip->ip_p;
		len = ntohs(ip->ip_len);
#ifdef USE_INET6
	} else if (IP_V(ip) == 6) {
		tmp.fin_hlen = sizeof(ip6_t);
		csump += sizeof(ip6_t);
		p = ((ip6_t *)ip)->ip6_nxt;
		len = ntohs(((ip6_t *)ip)->ip6_plen);
		len += sizeof(ip6_t);
#endif
	}
	tmp.fin_plen = len;
	tmp.fin_dlen = len - tmp.fin_hlen;

	switch (p)
	{
	case IPPROTO_TCP :
		hdr = csump;
		csump += offsetof(tcphdr_t, th_sum);
		break;
	case IPPROTO_UDP :
		hdr = csump;
		csump += offsetof(udphdr_t, uh_sum);
		break;
	case IPPROTO_ICMP :
		hdr = csump;
		csump += offsetof(icmphdr_t, icmp_cksum);
		break;
	default :
		csump = NULL;
		hdr = NULL;
		break;
	}
	if (hdr != NULL) {
		tmp.fin_m = m;
		tmp.fin_mp = &m;
		tmp.fin_dp = hdr;
		tmp.fin_ip = ip;
		tmp.fin_plen = len;
		*csump = 0;
		*(u_short *)csump = fr_cksum(&tmp, ip, p, hdr);
	}
}


void
test_usermode(r)
	struct ipread *r;
{
	char	*iface;
	int	fd, i, dir;
	struct	ifnet	*ifp;
	ipf_test_pkt_t	pkt;
	mb_t	mb, *m, *n;
	int	pcount;
	ip_t	*ip;

	m = &mb;
	dir = 0;
	iface = NULL;

	i = 1;
	if (ipftestioctl(IPL_LOGIPF, SIOCFRENB, &i) != 0)
		exit(1);

	if (loaded == 0) {
		(void)fprintf(stderr,"no rules loaded\n");
		exit(-1);
	}

	if (opts & OPT_SAVEOUT)
		init_ifp();

	if (datain)
		fd = (*r->r_open)(datain);
	else
		fd = (*r->r_open)("-");

	if (fd < 0)
		exit(-1);

	pcount = 0;
	m = &mb;
	m->m_data = (char *)m->mb_buf;
	while ((i = (*r->r_readip)(m, &iface, &dir)) > 0) {

		if ((iface == NULL) || (*iface == '\0'))
			iface = ifname;
		ip = MTOD(m, ip_t *);
		m->mb_ifp = get_unit(iface, IP_V(ip));
		m->mb_len = i;
		pkt.pkt_length = i;
		pkt.pkt_direction = dir;
		pkt.pkt_result = 0;
		pkt.pkt_freed = 0;
		pkt.pkt_id = pcount++;
		pkt.pkt_flags = mb.mb_flags;

		if ((r->r_flags & R_DO_CKSUM) || docksum)
			fixv4sums(m, ip);
		if (IP_V(ip) == 4) {
			pkt.pkt_family = AF_INET;
			if (sip.s_addr)
				dir = !(sip.s_addr == ip->ip_src.s_addr);
		}
#ifdef	USE_INET6
		else {
			pkt.pkt_family = AF_INET6;
		}
#endif
		ifp = m->mb_ifp;
		blockreason = 0;
		(void) strncpy(pkt.pkt_ifname, iface, LIFNAMSIZ);
		pkt.pkt_ifname[sizeof(pkt.pkt_ifname) - 1] = '\0';
		bcopy(m->mb_buf, pkt.pkt_buf, M_LEN(m));

		errno = ipf_test_pkt(softc, &pkt);
		if (errno == 0) {
			i = ipf_check_result(pkt.pkt_result);
			if (pkt.pkt_freed == 1)
				m = NULL;
			mb.mb_len = pkt.pkt_length;
			bcopy(pkt.pkt_buf, mb.mb_buf, pkt.pkt_length);
			print_result(i, dir, m, &mb);
		}

		if (dir && (ifp != NULL) && IP_V(ip) && (m != NULL))
#if  defined(__sgi) && (IRIX < 60500)
			(*ifp->if_output)(ifp, (void *)m, NULL);
#else
# if TRU64 >= 1885
			(*ifp->if_output)(ifp, (void *)m, NULL, 0, 0);
# else
			(*ifp->if_output)(ifp, (void *)m, NULL, 0);
# endif
#endif

		while ((m != NULL) && (m != &mb)) {
			n = m->mb_next;
			freembt(m);
			m = n;
		}

		if ((opts & (OPT_BRIEF|OPT_NAT)) != (OPT_NAT|OPT_BRIEF))
			putchar('\n');
		dir = 0;
		if (iface != ifname) {
			free(iface);
			iface = ifname;
		}
		m = &mb;
		m->mb_flags = 0;
		m->mb_data = (char *)m->mb_buf;
	}

	if (i != 0)
		fprintf(stderr, "readip failed: %d\n", i);
	(*r->r_close)();

	if (logout != NULL) {
		drain_log(logout);
	}

	if (dump == 1)  {
		dumpnat(softc->ipf_nat_soft);
		dumpstate(softc, softc->ipf_state_soft);
		ipf_lookup_dump(softc, softc->ipf_state_soft);
		dumpgroups_test(softc);
	}

	ipf_fini_all(softc);

	ipf_destroy_all(softc);

	ipf_unload_all();

	ipf_mutex_clean();
	ipf_rwlock_clean();
}


void
test_kernmode(r)
	struct ipread *r;
{
	ipf_test_pkt_t pkt;
	char *iface;
	int idcount;
	int result;
	ip_t *ip;
	mb_t mb;
	char *s;
	mb_t *m;
	int dir;
	int fd;
	int i;

	if (datain)
		fd = (*r->r_open)(datain);
	else
		fd = (*r->r_open)("-");

	if (fd < 0)
		exit(-1);

	idcount = 1;
	m = &mb;
	m->m_data = (char *)m->mb_buf;
	ip = MTOD(m, ip_t *);
	while ((i = (*r->r_readip)(&mb, &iface, &dir)) > 0) {
		if ((iface == NULL) || (*iface == '\0'))
			iface = ifname;
		if ((r->r_flags & R_DO_CKSUM) || docksum)
			fixv4sums(m, ip);
		m->mb_ifp = get_unit(iface, IP_V(ip));
		pkt.pkt_length = M_LEN(m);
		pkt.pkt_direction = dir;
		pkt.pkt_result = 0;
		pkt.pkt_freed = 0;
		pkt.pkt_id = idcount++;
		pkt.pkt_flags = m->mb_flags;
		(void) strncpy(pkt.pkt_ifname, iface, LIFNAMSIZ);
		pkt.pkt_ifname[LIFNAMSIZ - 1] = '\0';
		bcopy(m->mb_buf, pkt.pkt_buf, M_LEN(m));

		s = strchr(pkt.pkt_ifname, '=');
		if (s != NULL)
			*s = '\0';
		if (IP_V(ip) == 4) {
			pkt.pkt_family = AF_INET;
			if (ntohs(ip->ip_len) != pkt.pkt_length) {
				fflush(stdout);
				fprintf(stderr,
					"ip_len(%d) != pkt_length(%d)\n",
					ntohs(ip->ip_len), pkt.pkt_length);
				abort();
			}
		}
#ifdef USE_INET6
		else if (IP_V(ip) == 6) {
			pkt.pkt_family = AF_INET6;
		}
#endif
		else {
			fflush(stdout);
			printf("mb_data %p mb_buf %p\n", mb.mb_data, mb.mb_buf);
			mb_hexdump(&mb, stdout);
			mb_hexdump(&mb, stderr);
			fprintf(stderr, "unknown IP version(%d)\n", IP_V(ip));
			abort();
		}
		if (ioctl(ipf_fd, SIOCIPFTSTPKT, &pkt) != 0) {
			perror("ioctl(SIOCIPFTSTPKT)");
			exit(1);
		}
		result = ipf_check_result(pkt.pkt_result);
		if (pkt.pkt_freed == 1)
			m = NULL;

		bcopy(pkt.pkt_buf, mb.mb_buf, pkt.pkt_length);
		blockreason = pkt.pkt_reason;
		mb.mb_len = pkt.pkt_length;
		print_result(result, dir, m, &mb);
		if ((opts & (OPT_BRIEF|OPT_NAT)) != (OPT_NAT|OPT_BRIEF))
			putchar('\n');
		m = &mb;
		m->mb_flags = 0;
		m->mb_data = (char *)m->mb_buf;
	}

	if (dump == 1) {
		int osave = opts;
		opts |= OPT_HITS;
		dumpnat_live();
		dumpstate_live();
		dumplookup_live();
		dumpgroups_live();
		opts = osave;
	}
}


void
print_result(result, dir, m, mbp)
	int result;
	int dir;
	mb_t *m;
	mb_t *mbp;
{
	if ((opts & OPT_NAT) == 0) {
		switch (result)
		{
		case -4 :
			PRINTF("preauth");
			break;
		case -3 :
			PRINTF("account");
			break;
		case -2 :
			PRINTF("auth");
			break;
		case -1 :
			PRINTF("block");
			break;
		case 0 :
			PRINTF("pass");
			break;
		case 1 :
			if (m == NULL)
				PRINTF("bad-packet");
			else
				PRINTF("nomatch");
			break;
		case -5 :
			PRINTF("block return-rst");
			break;
		case -6 :
			PRINTF("block return-icmp");
			break;
		case -7 :
			PRINTF("block return-icmp-as-dest");
			break;
		default :
			PRINTF("unrecognised return %#x\n", result);
			break;
		}
	}

	if (!(opts & OPT_BRIEF)) {
		putchar(' ');
		if (m != NULL)
			printpacket(dir, m);
		else
			printpacket(dir, mbp);
		PRINTF("--------------");
	} else if ((opts & (OPT_BRIEF|OPT_NAT)) == (OPT_NAT|OPT_BRIEF)) {
		if (m != NULL)
			printpacket(dir, m);
		else
			PRINTF("%d\n", blockreason);
	}
}


void
user_init(cmd)
	ioctlcmd_t cmd;
{
	ipf_load_all();
	softc = ipf_create_all(NULL);
	if (softc == NULL)
		exit(1);

	if (ipf_init_all(softc) == -1)
		exit(1);

	if (cmd != SIOCFRENB) {
		int i = 1;

		if (ipftestioctl(IPL_LOGIPF, SIOCFRENB, &i) != 0)
			exit(1);
	}
}


int
ipf_check_result(pass)
	u_32_t pass;
{
	if ((pass & FR_NOMATCH) != 0)
		return 1;

	if ((pass & FR_RETMASK) != 0) {
		switch (pass & FR_RETMASK)
		{
		case FR_RETRST :
			return -5;
		case FR_RETICMP :
			return -6;
		case FR_FAKEICMP :
			return -7;
		}
	}

	switch (pass & FR_CMDMASK)
	{
	case FR_PASS :
		return 0;
	case FR_BLOCK :
		return -1;
	case FR_AUTH :
		return -2;
	case FR_ACCOUNT :
		return -3;
	case FR_PREAUTH :
		return -4;
	}
	return 2;
}


void
ipf_group_walker(unit, set, info)
	int unit;
	int set;
	frgroupiter_t *info;
{
	static int done[2][IPL_LOGSIZE] = {
					   { 0, 0, 0, 0, 0, 0, 0, 0},
					   { 0, 0, 0, 0, 0, 0, 0, 0}
					  };

	if (done[set][unit] == 0) {
		printf("Dev.%d. Group %s Flags %#x\n",
			unit, info->gi_name, info->gi_flags);
		done[set][unit] = 1;
	}

	if (info->gi_name[0] != '\0')
		walk_live_fr_rules(0, info->gi_flags, 0, info->gi_name,
				   ipf_walker);
}


void
ipf_walker(fp)
        frentry_t *fp;
{
	printfr(fp, ioctl);
}


void
dumpgroups_live()
{

	printf("List of groups configured (set 0)\n");
	walk_live_groups(-1, 0, ipf_group_walker);
	printf("List of groups configured (set 1)\n");
	walk_live_groups(-1, 1, ipf_group_walker);

	printf("Rules configured (set 0, in)\n");
	walk_live_fr_rules(0, F_IN, 0, NULL, ipf_walker);
	printf("Rules configured (set 0, out)\n");
	walk_live_fr_rules(0, F_OUT, 0, NULL, ipf_walker);
	printf("Rules configured (set 1, in)\n");
	walk_live_fr_rules(0, F_IN, 1, NULL, ipf_walker);
	printf("Rules configured (set 1, out)\n");
	walk_live_fr_rules(0, F_OUT, 1, NULL, ipf_walker);

	printf("Accounting rules configured (set 0, in)\n");
	walk_live_fr_rules(0, F_ACIN, 0, NULL, ipf_walker);
	printf("Accounting rules configured (set 0, out)\n");
	walk_live_fr_rules(0, F_ACOUT, 0, NULL, ipf_walker);
	printf("Accounting rules configured (set 1, in)\n");
	walk_live_fr_rules(0, F_ACIN, 1, NULL, ipf_walker);
	printf("Accounting rules configured (set 1, out)\n");
	walk_live_fr_rules(0, F_ACOUT, 1, NULL, ipf_walker);
}


void
ipnat_walker(ipn)
	ipnat_t *ipn;
{
	printnat(ipn, opts & (OPT_DEBUG|OPT_VERBOSE));
}


void
nat_walker(ticks, filter, nat)
	u_long ticks;
	int *filter;
	nat_t *nat;
{

	printactivenat(nat, opts, ticks);
	if (nat->nat_aps)
		printf("\tproxy active\n");
}


void
hostmap_walker(hm)
	hostmap_t *hm;
{
	hm->hm_ref--;
	if (hm->hm_ref > 0)
		printhostmap(hm, hm->hm_hv);
}


void
dumpnat_live()
{
	printf("List of active MAP/Redirect filters:\n");
	walk_live_ipnat(ipnat_walker);
	printf("\n");
	printf("List of active sessions:\n");
	walk_live_nat(0, NULL, nat_walker);
	printf("\n");
	printf("Hostmap table:\n");
	walk_live_hostmap(hostmap_walker);
}


void
state_walker(ticks, filter, is)
	u_long ticks;
	int *filter;
	ipstate_t *is;
{
	printstate(is, opts, ticks);
}


void
dumpstate_live()
{
	printf("List of active state sessions:\n");
	walk_live_states(0, NULL, state_walker);
}


void
dumplookup_live()
{
	printf("List of configured pools\n");
	printf("List of configured hash tables\n");
}

/*
 * Display the built up state table rules and mapping entries.
 */
void
dumpstate(softc, arg)
	ipf_main_softc_t *softc;
	void *arg;
{
	ipf_state_softc_t *softs = arg;
	ipstate_t *ips;

	printf("List of active state sessions:\n");
	for (ips = softs->ipf_state_list; ips != NULL; )
		ips = printstate(ips,
				 opts & (OPT_DEBUG|OPT_VERBOSE|OPT_NORESOLVE),
				 softc->ipf_ticks);
}
