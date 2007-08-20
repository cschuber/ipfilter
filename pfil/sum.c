/*
 * Copyright (C) 2000 by Darren Reed.
 */
#ifdef __hpux
#define	ip_cksum	ip_csuma
struct uio;
#endif
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/stream.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/cmn_err.h>
#include <sys/dlpi.h>
#ifdef __hpux
# include <sys/io.h>
# include <sys/moddefs.h>
#endif
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "compat.h"
#include "qif.h"

#define   IP_SIMPLE_HDR_LENGTH_IN_WORDS   5


u_short
pfil_tcpsum(m, ip, tcp)
	mblk_t *m;
	struct ip *ip;
	struct tcphdr *tcp;
{
	u_short *sp, slen;
	u_int sum, sum2;
	int hlen;

	/*
	 * Add up IP Header portion
	 */
	hlen = ip->ip_hl << 2;
	slen = ip->ip_len - hlen;
	sum = htons(IPPROTO_TCP);
	sum += htons(slen);
	sp = (u_short *)&ip->ip_src;
	sum += *sp++;	/* ip_src */
	sum += *sp++;
	sum += *sp++;	/* ip_dst */
	sum += *sp++;
	tcp->th_sum = 0;
	sum2 = ip_cksum(m, hlen, sum);
	sum2 = (sum2 & 0xffff) + (sum2 >> 16);
	sum2 = ~sum2 & 0xffff;
	return sum2;
}


/* Return the IP checksum for the IP header at "iph". */
unsigned int
pfil_ip_csum_hdr(iph)
	u_char *iph;
{
	u_short *uph;
	u_int sum;
	u_int u1;

	u1 = (*iph & 0xf) - IP_SIMPLE_HDR_LENGTH_IN_WORDS;

	uph = (unsigned short *)iph;
	sum = uph[0] + uph[1] + uph[2] + uph[3] + uph[4] +
	      uph[5] + uph[6] + uph[7] + uph[8] + uph[9];

	if (u1) {
		do {
			sum += uph[10];
			sum += uph[11];
			uph += 2;
		} while (--u1);
	}
	sum = (sum & 0xffff) + (sum >> 16);
	sum = ~(sum + (sum >> 16)) & 0xffff;
	if (sum == 0xffff)
		sum = 0;
	return sum;
}
