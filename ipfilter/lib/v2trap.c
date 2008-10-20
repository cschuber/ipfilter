#include "ipf.h"
#include "ipl.h"

static u_char sysuptime[] = { 6, 8, 0x2b, 6, 1, 2, 1, 1, 3, 0 };
/*
 * Enterprise number OID:
 * 1.3.6.1.4.1.9932
 */
static u_char ipf_trap0_1[] = { 6, 10, 0x2b, 6, 1, 4, 1, 0xcd, 0x4c, 1, 1, 1 };
static u_char ipf_trap0_2[] = { 6, 10, 0x2b, 6, 1, 4, 1, 0xcd, 0x4c, 1, 1, 2 };

static int writeint __P((u_char *, int));
static int writelength __P((u_char *, u_int));
static int maketrap_v2 __P((char *, u_char *, int, u_char *, int, u_32_t,
			    u_int, time_t));

int sendtrap_v2_0 __P((int, char *, char *, int, time_t));

static char def_community[] = "public";	/* ublic */

static int
writelength(buffer, value)
	u_char *buffer;
	u_int value;
{
	u_int n = htonl(value);
	int len;

	if (value < 128) {
		*buffer = value;
		return 1;
	}
	if (value > 0xffffff)
		len = 4;
	else if (value > 0xffff)
		len = 3;
	else if (value > 0xff)
		len = 2;
	else
		len = 1;

	*buffer = 0x80 | len;

	bcopy((u_char *)&n + 4 - len, buffer + 1, len);

	return len + 1;
}


static int
writeint(buffer, value)
	u_char *buffer;
	int value;
{
	u_char *s = buffer;
	u_int n = value;

	if (value == 0) {
		*buffer = 0;
		return 1;
	}

	if (n >  4194304) {
		*s++ = 0x80 | (n / 4194304);
		n -= 4194304 * (n / 4194304);
	}
	if (n >  32768) {
		*s++ = 0x80 | (n / 32768);
		n -= 32768 * (n / 327678);
	}
	if (n > 128) {
		*s++ = 0x80 | (n / 128);
		n -= (n / 128) * 128;
	}
	*s++ = (u_char)n;

	return s - buffer;
}



/*
 * First style of traps is:
 * 1.3.6.1.4.1.9932.1.1
 */
static int
maketrap_v2(community, buffer, bufsize, msg, msglen, ipaddr, code, when)
	char *community;
	u_char *buffer;
	int bufsize;
	u_char *msg;
	int msglen;
	u_32_t ipaddr;
	u_int code;
	time_t when;
{
	u_char *s = buffer, *t, *pdulen;
	u_char *varlen;
	int basesize = 77;
	u_short len;
	int trapmsglen;;
	int pdulensz;
	int varlensz;
	int baselensz;
	int n;

	if (community == NULL || *community == '\0')
		community = def_community;
	basesize += strlen(community) + msglen;

	if (basesize + 8 > bufsize)
		return 0;

	memset(buffer, 0xff, bufsize);
	*s++ = 0x30;		/* Sequence */

	if (basesize - 1 >= 128) {
		baselensz = 2;
		basesize++;
	} else {
		baselensz = 1;
	}
	s += baselensz;
	*s++ = 0x02;		/* Integer32 */
	*s++ = 0x01;		/* length 1 */
	*s++ = 0x01;		/* version 2 */
	*s++ = 0x04;		/* octet string */
	*s++ = strlen(community);		/* length of "public" */
	bcopy(community, s, s[-1]);
	s += s[-1];
	*s++ = 0xA7;		/* PDU(7) */
	pdulen = s++;
	if (basesize - (s - buffer) >= 128) {
		pdulensz = 2;
		basesize++;
		s++;
	} else {
		pdulensz = 1;
	}
	/* request id */
	*s++ = 0x2;	/* integer */
	*s++ = 0x4;	/* len 4 */
	*s++ = 0x0;	/* noError */
	*s++ = 0x0;	/* noError */
	*s++ = 0x0;	/* noError */
	*s++ = 0x0;	/* noError */

	/* error status */
	*s++ = 0x2;	/* integer */
	*s++ = 0x1;	/* len 1 */
	*s++ = 0x0;	/* noError */

	/* error-index */
	*s++ = 0x2;	/* integer */
	*s++ = 0x1;	/* len 1 */
	*s++ = 0x0;	/* noError */

	*s++ = 0x30;	/* sequence */
	varlen = s++;
	if (basesize - (s - buffer) >= 128) {
		varlensz = 2;
		basesize++;
		s++;
	} else {
		varlensz = 1;
	}

	*s++ = 0x30;	/* sequence */
	*s++ = sizeof(sysuptime) + 6;

	bcopy(sysuptime, s, sizeof(sysuptime));
	s += sizeof(sysuptime);

	*s++ = 0x43;	/* Timestamp */
	*s++ = 0x04;	/* TimeTicks */
	*s++ = 0x0;
	*s++ = 0x0;
	*s++ = 0x0;
	*s++ = 0x0;

	*s++ = 0x30;
	t = s + 1;
	bcopy(ipf_trap0_1, t, sizeof(ipf_trap0_1));
	t += sizeof(ipf_trap0_1);

	*t++ = 0x2;		/* Integer */
	n = writeint(t + 1, IPFILTER_VERSION);
	*t = n;
	t += n + 1;

	len = t - s - 1;
	writelength(s, len);

	s = t;
	*s++ = 0x30;
	if (msglen < 128) {
		if (msglen + 1 + 1 + sizeof(ipf_trap0_2) >= 128)
			trapmsglen = 2;
		else
			trapmsglen = 1;
	} else {
		if (msglen + 2 + 1 + sizeof(ipf_trap0_2) >= 128)
			trapmsglen = 2;
		else
			trapmsglen = 1;
	}
	t = s + trapmsglen;
	bcopy(ipf_trap0_2, t, sizeof(ipf_trap0_2));
	t += sizeof(ipf_trap0_2);

	*t++ = 0x4;		/* Octet string */
	n = writelength(t, msglen);
	t += n;
	bcopy(msg, t, msglen);
	t += msglen;

	len = t - s - trapmsglen;
	writelength(s, len);

	len = t - varlen - varlensz;
	writelength(varlen, len);		/* pdu length */

	len = t - pdulen - pdulensz;
	writelength(pdulen, len);		/* pdu length */

	len = t - buffer - baselensz - 1;
	writelength(buffer + 1, len);	/* length of trap */

	return t - buffer;
}


int
sendtrap_v2_0(fd, community, msg, msglen, when)
	int fd;
	char *community, *msg;
	int msglen;
	time_t when;
{

	u_char buffer[1500];
	int n;

	n = maketrap_v2(community, buffer, sizeof(buffer),
			(u_char *)msg, msglen, 0, 0, when);
	if (n > 0) {
		return send(fd, buffer, n, 0);
	}

	return 0;
}
