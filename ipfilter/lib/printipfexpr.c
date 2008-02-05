#include "ipf.h"

static void printport __P((int *));
static void printhosts __P((int *));
static void printsingle __P((int *));


void printipfexpr(array)
	int *array;
{
	int i, nelems, j, not;
	ipfexp_t *ipfe;

	nelems = array[0];

	for (i = 1; i < nelems; ) {
		ipfe = (ipfexp_t *)(array + i);
		if (ipfe->ipfe_cmd == IPF_EXP_END)
			break;

		not = ipfe->ipfe_not;

		switch (ipfe->ipfe_cmd)
		{
		case IPF_EXP_IP_ADDR :
			printf("ip.addr %s= ", not ? "!" : "");
			printhosts(array + i);
			break;

		case IPF_EXP_IP_PR :
			printf("ip.p %s= ", not ? "!" : "");
			printsingle(array + i);
			break;

		case IPF_EXP_IP_SRCADDR :
			printf("ip.src %s= ", not ? "!" : "");
			printhosts(array + i);
			break;

		case IPF_EXP_IP_DSTADDR :
			printf("ip.dst %s= ", not ? "!" : "");
			printhosts(array + i);
			break;

		case IPF_EXP_TCP_PORT :
			printf("tcp.port %s= ", not ? "!" : "");
			printport(array + i);
			break;

		case IPF_EXP_TCP_DPORT :
			printf("tcp.dport %s= ", not ? "!" : "");
			printport(array + i);
			break;

		case IPF_EXP_TCP_SPORT :
			printf("tcp.sport %s= ", not ? "!" : "");
			printport(array + i);
			break;

		case IPF_EXP_TCP_FLAGS :
			printf("tcp.flags %s= ", not ? "!" : "");

			for (j = 0; j < ipfe->ipfe_narg; ) {
				printtcpflags(array[i + 3], array[i + 4]);
				j += 2;
				if (j < array[3])
					putchar(',');
			}
			break;

		case IPF_EXP_UDP_PORT :
			printf("udp.port %s= ", not ? "!" : "");
			printport(array + i);
			break;

		case IPF_EXP_UDP_DPORT :
			printf("udp.dport %s= ", not ? "!" : "");
			printport(array + i);
			break;

		case IPF_EXP_UDP_SPORT :
			printf("udp.sport %s= ", not ? "!" : "");
			printport(array + i);
			break;

		case IPF_EXP_IDLE_GT :
			printf("idle-gt %s= ", not ? "!" : "");
			printsingle(array + i);
			break;

		case IPF_EXP_TCP_STATE :
			printf("tcp-state %s= ", not ? "!" : "");
			printsingle(array + i);
			break;

		case IPF_EXP_END :
			break;

		default :
			printf("#%#x,len=%d;",
			       ipfe->ipfe_cmd, ipfe->ipfe_narg);
		}

		if (array[i] != IPF_EXP_END)
			putchar(';');

		i += ipfe->ipfe_narg + 3;
		if (array[i] != IPF_EXP_END)
			putchar(' ');
	}
}


static void printsingle(array)
	int *array;
{
	ipfexp_t *ipfe = (ipfexp_t *)array;
	int i;

	for (i = 0; i < ipfe->ipfe_narg; ) {
		printf("%d", array[i + 3]);
		i++;
		if (i < ipfe->ipfe_narg)
			putchar(',');
	}
}


static void printport(array)
	int *array;
{
	ipfexp_t *ipfe = (ipfexp_t *)array;
	int i;

	for (i = 0; i < ipfe->ipfe_narg; ) {
		printf("%d", ntohs(array[i + 3]));
		i++;
		if (i < ipfe->ipfe_narg)
			putchar(',');
	}
}


static void printhosts(array)
	int *array;
{
	ipfexp_t *ipfe = (ipfexp_t *)array;
	int i;

	for (i = 0; i < ipfe->ipfe_narg; ) {
		printhostmask(AF_INET, (u_32_t *)(array + i + 3),
			      (u_32_t *)(array + i + 4));
		i += 2;
		if (i < ipfe->ipfe_narg)
			putchar(',');
	}
}