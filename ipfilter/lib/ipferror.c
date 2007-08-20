#include "ipf.h"

#include <sys/ioctl.h>

void ipferror(fd, msg)
int fd;
char *msg;
{
	int err, save;

	save = errno;

	err = 0;

	if (fd >= 0)
		(void) ioctl(fd, SIOCIPFINTERROR, &err);

	fprintf(stderr, "%d:", err);
	perror(msg);
}
