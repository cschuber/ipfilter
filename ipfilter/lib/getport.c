#include "ipf.h"

int getport(name)
char *name;
{
	struct servent *s;

	s = getservbyname(name, NULL);
	if (s != NULL)
		return s->s_port;
	return 0;
}
