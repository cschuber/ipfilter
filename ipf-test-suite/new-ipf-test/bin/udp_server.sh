#!/bin/ksh
#
# A version of perl with IO::Socket::IP that works with IPv6 is required.
# Thus put system directories at the end in case of the newer perl being
# at a new home.
#
PATH=/usr/local/bin:/opt/sfw/bin:/usr/sfw/bin:/usr/pkg/bin:/usr/bin:/bin
#
. $(dirname $0)/../vars.sh
exec perl ${IPF_BIN_DIR}/udp_server.pl $* 2>&1
