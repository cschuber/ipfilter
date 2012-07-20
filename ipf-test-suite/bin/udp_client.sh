#!/bin/ksh
#
# A version of perl with IO::Socket::IP that works with IPv6 is required.
# Thus put system directories at the end in case of the newer perl being
# at a new home.
#
PATH=/usr/local/bin:/opt/sfw/bin:/usr/sfw/bin:/usr/pkg/bin:/usr/bin:/bin
#
dir=${0%/*}
. ${dir}/../config.sh
exec perl ${IPF_BIN_DIR}/udp_client.pl $1 $2 2>&1
