#!/bin/ksh
. $(dirname $0)/../vars.sh
kill -INT $(cat ${IPF_TMP_DIR}/tcpserver.pid.${1}) || echo "tcpserver kill failed"
sleep 1
exit 0
