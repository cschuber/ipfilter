#!/bin/ksh
. $(dirname $0)/../vars.sh
kill -INT $(cat ${IPF_TMP_DIR}/udpserver.pid.${1}) || echo "udpserver kill failed"
sleep 1
exit 0
