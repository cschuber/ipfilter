#!/bin/ksh
dir=${0%/*}
. ${dir}/../config.sh
kill -INT $(cat ${IPF_TMP_DIR}/tcpserver.pid.${1}) || print "| tcpserver kill failed"
sleep 1
exit 0
