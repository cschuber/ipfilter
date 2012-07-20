#!/bin/ksh
dir=${0%/*}
. ${dir}/../config.sh
kill -INT $(cat ${IPF_TMP_DIR}/udpserver.pid.${1}) || print "| udpserver kill failed"
sleep 1
exit 0
