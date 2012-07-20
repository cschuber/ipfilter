#!/bin/ksh
addr=$1
path=$2
TFTP_OUTPUT=${3}/tftp-job.out

print "| echo 'get ${2} /dev/null; quit' | tftp ${addr} > ${TFTP_OUTPUT} 2>&1 &"
print "get ${2} /dev/null; quit" | tftp ${addr} > ${TFTP_OUTPUT} 2>&1 &
job=$!
(sleep 3 && kill -INT ${job} 2>/dev/null || print "| tftp kill failed") &
wait $job
ret=$?
print "| tftp job returned ${ret}"
print "| tftp job output start"
cat ${TFTP_OUTPUT}
print "| tftp job output end"
bytes=$(sed -n -e 's/.*Received \([0-9][0-9]*\) .*/\1/p' ${TFTP_OUTPUT})
if [[ -z $bytes ]] ; then
	bytes="0"
fi
print "BYTES $bytes"
exit ${ret}
