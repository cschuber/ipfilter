#!/bin/ksh
addr=$1
destdir=$2

echo 'get /test_data.txt /dev/null' | tftp ${addr} > ${destdir}/tftp.out 2>&1 &
job=$!
(sleep 3 && kill -INT ${job} 2>/dev/null || echo "tftp kill failed") &
wait $job
ret=$?
echo "-- tftp job returned ${ret}"
echo "-- tftp job output"
cat ${destdir}/tftp.out
exit ${ret}
