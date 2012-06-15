#!/bin/ksh
#
# 1 = source address
# 2 = target address
#
PATH=/bin:/usr/bin:/sbin:/usr/sbin

src=$1
target=$2
tmpfile=$3
pass=$4

traceroute -s ${src} -m 5 -w 2 -n ${target} > ${4} 2>&1 &
job=$!
(sleep 4 && kill $job)
wait $job
ret=$?

if [ $pass = pass ] ; then
	expected=0
else
	expected=1
fi

echo "traceroute returned $ret expected $expected";
if [ $ret != $expected ] ; then
	echo "FAIL traceroute result does not match expected"
else
	echo "PASS traceroute result matches expected"
fi
exit $ret
