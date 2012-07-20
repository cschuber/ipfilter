#!/bin/ksh
#
# 1 = source address
# 2 = target address
#
PATH=/bin:/usr/bin:/sbin:/usr/sbin

interface=$1
src=$2
target=$3
pass=$4

traceroute -i ${interface} -s ${src} -m 5 -w 2 -n ${target} &
job=$!
(sleep 4 && kill $job)
wait $job
ret=$?

if [[ $pass = pass ]] ; then
	expected=0
else
	expected=1
fi
if [[ $ret = 0 ]] ; then
	:
else
	ret=1
fi

print "| traceroute returned $ret expected $expected";
if [[ $expected = $ret ]] ; then
	print "PASS traceroute result matches expected"
else
	print "FAIL traceroute result does not match expected"
fi
exit $ret
