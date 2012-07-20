#!/bin/ksh
PATH=/bin:/usr/bin:/sbin:/usr/sbin
dest=$1
size=$2
result=$3
localaddr=$4

if [[ $size = big ]] ; then
	size=2000
else
	size=56
fi

if [[ $result = pass ]] ; then
	expected=0
else
	expected=1
fi

case `uname -s` in
SunOS)
	print "| ping -s ${dest} ${size} 3"
	ping -s ${dest} ${size} 3 2>&1 &
	job=$!
	(sleep 6 && kill -INT $job 2>/dev/null || print "| ping kill failed") &
	wait $job
	ret=$?
	;;
*)
	case $dest in
	*:*)
		pingprog="ping6 -n"
		;;
	*)
		pingprog="ping -n"
		;;
	esac
	print "| ${pingprog} -c 3 -s ${size} ${dest}"
	${pingprog} -c 3 -s ${size} ${dest} 2>&1 &
	job=$!
	(sleep 6 && kill -INT $job 2>/dev/null || print "| ping kill failed") &
	wait $job
	ret=$?
	;;
esac
print "| ping returned $ret expected $expected";
if [[ $ret != 0 ]] ; then
	ret=1
fi
if [[ $ret = $expected ]] ; then
	print "PASS ping result matches expected"
else
	print "FAIL ping result does not match expected"
fi
exit $ret
