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
	echo "ping -s ${dest} ${size} 3"
	ping -s ${dest} ${size} 3 &
	job=$!
	(sleep 6 && kill -INT $job 2>/dev/null || echo "ping kill failed") &
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
	echo "${pingprog} -c 3 -s ${size} ${dest}"
	${pingprog} -c 3 -s ${size} ${dest} &
	job=$!
	(sleep 6 && kill -INT $job 2>/dev/null || echo "ping kill failed") &
	wait $job
	ret=$?
	;;
esac
echo "ping returned $ret expected $expected";
if [[ $ret == 0 && $expected == 0 ]] ; then
	echo "PASS ping result matches expected"
else
	if [[ $ret != 0 && $expected != 0 ]] ; then
		echo "PASS ping result matches expected"
		ret=0
	else
		echo "FAIL ping result does not match expected"
	fi
fi
exit $ret
