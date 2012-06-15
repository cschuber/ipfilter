#!/bin/ksh
n=$(uname -n)
echo "- Kill ${n}:${1}"
SIG=INT

pid=$(cat ${1})
echo "- Kill ${n}:${1} PID ${pid}"
while kill -0 ${pid} >/dev/null 2>&1; do
	kill -${SIG} ${pid} 2>&1
	sleep 1
	SIG=TERM
done
exit 0
