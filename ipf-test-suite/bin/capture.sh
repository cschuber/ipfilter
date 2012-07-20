#!/bin/ksh

for i in /sbin /usr/sbin /bin /usr/bin /opt/sfw/sbin; do
	if [ -f $i/tcpdump ] ; then
		$i/tcpdump -s 1536 -w ${2} -i ${1} >/dev/null 2>&1 &
		job=$!
		print ${job} > ${3}
		wait ${job}
		exit $?
	fi
done
if [[ -f /usr/sbin/snoop ]] ; then
	/usr/sbin/snoop -s 1536 -o ${2} -d ${1} >/dev/null 2>&1 &
	job=$!
	print ${job} > ${3}
	wait ${job}
	exit $?
fi
exit 1
