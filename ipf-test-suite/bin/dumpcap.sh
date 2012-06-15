#!/bin/sh

for i in /sbin /usr/sbin /bin /usr/bin /opt/sfw/sbin; do
	if [ -f $i/tcpdump ] ; then
		exec $i/tcpdump -r ${1} -nvvv
	fi
done
if [ -f /usr/sbin/snoop ] ; then
	exec /usr/sbin/snoop -i ${1} -Vr
fi
exit 1
