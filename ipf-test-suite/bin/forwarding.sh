#!/bin/ksh

if [[ -f /usr/sbin/ndd ]] ; then
	/usr/sbin/ndd -set /dev/ip ip_forwarding 1 2>&1
	/usr/sbin/ndd -set /dev/ip ip6_forwarding 1 2>&1
fi
if [[ -f /sbin/sysctl ]] ; then
	/sbin/sysctl -w net.inet.ip.forwarding=1 2>&1
	/sbin/sysctl -w net.inet6.ip6.forwarding=1 2>&1
fi
