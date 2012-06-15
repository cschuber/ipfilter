#!/bin/sh

if [ -f /usr/sbin/ndd ] ; then
	ndd -set /dev/ip ip_forwarding 1
fi
if [ -f /sbin/sysctl ] ; then
	sysctl -w net.inet.ip.forwarding=1
fi
