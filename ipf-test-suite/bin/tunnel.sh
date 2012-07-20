#!/bin/ksh
PATH=/sbin:/usr/sbin:/bin:/usr/bin

try() {
	$@
	if [ $? -ne 0 ] ; then
		print "FAILED: $*"
	fi
}

tun_set_local() {
	if [[ $1 = local ]] ; then
		localv4addr=${SENDER_TUNNEL_ADDR_V4}
		remotev4addr=${RECEIVER_TUNNEL_ADDR_V4}
		localv6addr=${SENDER_TUNNEL_ADDR_V6}
		remotev6addr=${RECEIVER_TUNNEL_ADDR_V6}
	else
		localv4addr=${RECEIVER_TUNNEL_ADDR_V4}
		remotv4eaddr=${SENDER_TUNNEL_ADDR_V4}
		localv6addr=${RECEIVER_TUNNEL_ADDR_V6}
		remotev6addr=${SENDER_TUNNEL_ADDR_V6}
	fi
}

tun_create() {
	case `uname -s` in
	SunOS)
		if ifconfig ip.tun900 >/dev/null 2>&1; then
			try ifconfig ip.tun900 inet unplumb
			try ifconfig ip.tun900 inet6 unplumb
			try dladm delete-iptun ip.tun900
		fi
		try dladm create-iptun -t -T ipv4 -a local=$1 -a remote=$2 ip.tun900
		try ifconfig ip.tun900 inet plumb
		try ifconfig ip.tun900 inet ${localv4addr} ${remotev4addr} up
		try ifconfig ip.tun900 netmask 255.255.255.255
		try ifconfig ip.tun900 inet6 plumb
		try ifconfig ip.tun900 inet6 ${localv6addr}/128 ${remotev6addr} up
		;;
	*BSD)
		if ifconfig gif900 >/dev/null 2>&1; then
			try ifconfig gif900 destroy
		fi
		try ifconfig gif900 create
		try ifconfig gif900 tunnel $1 $2
		try ifconfig gif900 ${localav4ddr} ${remotev4addr} up
		try ifconfig gif900 inet6 ${localv6addr} ${remotev6addr} prefixlen 128 up
		;;
	esac
}

tun_destroy() {
	case `uname -s` in
	SunOS)
		try ifconfig ip.tun900 inet6 unplumb
		try ifconfig ip.tun900 inet unplumb
		try dladm delete-iptun ip.tun900
		;;
	*BSD)
		try ifconfig gif900 destroy
		;;
	esac
}

case $1 in
create)
	tun_set_local $2
	tun_create $3 $4
	;;
destroy)
	tun_destroy
	;;
esac
exit 0
