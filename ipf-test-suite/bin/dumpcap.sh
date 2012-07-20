#!/bin/ksh

for i in /sbin /usr/sbin /bin /usr/bin /opt/sfw/sbin; do
	if [[ -f $i/tcpdump ]] ; then
		case $2 in
		frag)
			greparg="frag |offset "
			;;
		*)
			greparg="$2"
			;;
		esac
		exec $i/tcpdump -nr "${1}" -nvvv not arp 2>&1 | \
		    egrep -iv 'advert|solicit|unreach' | egrep " > |$greparg"
	fi
done
if [[ -f /usr/sbin/snoop ]] ; then
	exec /usr/sbin/snoop -i ${1} -r not arp | 2>&1 \
	    egrep -v 'solicitation|advertisement|unreach' | grep "${2}"
fi
exit 1
