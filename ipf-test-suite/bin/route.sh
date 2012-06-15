#!/bin/ksh

PATH=/sbin:/usr/sbin:${PATH}

case `uname -s` in
SunOS)
	exec route $@
	;;
*BSD)
	if [[ "$1" = "-f" ]] ; then
		exec route flush
	else
		exec route $@
	fi
esac
exit 1
