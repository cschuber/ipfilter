#!/bin/ksh

if [ $# -lt 2 ] ; then
	exit 1
fi
PATH=/sbin:/usr/sbin:${PATH}
if [[ $2 = SETME ]] ; then
	exit 0
fi
if [[ $# -gt 2 && $3 = SETME ]] ; then
	exit 0
fi
os=`uname -s`
rel=`uname -r`

try() {
	if ! $@ 2>&1; then
		echo "FAILED: $*"
	fi
}

case $os$rel in
SunOS5.*)
	if ! ifconfig $2 $1 >/dev/null 2>&1; then
		try ifconfig $2 $1 plumb
	fi
	case $3 in
	*:*)
		try ifconfig $2 $1 addif $3/$4 up
		;;
	*)
		try ifconfig $2 $1 addif $3 netmask $4 up
		;;
	esac
	;;
*)
	case $3 in
	*:*)
		try ifconfig $2 $1 alias $3/$4 up
		;;
	*)
		try ifconfig $2 $1 alias $3 netmask $4 up
		;;
	esac
	;;
esac

exit 0
