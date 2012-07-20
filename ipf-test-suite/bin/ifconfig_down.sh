#!/bin/ksh

if [ $# -lt 2 ] ; then
	exit 1
fi
if [ $2 = SETME ] ; then
	exit 0
fi
PATH=/sbin:/usr/sbin:${PATH}
os=`uname -s`
rel=`uname -r`

try() {
	$@ 2>&1
	if [ $? -ne 0 ] ; then
		print "FAILED: $*"
	fi
}

unplumb() {
	ifconfig $2 $1 > /dev/null 2>&1
	ret=$?
	if [[ $ret -ne 0 ]]; then
		print "FAILED: ifconfig $2"
		return $ret
	fi
	ifconfig $2 $1 | egrep "	$1 " | egrep -v ' fe80:' | \
	while read family addr a b c d; do
		if [[ $addr = alias ]] ; then
			addr=$a
		fi
		try ifconfig $2 $1 $addr delete
	done
	return 0
}

case $os$rel in
SunOS5.*)
	if ifconfig $2 $1 >/dev/null 2>&1; then
		try ifconfig $2 $1 unplumb
	fi
	;;
*)
	unplumb $1 $2
	;;
esac
exit 0
