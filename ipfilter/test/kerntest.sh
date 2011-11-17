#!/bin/sh
#
# The order in which the interfaces are used is not as important as
# their existance.
#

if [ ! -f .nicstate ] ; then
	NICS=`ifconfig -a | egrep '^[a-z][^ ]*:' | grep -v LOOPBACK | sed -e 's/^\([a-z][^:]*\):.*/\1/'`
	num=0
	for i in $NICS; do
		eval `echo NIC${num}=$i`
		num=`expr $num + 1`
	done
	if [ -z "${NIC0}" ] ; then
		echo "Could not find NIC0"
		exit 1
	fi
	if [ -z "${NIC1}" ] ; then
		echo "Could not find NIC1"
		exit 1
	fi
	if [ -z "${NIC2}" ] ; then
		echo "Could not find NIC2"
		exit 1
	fi
	if [ -z "${NIC3}" ] ; then
		echo "Could not find NIC3"
		exit 1
	fi
	NIC0ADDR=`netstat -nr | egrep "\.[0-9]+ *U .*${NIC0}" | head -1 | awk ' { printf "%-15s", $2; } ' -`
	NIC0ADDR6=`netstat -nr | egrep " [:0-9a-f]+ *U .*${NIC0}" | head -1 | awk ' { print $2; } ' -`
	NIC1ADDR=`netstat -nr | egrep "\.[0-9]+ *U .*${NIC1}" | head -1 | awk ' { printf "%-15s", $2; } ' -`
	NIC1ADDR6=`netstat -nr | egrep " [:0-9a-f]+ *U .*${NIC1}" | head -1 | awk ' { print $2; } ' -`
	NIC0HEXADDR=`echo ${NIC0ADDR} | awk -F. '{ printf "%02x%02x %02x%02x", $1, $2, $3, $4; } ' -`
	NIC0HEXADDR6=`echo "${NIC0ADDR6}" | perl -e '$F=<>; @A=split(/:/,$F); for ($i = 0; $i <= $#A; $i++) { if (!length($A[$i])) { for ($j = 0; $j < 8 - $#A; $j++) { $addr = $addr." 0000"; } } else { $hex = "0000$A[$i]"; $hex =~ s/.*(....)$/$1/; $addr = $addr." $hex"; } } $addr =~ s/^ //; print "$addr\n";'`
	NIC1HEXADDR=`echo ${NIC1ADDR} | awk -F. '{ printf "%02x%02x %02x%02x", $1, $2, $3, $4; } ' -`
	NIC1HEXADDR6=`echo "${NIC1ADDR6}" | perl -e '$F=<>; @A=split(/:/,$F); for ($i = 0; $i <= $#A; $i++) { if (!length($A[$i])) { for ($j = 0; $j < 8 - $#A; $j++) { $addr = $addr." 0000"; } } else { $hex = "0000$A[$i]"; $hex =~ s/.*(....)$/$1/; $addr = $addr." $hex"; } } $addr =~ s/^ //; print "$addr\n";'`
	cat > .nicstate << __EOF__
NIC0=${NIC0}
NIC1=${NIC1}
NIC2=${NIC2}
NIC3=${NIC3}
NIC0ADDR="${NIC0ADDR}"
NIC0ADDR6="${NIC0ADDR6}"
NIC1ADDR="${NIC1ADDR}"
NIC1ADDR6="${NIC1ADDR6}"
NIC0HEXADDR="${NIC0HEXADDR}"
NIC0HEXADDR6="${NIC0HEXADDR6}"
NIC1HEXADDR="${NIC1HEXADDR}"
NIC1HEXADDR6="${NIC1HEXADDR6}"
__EOF__
else
	. ./.nicstate
fi
export NIC0
export NIC1
export NIC2
export NIC3
export NIC0ADDR
export NIC0ADDR6
export NIC1ADDR
export NIC1ADDR6
export NIC0HEXADDR
export NIC0HEXADDR6
export NIC1HEXADDR
export NIC1HEXADDR6
RESDIR=kern
export RESDIR
#
mkdir -p ${RESDIR}
#
# These tests cannot be run meaningfully through the kernel from ipftest
# and tested for proper function as they use policy routing.
#
touch ${RESDIR}/ni21 ${RESDIR}/ni23 ${RESDIR}/ni6 ${RESDIR}/n18 ${RESDIR}/ni18
#
ipf -T update_ipid=0
make -k kerntests
#make RESDIR=kern TESTMODE=kern kern/n6
