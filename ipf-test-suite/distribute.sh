#!/bin/ksh

. ./config.sh

if [[ $# -gt 0 ]] ; then
	list=$@
else
	list="SUT SENDER RECEIVER"
fi

#
for h in $list; do
	host=$(eval "echo \${${h}_CTL_HOSTNAME}")
	echo "Copying to $h:$host"
	if [[ ${host} != DONOTUSE ]] ; then
		tar cf - . | ${RRSH} ${host} "mkdir -p ${IPF_VAR_DIR}; cd ${IPF_VAR_DIR}; tar xpf -"
	fi
done
#
exit 0
