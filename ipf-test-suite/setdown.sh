#!/bin/ksh

. ./vars.sh

#
for h in sut sender receiver; do
	H=$(echo $h | tr '[a-z]' '[A-Z]')
	dest=$(eval echo \$${H}_CTL_HOSTNAME)
	if [[ ${dest} != DONOTUSE ]] ; then
		#
		# Unconfigure networking...
		#
		${RRSH} -n -l root ${dest} sh ${IPF_VAR_DIR}/config_net_down.sh
		${RRSH} -n -l root ${dest} "${IPF_BIN_DIR}/route.sh -f;"
	fi
done
#
#
if [[ ${SENDER_CTL_HOSTNAME} != DONOTUSE ]]; then
	${RRSH} ${SENDER_CTL_HOSTNAME} ${IPF_BIN_DIR}/tunnel.sh destroy
fi
if [[ ${RECEIVER_CTL_HOSTNAME} != DONOTUSE ]]; then
	${RRSH} ${RECEIVER_CTL_HOSTNAME} ${IPF_BIN_DIR}/tunnel.sh destroy
fi
#
exit 0
