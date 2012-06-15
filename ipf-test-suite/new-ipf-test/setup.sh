#!/bin/ksh

. ./vars.sh

(cd tests/1h/v4; ./gen_XXX_test_sh)

#
# Test remote access
#
for h in SUT SENDER RECEIVER; do
	host=$(eval "echo \${${h}_CTL_HOSTNAME}")
	if [[ ${host} != DONOTUSE ]] ; then
		x=$(${RRSH} -n -l root ${host} echo hello_world)
		if [[ $x != hello_world ]] ; then
			echo "Remote access to ${host} not operational"
			exit 1
		fi
	fi
done

for h in SUT SENDER RECEIVER; do
	host=$(eval "echo \${${h}_CTL_HOSTNAME}")
	echo "Copying to $h:$host"
	if [[ ${host} != DONOTUSE ]] ; then
		tar cf - . | ${RRSH} ${host} "mkdir -p ${IPF_VAR_DIR}; cd ${IPF_VAR_DIR}; tar xpf -"
	fi
done
#
for h in sut sender receiver; do
	echo "Configuring $h"
	H=$(echo $h | tr '[a-z]' '[A-Z]')
	n0=$(eval echo \$${H}_NET0_IFP_NAME)
	n0v4=$(eval echo \$${H}_NET0_ADDR_V4)
	n0v4m=$(eval echo \$NET0_NETMASK_V4)
	n1=$(eval echo \$${H}_NET1_IFP_NAME)
	n1v4=$(eval echo \$${H}_NET1_ADDR_V4)
	n1v4m=$(eval echo \$NET1_NETMASK_V4)
	n0v6=$(eval echo \$${H}_NET0_ADDR_V6)
	n0v6m=$(eval echo \$NET0_NETMASK_V6)
	n1v6=$(eval echo \$${H}_NET1_ADDR_V6)
	n1v6m=$(eval echo \$NET1_NETMASK_V6)
	cat > ${IPF_TMP_DIR}/${h}_config_net_up.sh <<__EOF__
${IPF_VAR_DIR}/bin/ifconfig_up.sh inet ${n0} ${n0v4} ${n0v4m}
${IPF_VAR_DIR}/bin/ifconfig_up.sh inet ${n1} ${n1v4} ${n1v4m}
${IPF_VAR_DIR}/bin/ifconfig_up.sh inet6 ${n0} ${n0v6} ${n0v6m}
${IPF_VAR_DIR}/bin/ifconfig_up.sh inet6 ${n1} ${n1v6} ${n1v6m}
__EOF__
	a=1
	while [[ $a -gt 0 ]] ; do
		name=${H}_NET0_ADDR_V4_A${a}
		val=$(eval echo \$$name)
		if [[ -n ${val} ]] ; then
			cat >> ${IPF_TMP_DIR}/${h}_config_net_up.sh <<__EOF__
${IPF_VAR_DIR}/bin/ifconfig_up.sh inet ${n0} ${val} ${n0v4m}
__EOF__
		else
			a=0
		fi
		name=${H}_NET0_ADDR_V6_A${a}
		val=$(eval echo \$$name)
		if [[ -n ${val} ]] ; then
			cat >> ${IPF_TMP_DIR}/${h}_config_net_up.sh <<__EOF__
${IPF_VAR_DIR}/bin/ifconfig_up.sh inet6 ${n0} ${val} ${n0v6m}
__EOF__
		else
			a=0
		fi
		if [[ $a -gt 0 ]] ; then
			a=$((a + 1))
		fi
	done
	a=1
	while [[ $a -gt 0 ]] ; do
		name=${H}_NET1_ADDR_V4_A${a}
		val=$(eval echo \$$name)
		if [[ -n ${val} ]] ; then
			cat >> ${IPF_TMP_DIR}/${h}_config_net_up.sh <<__EOF__
${IPF_VAR_DIR}/bin/ifconfig_up.sh inet inet ${n1} ${val} ${n1v4m}
__EOF__
		else
			a=0
		fi
		name=${H}_NET1_ADDR_V6_A${a}
		val=$(eval echo \$$name)
		if [[ -n ${val} ]] ; then
			cat >> ${IPF_TMP_DIR}/${h}_config_net_up.sh <<__EOF__
${IPF_VAR_DIR}/bin/ifconfig_up.sh inet inet6 ${n1} ${val} ${n1v6m}
__EOF__
		else
			a=0
		fi
		if [[ $a -gt 0 ]] ; then
			a=$((a + 1))
		fi
	done
	chmod +x ${IPF_TMP_DIR}/${h}_config_net_up.sh
	cat > ${IPF_TMP_DIR}/${h}_config_net_down.sh <<__EOF__
${IPF_VAR_DIR}/bin/ifconfig_down.sh inet ${n0}
${IPF_VAR_DIR}/bin/ifconfig_down.sh inet ${n1}
${IPF_VAR_DIR}/bin/ifconfig_down.sh inet6 ${n0}
${IPF_VAR_DIR}/bin/ifconfig_down.sh inet6 ${n1}
__EOF__
	chmod +x ${IPF_TMP_DIR}/${h}_config_net_down.sh
	dest=$(eval echo \$${H}_CTL_HOSTNAME)
	if [[ ${dest} != DONOTUSE ]] ; then
		${RRCP} ${IPF_TMP_DIR}/${h}_config_net_down.sh ${dest}:${IPF_VAR_DIR}/config_net_down.sh
		${RRCP} ${IPF_TMP_DIR}/${h}_config_net_up.sh ${dest}:${IPF_VAR_DIR}/config_net_up.sh
		#
		# Unconfigure networking...
		#
		${RRSH} -n -l root ${dest} sh ${IPF_VAR_DIR}/config_net_down.sh
		#
		# ...then configure networking.
		#
		${RRSH} -n -l root ${dest} sh ${IPF_VAR_DIR}/config_net_up.sh
	fi
done
#
wget -O /dev/null ftp://${SUT_NET0_ADDR_V4}/${FTP_PATH} >/dev/null 2>&1
if [[ $? -ne 0 ]] ; then
	echo "FTP not available at ${SUT_NET0_ADDR_V4}"
	echo "REQUIRED for testing"
	exit 1
	exit 1
fi
if [[ ${RECEIVER_CTL_HOSTNAME} != DONOTUSE ]]; then
	wget -O /dev/null ftp://${RECEIVER_NET1_ADDR_V4}/${FTP_PATH} >/dev/null 2>&1
	if [[ $? -ne 0 ]] ; then
		echo "FTP not available at ${RECEIVER_NET1_ADDR_V4}"
		echo "REQUIRED for testing"
		exit 1
		exit 1
	fi
fi
#

./routing.sh

#
#
${RRSH} ${SUT_CTL_HOSTNAME} pkill ipmon
${RRSH} ${SUT_CTL_HOSTNAME} ${IPF_BIN_DIR}/forwarding.sh
#
#
exit 0
