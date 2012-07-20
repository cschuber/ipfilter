#!/bin/ksh

. ./config.sh

#
${RRSH} -n ${SENDER_CTL_HOSTNAME} "${IPF_BIN_DIR}/route.sh flush;"
${RRSH} -n ${SENDER_CTL_HOSTNAME} "${IPF_BIN_DIR}/route.sh add -inet -net ${NET1_NET_V4}.0 ${SUT_NET0_ADDR_V4};"
${RRSH} -n ${SENDER_CTL_HOSTNAME} "${IPF_BIN_DIR}/route.sh add -inet -net ${NET0_FAKE_NET_V4} -netmask ${NET0_FAKE_NETMASK_V4} ${SUT_NET0_ADDR_V4};"
${RRSH} -n ${SENDER_CTL_HOSTNAME} "${IPF_BIN_DIR}/route.sh add -inet6 -net ${NET0_FAKE_NET_V6} -prefixlen ${NET0_FAKE_NETMASK_V6} ${SUT_NET0_ADDR_V6};"
${RRSH} -n ${SENDER_CTL_HOSTNAME} "${IPF_BIN_DIR}/route.sh add -inet -net ${NET1_FAKE_NET_V4} -netmask ${NET1_FAKE_NETMASK_V4}  ${SUT_NET0_ADDR_V4};"
${RRSH} -n ${SENDER_CTL_HOSTNAME} "${IPF_BIN_DIR}/route.sh add -inet6 -net ${NET1_NET_V6}::0 -prefixlen ${NET1_NETMASK_V6} ${SUT_NET0_ADDR_V6};"
${RRSH} -n ${SENDER_CTL_HOSTNAME} "${IPF_BIN_DIR}/route.sh add -inet6 -net ${NET1_FAKE_NET_V6} -prefixlen ${NET1_FAKE_NETMASK_V6} ${SUT_NET0_ADDR_V6};"
if [[ ${RECEIVER_CTL_HOSTNAME} != DONOTUSE ]]; then
	${RRSH} -n ${RECEIVER_CTL_HOSTNAME} "${IPF_BIN_DIR}/route.sh flush"
	${RRSH} -n ${RECEIVER_CTL_HOSTNAME} "${IPF_BIN_DIR}/route.sh add -inet -net ${NET0_NET_V4}.0 ${SUT_NET1_ADDR_V4};"
	${RRSH} -n ${RECEIVER_CTL_HOSTNAME} "${IPF_BIN_DIR}/route.sh add -inet -net ${NET0_FAKE_ADDR_V4} -netmask ${NET0_FAKE_NETMASK_V4} ${SUT_NET1_ADDR_V4};"
	${RRSH} -n ${RECEIVER_CTL_HOSTNAME} "${IPF_BIN_DIR}/route.sh add -inet6 -net ${NET0_FAKE_ADDR_V6} -prefixlen ${NET0_FAKE_NETMASK_V6} ${SUT_NET1_ADDR_V6};"
	${RRSH} -n ${RECEIVER_CTL_HOSTNAME} "${IPF_BIN_DIR}/route.sh add -inet -net ${NET1_FAKE_ADDR_V4} -netmask ${NET1_FAKE_NETMASK_V4} ${SUT_NET1_ADDR_V4};"
	${RRSH} -n ${RECEIVER_CTL_HOSTNAME} "${IPF_BIN_DIR}/route.sh add -inet6 -net ${NET0_NET_V6}::0 -prefixlen ${NET0_NETMASK_V6} ${SUT_NET1_ADDR_V6};"
	${RRSH} -n ${RECEIVER_CTL_HOSTNAME} "${IPF_BIN_DIR}/route.sh add -inet6 -net ${NET1_FAKE_ADDR_V6} -prefixlen ${NET1_FAKE_NETMASK_V6} ${SUT_NET1_ADDR_V6};"
	#
	# Build tunnels
	#
	#${RRSH} ${SENDER_CTL_HOSTNAME} ${IPF_BIN_DIR}/tunnel.sh create local ${SENDER_NET0_ADDR_V4} ${RECEIVER_NET1_ADDR_V4}
	#${RRSH} ${RECEIVER_CTL_HOSTNAME} ${IPF_BIN_DIR}/tunnel.sh create remote ${RECEIVER_NET1_ADDR_V4} ${SENDER_NET0_ADDR_V4}
fi
#
exit 0
