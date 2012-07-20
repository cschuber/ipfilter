#!/bin/ksh

capture_net1=0;
preserve_net1=0;

gen_ipf_conf() {
	generate_pass_rules
	generate_test_hdr
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET0_IFP_NAME} inet6 ${SUT_NET0_ADDR_V6} -> ${NET0_FAKE_ADDR_V6} age 300/300 udp purge
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	start_udp_server ${SENDER_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V6} 5052
	sleep 1
	udp_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V6} 5052 pass
	ret=$?
	stop_udp_server ${SENDER_CTL_HOSTNAME} 1
	ret=$((ret + $?))
	${BIN_IPNAT} -l > ${IPF_TMP_DIR}/ipnat.out
	active=$(egrep '^MAP' ${IPF_TMP_DIR}/ipnat.out | wc -l)
	active=$((active))
	if [[ $active != 1 ]] ; then
		echo "-- ERROR MAP entry count wrong, should be 1 ($active)"
		echo "-- ipnat -l output"
		cat ${IPF_TMP_DIR}/ipnat.out
		return 1
	fi
	echo "-- active=$active"
	echo "-- remove conf entries in ${TEST_IPNAT_CONF}"
	${BIN_IPNAT} -rf ${TEST_IPNAT_CONF}
	echo "-- veirfy NAT configuration is empty"
	${BIN_IPNAT} -l > ${IPF_TMP_DIR}/ipnat.out
	active=$(egrep '^MAP' ${IPF_TMP_DIR}/ipnat.out | wc -l)
	active=$((active))
	echo "-- active=$active"
	if [[ $active != 0 ]] ; then
		echo "-- ERROR MAP entry present when none should be active"
		echo "-- ipnat -l output"
		cat ${IPF_TMP_DIR}/ipnat.out
		ret=1
	else
		ret=0
	fi
	return $ret;
}

do_tune() {
	return 0;
}

do_verify() {
	count_logged_nat_sessions
	count=$?
	count_purged_nat_sessions
	purged=$?
	if [[ $count != $purged ]] ; then
		echo "-- ERROR NAT sessions ($count) do not equal purged ($purged)"
		return 1
	fi
	return 0;
}
