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
map ${SUT_NET0_IFP_NAME} ${SUT_NET0_ADDR_V6} -> ${NET0_FAKE_ADDR_V6} age 300/300 purge
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	ping_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V6} big pass ${SUT_NET0_ADDR_V6}
	ret=$?
	if [[ $ret != 0 ]] ; then
		print - "-- ERROR ($ret) returned from ping_test"
		return $ret
	fi
	print - "|--- look for at least one NAT session for ping"
	${BIN_IPNAT} -l > ${IPF_TMP_DIR}/ipnat.out
	active=$(egrep '^MAP' ${IPF_TMP_DIR}/ipnat.out | wc -l)
	active=$((active))
	print - "|--- active=$active"
	if [[ $active != 1 ]] ; then
		print - "-- ERROR MAP entry not present when active expected"
		print "|--- ipnat -l output"
		cat ${IPF_TMP_DIR}/ipnat.out
		return 1
	fi
	print "|--- remove conf entries in ${TEST_IPNAT_CONF}"
	${BIN_IPNAT} -rf ${TEST_IPNAT_CONF}
	print "|--- veirfy NAT configuration is empty"
	${BIN_IPNAT} -l > ${IPF_TMP_DIR}/ipnat.out
	active=$(egrep '^MAP' ${IPF_TMP_DIR}/ipnat.out | wc -l)
	active=$((active))
	print "|--- active=$active"
	if [[ $active != 0 ]] ; then
		print - "-- ERROR MAP entry present when none should be active"
		print "|--- ipnat -l output"
		cat ${IPF_TMP_DIR}/ipnat.out
		return 1
	fi
	return 0
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
		print - "-- ERROR NAT sessions ($count) != purged ($purged)"
		return 1
	fi
	return 0;
}
