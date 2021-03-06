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
map ${SUT_NET0_IFP_NAME} inet6 ${SUT_NET0_ADDR_V6} -> ${NET0_FAKE_ADDR_V6} age 60/60 udp
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
	if [[ $active == 0 ]] ; then
		ret=1
		echo "-- No active NAT sessions found in ipnat.out ($active)"
		cat ${IPF_TMP_DIR}/ipnat.out
	else
		ret=0
	fi
	return $ret;
}

do_tune() {
	return 0;
}

do_verify() {
	expired=0
	count_expired_nat_sessions
	expired=$((expired + $?))
	if [[ $expired != 0 ]] ; then
		echo "-- ERROR NAT sessions expired ($expired) non-zero"
		return 1
	fi
	return 0;
}
