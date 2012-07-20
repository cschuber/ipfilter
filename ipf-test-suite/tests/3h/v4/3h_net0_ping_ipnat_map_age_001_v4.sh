#!/bin/ksh


gen_ipf_conf() {
	generate_pass_rules
	generate_test_hdr
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET1_IFP_NAME} ${SENDER_NET0_ADDR_V4} -> ${NET1_FAKE_ADDR_V4} age 1/1
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	ping_test ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} small pass
	ret=$?
	if [[ $ret != 0 ]] ; then
		print - "-- ERROR ($ret) returned from ping_test"
		return $ret
	fi
	sleep 1
	${BIN_IPNAT} -l > ${IPF_TMP_DIR}/ipnat.out
	active=$(egrep '^MAP' ${IPF_TMP_DIR}/ipnat.out | wc -l)
	active=$((active))
	if [[ $active != 0 ]] ; then
		print - "|--- Active NAT sessions found in ipnat.out ($active)"
		cat ${IPF_TMP_DIR}/ipnat.out
		return 1;
	fi
	return 0;
}

do_tune() {
	return 0;
}

do_verify() {
	count_logged_nat_sessions
	count=$?
	count=$((count + 0))
	count_expired_nat_sessions
	expired=$?
	expired=$((expired + 0))
	if [[ $count != $expired ]] ; then
		print - "-- ERROR NAT sessions ($count) do not equal expired ($expired)"
		return 1
	fi
	print - "-- OK NAT sessions ($count) equals expired ($expired)"
	return 0;
}
