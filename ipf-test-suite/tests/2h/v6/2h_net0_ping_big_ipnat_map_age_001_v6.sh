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
map ${SUT_NET0_IFP_NAME} ${SUT_NET0_ADDR_V6} -> ${NET0_FAKE_ADDR_V6} age 1/1
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	ping_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V6} big pass
	ret=$?
	if [[ $ret != 0 ]] ; then
		echo "-- error ($ret) returned from ping_test"
		return $ret
	fi
	sleep 1
	${BIN_IPNAT} -l > ${IPF_TMP_DIR}/ipnat.out
	active=$(egrep '^MAP' ${IPF_TMP_DIR}/ipnat.out | wc -l)
	active=$((active))
	if [[ $active != 0 ]] ; then
		ret=1
		echo "-- Active NAT sessions found in ipnat.out ($active)"
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
	count_logged_nat_sessions
	count=$?
	count_expired_nat_sessions
	expired=$?
	if [[ $count != $expired ]] ; then
		echo "-- NAT sessions ($count) do not equal expired ($purged)"
		return 1
	fi
	return 0;
}
