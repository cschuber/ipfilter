#!/bin/ksh

gen_ipf_conf() {
	generate_pass_rules
	generate_test_hdr
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET0_IFP_NAME} ${SUT_NET0_ADDR_V4} -> ${NET0_FAKE_ADDR_V4} age 60/60
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	ping_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V4} small pass
	ret=$?
	if [[ $ret != 0 ]] ; then
		echo "-- error ($ret) returned from ping_test"
		return $ret
	fi
	${BIN_IPNAT} -l > ${IPF_TMP_DIR}/ipnat.out
	active=$(egrep '^MAP' ${IPF_TMP_DIR}/ipnat.out | wc -l)
	active=$((active))
	if [[ $active != 1 ]] ; then
		echo "-- No active NAT sessions found ipnat.out ($active)"
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
	return 0;
}
