#!/bin/ksh

gen_ipf_conf() {
	generate_pass_rules
	generate_test_hdr
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET0_IFP_NAME} ${SUT_NET0_ADDR_V4} -> ${NET0_FAKE_ADDR_V4} icmpidmap icmp 1000:2000
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	ping_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V4} small pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	${IPF_BIN_DIR}/log.sh verify_srcdst_0 \
	    ${NET0_FAKE_ADDR_V4} ${SENDER_NET0_ADDR_V4}
	if [[ $? -eq 0 ]] ; then
		echo "No packets ${NET0_FAKE_ADDR_V4},${SENDER_NET0_ADDR_V4}"
		return 1
	fi
	return 0;
}
