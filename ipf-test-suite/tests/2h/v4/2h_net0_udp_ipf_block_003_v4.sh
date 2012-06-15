#!/bin/ksh

gen_ipf_conf() {
	generate_pass_rules
	generate_test_hdr
	cat << __EOF__
block in on ${SUT_NET0_IFP_NAME} proto udp from any to ${SUT_NET0_ADDR_V4} port >= 5053
block out on ${SUT_NET0_IFP_NAME} proto udp from ${SUT_NET0_ADDR_V4} port >= 5053 to ${SENDER_NET0_ADDR_V4}
__EOF__
	return 0;
}

gen_ipnat_conf() {
	return 1;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	start_udp_server ${SUT_CTL_HOSTNAME} ${SUT_NET0_ADDR_V4} 5053
	sleep 1
	udp_test ${SENDER_CTL_HOSTNAME} ${SUT_NET0_ADDR_V4} 5053 block
	ret=$?
	stop_udp_server ${SUT_CTL_HOSTNAME} 0
	ret=$((ret + $?))
	return $ret;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
