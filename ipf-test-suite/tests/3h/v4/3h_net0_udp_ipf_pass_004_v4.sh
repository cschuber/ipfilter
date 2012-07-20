#!/bin/ksh

gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET0_IFP_NAME} proto udp from any to ${RECEIVER_NET1_ADDR_V4} port < 5055
pass out on ${SUT_NET0_IFP_NAME} proto udp from ${RECEIVER_NET1_ADDR_V4} port < 5055 to ${SENDER_NET0_ADDR_V4}
pass out on ${SUT_NET1_IFP_NAME} proto udp from any to ${RECEIVER_NET1_ADDR_V4} port < 5055
pass in on ${SUT_NET1_IFP_NAME} proto udp from ${RECEIVER_NET1_ADDR_V4} port < 5055 to ${SENDER_NET0_ADDR_V4}
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
	basic_udp_test ${RECEIVER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} \
	    5054 ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
