#!/bin/ksh

gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	return 0;
}

gen_ipnat_conf() {
	return 1;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	traceroute_test ${SENDER_CTL_HOSTNAME} ${SENDER_NET0_IFP_NAME} \
	    ${SENDER_NET0_ADDR_V4} ${RECEIVER_NET1_ADDR_V4} block
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
