
gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET0_IFP_NAME} proto udp from any to ${RECEIVER_NET1_ADDR_V6} port 5050:5058
pass out on ${SUT_NET1_IFP_NAME} proto udp from any to ${RECEIVER_NET1_ADDR_V6} port 5050:5058
pass in on ${SUT_NET1_IFP_NAME} proto udp from ${RECEIVER_NET1_ADDR_V6} port 5050:5058 to ${SENDER_NET0_ADDR_V6}
pass out on ${SUT_NET0_IFP_NAME} proto udp from ${RECEIVER_NET1_ADDR_V6} port 5050:5058 to ${SENDER_NET0_ADDR_V6}
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
	basic_udp_test ${RECEIVER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V6} \
	    5058 ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V6} pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	return 2;
}
