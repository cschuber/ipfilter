gen_ipf_conf() {
	generate_test_hdr
	cat << __EOF__
pass in quick on ${SUT_NET0_IFP_NAME} proto icmp from any to ${RECEIVER_NET1_ADDR_V4}/${NET0_NETMASK_V4}
pass out quick on ${SUT_NET0_IFP_NAME} proto icmp from ${RECEIVER_NET1_ADDR_V4}/${NET0_NETMASK_V4} to any
pass out quick on ${SUT_NET1_IFP_NAME} proto icmp from any to ${RECEIVER_NET1_ADDR_V4}/${NET0_NETMASK_V4}
pass in quick on ${SUT_NET1_IFP_NAME} proto icmp from ${RECEIVER_NET1_ADDR_V4}/${NET0_NETMASK_V4} to any
__EOF__
	generate_block_rules
	return 0;
}

gen_ipnat_conf() {
	return 1;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	ping_test ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} small pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
