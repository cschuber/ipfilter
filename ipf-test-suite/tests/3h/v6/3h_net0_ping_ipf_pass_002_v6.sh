
gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET0_IFP_NAME} proto ipv6-icmp from any to ${RECEIVER_NET1_ADDR_V6}
pass out on ${SUT_NET0_IFP_NAME} proto ipv6-icmp from ${RECEIVER_NET1_ADDR_V6} to any
pass out on ${SUT_NET1_IFP_NAME} proto ipv6-icmp from any to ${RECEIVER_NET1_ADDR_V6}
pass in on ${SUT_NET1_IFP_NAME} proto ipv6-icmp from ${RECEIVER_NET1_ADDR_V6} to any
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
	ping_test ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V6} small pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	return 2;
}
