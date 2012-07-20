capture_net1=0;
preserve_net1=0;

gen_ipf_conf() {
	generate_test_hdr
	cat << __EOF__
pass in quick on ${SUT_NET0_IFP_NAME} inet6 proto ipv6-icmp all
pass out quick on ${SUT_NET0_IFP_NAME} inet6 proto ipv6-icmp all
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
	ping_test ${SENDER_CTL_HOSTNAME} ${SUT_NET0_ADDR_V6} small pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
