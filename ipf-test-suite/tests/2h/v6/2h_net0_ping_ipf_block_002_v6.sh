capture_net1=0;
preserve_net1=0;

gen_ipf_conf() {
	generate_pass_rules
	generate_test_hdr
	cat << __EOF__
block in on ${SUT_NET0_IFP_NAME} inet6 proto ipv6-icmp all
block out on ${SUT_NET0_IFP_NAME} inet6 proto ipv6-icmp all
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
	ping_test ${SENDER_CTL_HOSTNAME} ${SUT_NET0_ADDR_V6} small block
	ret=$?
	echo "PING result=$ret"
	return $ret;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
