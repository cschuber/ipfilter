
gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET0_IFP_NAME} proto udp from any to pool/net1hosts
pass out on ${SUT_NET1_IFP_NAME} proto udp from any to pool/net1hosts
pass in on ${SUT_NET1_IFP_NAME} proto udp from pool/net1hosts to any
pass out on ${SUT_NET0_IFP_NAME} proto udp from pool/net1hosts to any
__EOF__
	return 0;
}

gen_ipnat_conf() {
	return 1;
}

gen_ippool_conf() {
	cat <<__EOF__
pool ipf/tree (name net1hosts;) { !${NET1_NET_V4}.0/${NET1_NETMASK_V4}; ${RECEIVER_NET1_ADDR_V4}; };
__EOF__
	return 0;
}

do_test() {
	basic_udp_test ${RECEIVER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} \
	    5051 ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	return 2;
}
