#!/bin/ksh

capture_net1=0;
preserve_net1=0;

gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET0_IFP_NAME} inet6 proto udp from any to pool/net0hosts
pass out on ${SUT_NET0_IFP_NAME} inet6 proto udp from pool/net0hosts to any
__EOF__
	return 0;
}

gen_ipnat_conf() {
	return 1;
}

gen_ippool_conf() {
	cat <<__EOF__
pool ipf/tree (name net0hosts;) { !${NET0_NET_V6}::0/${NET0_NETMASK_V6}; ${SUT_NET0_ADDR_V6}; };
__EOF__
	return 0;
}

do_test() {
	start_udp_server ${SUT_CTL_HOSTNAME} ${SUT_NET0_ADDR_V6} 5051
	sleep 1
	udp_test ${SENDER_CTL_HOSTNAME} ${SUT_NET0_ADDR_V6} 5051 pass
	ret=$?
	stop_udp_server ${SUT_CTL_HOSTNAME} 1
	ret=$((ret + $?))
	return $ret;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
