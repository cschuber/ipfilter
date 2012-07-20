#!/bin/ksh

capture_net1=0;
preserve_net1=0;

gen_ipf_conf() {
	generate_pass_rules
	generate_test_hdr
	cat << __EOF__
block in on ${SUT_NET0_IFP_NAME} inet6 proto udp from any to ${SUT_NET0_ADDR_V6} port 5049 <> 5056
block out on ${SUT_NET0_IFP_NAME} inet6 proto udp from ${SUT_NET0_ADDR_V6} port 5049 <> 5056 to ${SENDER_NET0_ADDR_V6}
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
	start_udp_server ${SUT_CTL_HOSTNAME} ${SUT_NET0_ADDR_V6} 5057
	sleep 1
	udp_test ${SENDER_CTL_HOSTNAME} ${SUT_NET0_ADDR_V6} 5057 block
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
