#!/bin/ksh

capture_net1=0;
preserve_net1=0;

gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET0_IFP_NAME} proto tcp from any to any flags S keep state
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
	start_tcp_server ${SUT_CTL_HOSTNAME} ${SUT_NET0_ADDR_V4} 5050
	sleep 1
	tcp_test ${SENDER_CTL_HOSTNAME} ${SUT_NET0_ADDR_V4} 5050 pass
	ret=$?
	stop_tcp_server ${SUT_CTL_HOSTNAME} 1
	ret=$((ret + $?))
	return $ret;
}

do_tune() {
	return 0;
}

do_verify() {
	return 2;
}
