#!/bin/ksh
# ni9
gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET0_IFP_NAME} proto tcp from any to any port = 5050 flags S keep state
pass in on ${SUT_NET0_IFP_NAME} proto tcp from any to any port = 5060 flags S keep state
pass in on ${SUT_NET0_IFP_NAME} proto tcp from any to any port = 5070 flags S keep state
__EOF__
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
rdr ${SUT_NET0_IFP_NAME} ${NET0_FAKE_ADDR_V4} port 1050 -> ${SUT_NET0_ADDR_V4} port = 5050 tcp round-robin
rdr ${SUT_NET0_IFP_NAME} ${NET0_FAKE_ADDR_V4} port 1050 -> ${SUT_NET0_ADDR_V4} port = 5060 tcp round-robin
rdr ${SUT_NET0_IFP_NAME} ${NET0_FAKE_ADDR_V4} port 1050 -> ${SUT_NET0_ADDR_V4} port = 5070 tcp round-robin
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	start_tcp_server ${SUT_CTL_HOSTNAME} ${SUT_NET0_ADDR_V4} 5050 A
	start_tcp_server ${SUT_CTL_HOSTNAME} ${SUT_NET0_ADDR_V4} 5060 B
	start_tcp_server ${SUT_CTL_HOSTNAME} ${SUT_NET0_ADDR_V4} 5070 C
	sleep 3
	tcp_test ${SENDER_CTL_HOSTNAME} ${NET0_FAKE_ADDR_V4} 1050 pass
	tcp_test ${SENDER_CTL_HOSTNAME} ${NET0_FAKE_ADDR_V4} 1050 pass
	tcp_test ${SENDER_CTL_HOSTNAME} ${NET0_FAKE_ADDR_V4} 1050 pass
	ret=$?
	stop_tcp_server ${SUT_CTL_HOSTNAME} 1 A
	ret=$((ret + $?))
	stop_tcp_server ${SUT_CTL_HOSTNAME} 1 B
	ret=$((ret + $?))
	stop_tcp_server ${SUT_CTL_HOSTNAME} 1 C
	ret=$((ret + $?))
	return $ret;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
