#!/bin/ksh

gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET0_IFP_NAME} proto tcp from hash/net0hosts to hash/net0hosts
pass out on ${SUT_NET0_IFP_NAME} proto tcp from hash/net0hosts to hash/net0hosts
__EOF__
	return 0;
}

gen_ipnat_conf() {
	return 1;
}

gen_ippool_conf() {
	cat <<__EOF__
pool ipf/hash (name net0hosts;) { ${NET0_NET_V4}.0/${NET0_NETMASK_V4}; };
__EOF__
	return 0;
}

do_test() {
	start_tcp_server ${SUT_CTL_HOSTNAME} ${SUT_NET0_ADDR_V4} 5051
	sleep 1
	tcp_test ${SENDER_CTL_HOSTNAME} ${SUT_NET0_ADDR_V4} 5051 pass
	ret=$?
	stop_tcp_server ${SUT_CTL_HOSTNAME} 1
	ret=$((ret + $?))
	return $ret;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
