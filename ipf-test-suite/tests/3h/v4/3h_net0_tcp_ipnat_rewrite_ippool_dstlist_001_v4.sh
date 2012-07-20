#!/bin/ksh
#
gen_ipf_conf() {
	generate_pass_rules
	generate_test_hdr
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
rewrite in on ${SUT_NET0_IFP_NAME} proto tcp from any to any port = 5050 -> src 0/0 dst dstlist/servers;
__EOF__
	return 0;
}

gen_ippool_conf() {
	cat <<__EOF__
pool nat/dstlist (name servers; policy round-robin;) {
        ${RECEIVER_NET1_ADDR_V4};
        ${RECEIVER_NET1_ADDR_V4_A1};
        ${RECEIVER_NET1_ADDR_V4_A2};
};
__EOF__
	return 0;
}

do_test() {
	ret=0
	start_tcp_server ${RECEIVER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} 5050 A
	tcp_test ${SENDER_CTL_HOSTNAME} ${NET0_FAKE_ADDR_V4} 5050 pass
	ret=$((ret + $?))
	start_tcp_server ${RECEIVER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4_A1} 5050 B
	tcp_test ${SENDER_CTL_HOSTNAME} ${NET0_FAKE_ADDR_V4} 5050 pass
	ret=$((ret + $?))
	start_tcp_server ${RECEIVER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4_A2} 5050 C
	tcp_test ${SENDER_CTL_HOSTNAME} ${NET0_FAKE_ADDR_V4} 5050 pass
	ret=$((ret + $?))
	stop_tcp_server ${RECEIVER_CTL_HOSTNAME} 1 A
	ret=$((ret + $?))
	stop_tcp_server ${RECEIVER_CTL_HOSTNAME} 1 B
	ret=$((ret + $?))
	stop_tcp_server ${RECEIVER_CTL_HOSTNAME} 1 C
	ret=$((ret + $?))
	return $ret;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
