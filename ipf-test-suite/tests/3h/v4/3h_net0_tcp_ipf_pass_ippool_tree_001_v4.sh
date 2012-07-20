
gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET0_IFP_NAME} proto tcp from any to pool/net0hosts
pass out on ${SUT_NET0_IFP_NAME} proto tcp from pool/net0hosts to any
pass out on ${SUT_NET1_IFP_NAME} proto tcp from any to pool/net0hosts
pass in on ${SUT_NET1_IFP_NAME} proto tcp from pool/net0hosts to any
__EOF__
	return 0;
}

gen_ipnat_conf() {
	return 1;
}

gen_ippool_conf() {
	cat <<__EOF__
pool ipf/tree (name net0hosts;) { ${RECEIVER_NET1_ADDR_V4}; };
__EOF__
	return 0;
}

do_test() {
	start_tcp_server ${RECEIVER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} 5051
	sleep 1
	tcp_test ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} 5051 pass
	ret=$?
	ret=$((ret))
	stop_tcp_server ${RECEIVER_CTL_HOSTNAME} 1
	ret=$((ret + $?))
	return $ret;
}

do_tune() {
	return 0;
}

do_verify() {
	return 2;
}
