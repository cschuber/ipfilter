
gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET0_IFP_NAME} proto udp from any to any port = 5050 keep state
pass in on ${SUT_NET0_IFP_NAME} proto udp from any to any port = 5060 keep state
__EOF__
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
rdr ${SUT_NET0_IFP_NAME} ${NET1_FAKE_ADDR_V4} port 1050 -> ${RECEIVER_NET1_ADDR_V4} port = 5050 udp round-robin sticky
rdr ${SUT_NET0_IFP_NAME} ${NET1_FAKE_ADDR_V4} port 1050 -> ${RECEIVER_NET1_ADDR_V4} port = 5060 udp round-robin
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	start_udp_server ${RECEIVER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} 5050 A
	start_udp_server ${RECEIVER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} 5060 B
	sleep 2
	udp_test ${SENDER_CTL_HOSTNAME} ${NET1_FAKE_ADDR_V4} 1050 pass
	udp_test ${SENDER_CTL_HOSTNAME} ${NET1_FAKE_ADDR_V4} 1050 pass
	udp_test ${SENDER_CTL_HOSTNAME} ${NET1_FAKE_ADDR_V4} 1050 pass
	ret=$?
	stop_udp_server ${RECEIVER_CTL_HOSTNAME} 2 A
	ret=$((ret + $?))
	stop_udp_server ${RECEIVER_CTL_HOSTNAME} 1 B
	ret=$((ret + $?))
	return $ret;
}

do_tune() {
	return 0;
}

do_verify() {
	return 2;
}
