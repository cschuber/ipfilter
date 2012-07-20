
gen_ipf_conf() {
	generate_pass_rules
	generate_test_hdr
	cat << __EOF__
block out on ${SUT_NET1_IFP_NAME} inet6 proto udp from any to ${RECEIVER_NET1_ADDR_V6} port < 5055
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
	start_udp_server ${RECEIVER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V6} 5054
	sleep 1
	udp_test ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V6} 5054 block
	ret=$?
	stop_udp_server ${RECEIVER_CTL_HOSTNAME} 0
	x=$?
	ret=$((ret + x))
	return $ret;
}

do_tune() {
	return 0;
}

do_verify() {
	return 2;
}
