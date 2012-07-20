
gen_ipf_conf() {
	generate_pass_rules
	generate_test_hdr
	cat << __EOF__
block in on ${SUT_NET1_IFP_NAME} proto tcp from ${RECEIVER_NET1_ADDR_V4} port < 5055 to any
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
	start_tcp_server ${RECEIVER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} 5054
	sleep 1
	tcp_test ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} 5054 block
	ret=$?
	ret=$((ret))
	stop_tcp_server ${RECEIVER_CTL_HOSTNAME} 0
	ret=$((ret + $?))
	return $ret;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_src_0 ${RECEIVER_NET1_ADDR_V4} 5054
	count=$?
	if [[ $count -ne 0 ]]; then
		print - "-- ERROR $count matching packets found"
		dumpcap_src_0 ${RECEIVER_NET1_ADDR_V4} 5054
		return 1
	fi
	print - "-- OK no matching packets found"
	return 0;
}
