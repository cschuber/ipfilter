
gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET0_IFP_NAME} proto icmp from any to any icmp-type echo
pass in on ${SUT_NET0_IFP_NAME} proto icmp from any to any with frag
pass out on ${SUT_NET0_IFP_NAME} proto icmp from any to any icmp-type echorep
pass out on ${SUT_NET0_IFP_NAME} proto icmp from any to any with frag
pass out on ${SUT_NET1_IFP_NAME} proto icmp from any to any icmp-type echo
pass out on ${SUT_NET1_IFP_NAME} proto icmp from any to any with frag
pass in on ${SUT_NET1_IFP_NAME} proto icmp from any to any icmp-type echorep
pass in on ${SUT_NET1_IFP_NAME} proto icmp from any to any with frag
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
	ping_test ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} big pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_srcdst_1 ${SENDER_NET0_ADDR_V4} ${RECEIVER_NET1_ADDR_V4} frag
	count=$?
	if [[ $count != 12 ]] ; then
		print - "-- ERROR $count packets when 12 should be seen"
		return 1;
	fi
	print - "-- OK correct packet count (12) seen"
	return 0;
}
