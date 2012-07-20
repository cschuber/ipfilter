
gen_ipf_conf() {
	generate_pass_rules
	generate_test_hdr
	cat << __EOF__
block in on ${SUT_NET0_IFP_NAME} proto icmp from any to ${RECEIVER_NET1_ADDR_V4}/${NET0_NETMASK_V4}
block out on ${SUT_NET0_IFP_NAME} proto icmp from ${RECEIVER_NET1_ADDR_V4}/${NET0_NETMASK_V4} to any
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
	ping_test ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} big block
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_src_1 ${RECEIVER_NET1_ADDR_V4} frag
	count=$?
	if [[ $count != 0 ]] ; then
		print - "-- ERROR $count packets when 0 should be seen"
		return 1;
	fi
	print - "-- OK no packets seen"
	return 0;
}
