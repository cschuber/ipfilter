capture_net1=0;
preserve_net1=0;

gen_ipf_conf() {
	generate_pass_rules
	generate_test_hdr
	cat << __EOF__
block in on ${SUT_NET0_IFP_NAME} all
block out on ${SUT_NET0_IFP_NAME} all
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
	ping_test ${SENDER_CTL_HOSTNAME} ${SUT_NET0_ADDR_V4} big block
	ret=$?
	print - "|--- PING result=$ret"
	return $ret;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_src_0 ${SUT_NET0_ADDR_V4} frag
	count=$?
	if [[ $count != 0 ]] ; then
		print - "-- ERROR $count packets when 0 should be seen"
		return 1;
	fi
	print - "-- OK no packets seen"
	return 0;
}
