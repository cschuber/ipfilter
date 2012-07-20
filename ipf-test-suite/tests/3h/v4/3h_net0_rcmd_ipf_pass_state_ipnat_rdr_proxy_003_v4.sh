
gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
        cat <<__EOF__
pass in quick on ${SUT_NET0_IFP_NAME} proto tcp from ${SENDER_NET0_ADDR_V4} to ${RECEIVER_NET1_ADDR_V4} port = shell flags S keep state
__EOF__
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
rdr ${SUT_NET0_IFP_NAME} ${NET1_FAKE_ADDR_V4} -> ${RECEIVER_NET1_ADDR_V4} proxy port 514 rcmd/tcp
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	rcmd_test ${SENDER_CTL_HOSTNAME} ${NET1_FAKE_ADDR_V4} pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	count_logged_nat_sessions
	created=$?
	if [[ $created -lt 2 ]] ; then
		print - "-- ERROR created count less than 2 ($created)"
		return 1;
	fi
	print - "-- OK created $created NAT sessions"
	return 0;
}
