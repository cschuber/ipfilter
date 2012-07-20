
gen_ipf_conf() {
	generate_pass_rules
	generate_test_hdr
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET1_IFP_NAME} ${SENDER_NET0_ADDR_V6} -> ${NET1_FAKE_ADDR_V6} proxy port tftp tftp/udp
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	tftp_test ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V6} ${FTP_PATH} pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_srcdst_1 ${NET1_FAKE_ADDR_V6} ${RECEIVER_NET1_ADDR_V6}
	count=$?
	if [[ $count -lt 3 ]] ; then
		print - "-- ERROR too few packets ($count) seen"
		return 1
	fi
	print "|--- $count packets between ${NET1_FAKE_ADDR_V6} and ${RECEIVER_NET1_ADDR_V6}"
	count_logged_nat_sessions
	created=$?
	if [[ $created -lt 2 ]] ; then
		print - "-- ERROR created count less than 2 ($created)"
		return 1;
	fi
	print - "-- OK created $created NAT sessions"
	return 0;
}
