
gen_ipf_conf() {
	generate_pass_rules
	generate_test_hdr
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET1_IFP_NAME} ${SENDER_NET0_ADDR_V4} -> ${NET1_FAKE_ADDR_V4} age 60/60
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	ping_test ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} big pass
	ret=$?
	if [[ $ret != 0 ]] ; then
		print - "-- ERROR ($ret) returned from ping_test"
		return $ret
	fi
	${BIN_IPNAT} -l > ${IPF_TMP_DIR}/ipnat.out
	active=$(egrep '^MAP' ${IPF_TMP_DIR}/ipnat.out | wc -l)
	active=$((active))
	if [[ $active -lt 1 ]] ; then
		print - "-- ERROR active NAT sessions found ipnat.out ($active)"
		cat ${IPF_TMP_DIR}/ipnat.out
		return 1
	fi
	print - "-- OK ping_test succeeded with age"
	return 0
}

do_tune() {
	return 0;
}

do_verify() {
	verify_srcdst_1 ${RECEIVER_NET1_ADDR_V4} ${NET1_FAKE_ADDR_V4} frag
	count=$?
	if [[ $count != 12 ]] ; then
		print - "-- ERROR $count packets when 12 should be seen"
		return 1;
	fi
	print - "-- OK correct packet count (12) seen"
	return 0;
}
