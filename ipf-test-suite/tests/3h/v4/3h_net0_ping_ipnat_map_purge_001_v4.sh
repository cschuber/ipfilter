
gen_ipf_conf() {
	generate_pass_rules
	generate_test_hdr
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET1_IFP_NAME} ${SENDER_NET0_ADDR_V4} -> ${NET1_FAKE_ADDR_V4} age 300/300 purge
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	ping_test ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} small pass ${SENDER_NET0_ADDR_V4}
	ret=$?
	if [[ $ret != 0 ]] ; then
		print - "-- ERROR ($ret) returned from ping_test"
		return $ret
	fi
	#
	# NAT is locked to prevent more NAT sessions being created between
	# the running of "ipnat -l" and "ipnat -rf"
	#
	${BIN_IPF} -T nat_lock=1 2>&1
	print "|--- look for at least one NAT session for ping"
	${BIN_IPNAT} -l > ${IPF_TMP_DIR}/ipnat.out
	active=$(egrep '^MAP' ${IPF_TMP_DIR}/ipnat.out | wc -l)
	active=$((active))
	print "|--- active=$active"
	if [[ $active != 1 ]] ; then
		print "|--- MAP entry not present when one should be active"
		print "|--- ipnat -l output"
		cat ${IPF_TMP_DIR}/ipnat.out
		${BIN_IPF} -T nat_lock=0 2>&1
		return 1
	fi
	print "|--- remove conf entries in ${TEST_IPNAT_CONF}"
	${BIN_IPNAT} -rf ${TEST_IPNAT_CONF}
	print "|--- verify NAT configuration is empty"
	${BIN_IPNAT} -l > ${IPF_TMP_DIR}/ipnat.out
	${BIN_IPF} -T nat_lock=0 2>&1
	active=$(egrep '^MAP' ${IPF_TMP_DIR}/ipnat.out | wc -l)
	active=$((active))
	print "|--- active=$active"
	if [[ $active != 0 ]] ; then
		print "|--- MAP entry present when none should be active"
		print "|--- ipnat -l output"
		cat ${IPF_TMP_DIR}/ipnat.out
		return 1;
	fi
	return 0;
}

do_tune() {
	return 0;
}

do_verify() {
	count_logged_nat_sessions
	count=$?
	count_purged_nat_sessions
	purged=$?
	if [[ $count != $purged ]] ; then
		print - "-- ERROR NAT sessions ($count) do not equal purged ($purged)"
		return 1
	fi
	print - "-- OK NAT sessions ($count) equals purged ($purged)"
	return 0;
}
