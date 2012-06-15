#!/bin/ksh

gen_ipf_conf() {
	generate_pass_rules
	generate_test_hdr
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET0_IFP_NAME} ${SUT_NET0_ADDR_V4} -> ${NET0_FAKE_ADDR_V4} age 300/300 purge
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	ping_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V4} small pass ${SUT_NET0_ADDR_V4}
	ret=$?
	if [[ $ret != 0 ]] ; then
		echo "-- error ($ret) returned from ping_test"
		return $ret
	fi
	echo "-- look for at least one NAT session for ping"
	${BIN_IPNAT} -l > ${IPF_TMP_DIR}/ipnat.out
	active=$(egrep '^MAP' ${IPF_TMP_DIR}/ipnat.out | wc -l)
	active=$((active))
	echo "-- active=$active"
	if [[ $active != 1 ]] ; then
		echo "MAP entry not present when one should be active"
		echo "-- ipnat -l output"
		cat ${IPF_TMP_DIR}/ipnat.out
		return 1
	fi
	echo "-- remove conf entries in ${TEST_IPNAT_CONF}"
	${BIN_IPNAT} -rf ${TEST_IPNAT_CONF}
	echo "-- veirfy NAT configuration is empty"
	${BIN_IPNAT} -l > ${IPF_TMP_DIR}/ipnat.out
	active=$(egrep '^MAP' ${IPF_TMP_DIR}/ipnat.out | wc -l)
	active=$((active))
	echo "-- active=$active"
	if [[ $active != 0 ]] ; then
		echo "MAP entry present when none should be active"
		echo "-- ipnat -l output"
		cat ${IPF_TMP_DIR}/ipnat.out
		ret=1
	else
		ret=0
	fi
	return $ret;
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
		echo "-- NAT sessions ($count) do not equal purged ($purged)"
		return 1
	fi
	return 0;
}
