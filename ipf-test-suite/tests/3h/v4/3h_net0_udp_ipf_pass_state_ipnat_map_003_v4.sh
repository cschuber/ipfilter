#!/bin/ksh
# ni7
gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET0_IFP_NAME} proto udp from any to any port = 5059 keep state
__EOF__
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET1_IFP_NAME} ${SENDER_NET0_ADDR_V4} -> ${NET1_FAKE_ADDR_V4} portmap udp auto
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	start_udp_server ${RECEIVER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} 5059
	sleep 3
	udp_test ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} 5059 pass
	ret=$?
	stop_udp_server ${RECEIVER_CTL_HOSTNAME} 1
	ret=$((ret + $?))
	return $ret;
}

do_tune() {
	return 0;
}

do_verify() {
	${IPF_BIN_DIR}/log.sh verify_srcdst_1 \
	    ${NET1_FAKE_ADDR_V4} ${RECEIVER_NET1_ADDR_V4}
	if [[ $? -eq 0 ]] ; then
		echo "No packets ${NET1_FAKE_ADDR_V4},${RECEIVER_NET1_ADDR_V4}"
		return 1
	fi
	return 0;
}
