#!/bin/ksh
# ni7
gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET1_IFP_NAME} proto udp from any to any port = 5057 keep state
__EOF__
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET0_IFP_NAME} ${SUT_NET0_ADDR_V4} -> ${NET0_FAKE_ADDR_V4} udp
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	start_udp_server ${SENDER_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V4} 5057
	sleep 3
	udp_test ${SENDER_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V4} 5057 pass
	ret=$?
	stop_udp_server ${RECEIVER_CTL_HOSTNAME} 1
	ret=$((ret + $?))
	return $ret;
}

do_tune() {
	return 0;
}

do_verify() {
	${IPF_BIN_DIR}/log.sh verify_srcdst_0 \
	    ${NET0_FAKE_ADDR_V4} ${SENDER_NET0_ADDR_V4}
	if [[ $? -eq 0 ]] ; then
		echo "No packets ${NET0_FAKE_ADDR_V4},${SENDER_NET0_ADDR_V4}"
		return 1
	fi
	return 0;
}
