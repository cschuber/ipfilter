#!/bin/ksh
# ni7
gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass out on ${SUT_NET0_IFP_NAME} proto tcp from any to any port = 5050 flags S keep state
__EOF__
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET0_IFP_NAME} ${SUT_NET0_ADDR_V4} -> ${NET0_FAKE_ADDR_V4} portmap tcp 10000:11000
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	start_tcp_server ${SENDER_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V4} 5050
	sleep 1
	tcp_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V4} 5050 pass
	ret=$?
	stop_tcp_server ${SENDER_CTL_HOSTNAME} 1
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
