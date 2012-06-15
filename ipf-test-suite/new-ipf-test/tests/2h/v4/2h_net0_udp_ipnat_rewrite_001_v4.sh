#!/bin/ksh

gen_ipf_conf() {
	generate_pass_rules
	generate_test_hdr
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
rewrite out on ${SUT_NET0_IFP_NAME} from ${SUT_NET0_ADDR_V4} to ${SENDER_NET0_ADDR_V4} -> src ${NET0_FAKE_ADDR_V4}/32 dst ${SENDER_NET0_ADDR_V4_A1};
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	start_udp_server ${SENDER_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V4_A1} 5051
	sleep 1
	udp_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V4} 5051 pass
	ret=$?
	stop_udp_server ${SENDER_CTL_HOSTNAME} 1
	ret=$((ret + $?))
	return $ret;
}

do_tune() {
	return 0;
}

do_verify() {
	${IPF_BIN_DIR}/log.sh verify_srcdst_0 \
	    ${NET0_FAKE_ADDR_V4} ${SENDER_NET0_ADDR_V4_A1}
	if [[ $? -eq 0 ]] ; then
		echo "No packets ${NET0_FAKE_ADDR_V4},${SENDER_NET0_ADDR_V4_A1}"
		return 1
	fi
	return 0;
}
