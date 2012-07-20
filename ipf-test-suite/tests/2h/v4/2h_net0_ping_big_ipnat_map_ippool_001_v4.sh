#!/bin/ksh

capture_net1=0;
preserve_net1=0;

gen_ipf_conf() {
	generate_pass_rules
	generate_test_hdr
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET0_IFP_NAME} from pool/nattest to any -> ${NET0_FAKE_ADDR_V4}
__EOF__
	return 0;
}

gen_ippool_conf() {
	cat <<__EOF__
pool nat/tree (name nattest;) { ${SUT_NET0_ADDR_V4}; };
__EOF__
	return 0;
}

do_test() {
	ping_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V4} big pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_srcdst_0 ${NET0_FAKE_ADDR_V4} ${SENDER_NET0_ADDR_V4} frag
	count=$?
	count=$((count + 0))
	if [[ $count != 12 ]] ; then
		print - "-- ERROR packet count for ${NET0_FAKE_ADDR_V4},${SENDER_NET0_ADDR_V4} is $count, not 12"
${IPF_BIN_DIR}/dumpcap.sh ${LOG0_FILE} 2>&1 | egrep "${NET0_FAKE_ADDR_V4}.*>.*${SENDER_NET0_ADDR_V4}.*icmp|${SENDER_NET0_ADDR_V4}.*>.*${NET0_FAKE_ADDR_V4}.*ICMP"
		return 1
	fi
	print - "-- OK correct packet count (12) seen"
	return 0;
}
