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
map ${SUT_NET0_IFP_NAME} ${SUT_NET0_ADDR_V6} -> ${NET0_FAKE_ADDR_V6}
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	ping_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V6} big pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_srcdst_0 ${SENDER_NET0_ADDR_V6} ${NET0_FAKE_ADDR_V6} frag
	count=$?
	count=$((count))
	if [[ $count -lt 12 ]] ; then
		print - "-- ERROR $count packets when 12 should be seen"
		return 1;
	fi
	print - "-- OK correct packet count ($count/12) seen"
	return 0;
}
