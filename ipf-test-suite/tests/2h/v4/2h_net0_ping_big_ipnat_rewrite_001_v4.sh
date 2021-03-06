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
rewrite out on ${SUT_NET0_IFP_NAME} from ${SUT_NET0_ADDR_V4} to ${SENDER_NET0_ADDR_V4} -> src ${NET0_FAKE_ADDR_V4}/32 dst ${SENDER_NET0_ADDR_V4_A1};
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	ping_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V4} big pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_srcdst_0 ${NET0_FAKE_ADDR_V4} ${SENDER_NET0_ADDR_V4_A1} frag
	count=$?
	if [[ $count != 12 ]] ; then
		print - "-- ERROR packets count ($count) not 12"
		return 1
	fi
	print - "-- OK correct packet count (12) seen"
	return 0;
}
