#!/bin/ksh


gen_ipf_conf() {
	generate_pass_rules
	generate_test_hdr
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
rewrite out on ${SUT_NET1_IFP_NAME} from ${SENDER_NET0_ADDR_V4} to ${RECEIVER_NET1_ADDR_V4} -> src ${NET1_FAKE_ADDR_V4}/32 dst ${RECEIVER_NET1_ADDR_V4_A1};
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	ping_test ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} big pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_srcdst_1 ${NET1_FAKE_ADDR_V4} ${RECEIVER_NET1_ADDR_V4_A1} frag
	count=$?
	if [[ $count != 12 ]] ; then
		print - "-- ERROR packets count ($count) not 12"
		return 1
	fi
	print - "-- OK correct packet count (12) seen"
	return 0;
}
