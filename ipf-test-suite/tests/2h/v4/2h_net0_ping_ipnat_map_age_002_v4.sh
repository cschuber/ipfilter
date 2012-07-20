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
map ${SUT_NET0_IFP_NAME} ${SUT_NET0_ADDR_V4} -> ${NET0_FAKE_ADDR_V4} age 60/60
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	ping_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V4} small pass
	ret=$?
	if [[ $ret != 0 ]] ; then
		print - "-- ERROR ($ret) returned from ping_test"
		return $ret
	fi
	return 0;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_srcdst_0 ${NET0_FAKE_ADDR_V4} ${SENDER_NET0_ADDR_V4} echo
	count=$?
	count=$((count))
	if [[ $count != 6 ]] ; then
		print - "-- ERROR packet count ($count) != 6"
		return 1;
	fi
	print - "-- OK packet count ($count) correct"
	return 0;
}
