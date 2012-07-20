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
rewrite out on ${SUT_NET0_IFP_NAME} from ${SUT_NET0_ADDR_V6} to ${SENDER_NET0_ADDR_V6} -> src ${NET0_FAKE_ADDR_V6}/${NET0_FAKE_NETMASK_V6} dst ${SENDER_NET0_ADDR_V6_A1};
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	ping_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V6} small pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_srcdst_0 ${NET0_FAKE_ADDR_V6} ${SENDER_NET0_ADDR_V6_A1} echo
	if [[ $? -eq 0 ]] ; then
		echo "-- ERROR No packets ${NET0_FAKE_ADDR_V6},${SENDER_NET0_ADDR_V6_A1}"
		return 1
	fi
	return 0;
}
