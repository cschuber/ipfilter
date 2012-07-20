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
rdr ${SUT_NET0_IFP_NAME} inet6 ${NET0_FAKE_ADDR_V6} -> ${SUT_NET0_ADDR_V6} ipv6-icmp
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	ping_test ${SENDER_CTL_HOSTNAME} ${NET0_FAKE_ADDR_V6} small pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
