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
map ${SUT_NET0_IFP_NAME} inet6 from pool/nattest to any -> ${NET0_FAKE_ADDR_V6}
__EOF__
	return 0;
}

gen_ippool_conf() {
	cat <<__EOF__
pool nat/tree (name nattest;) { ${NET0_NET_V6}::0/${NET0_NETMASK_V6}; };
__EOF__
	return 0;
}

do_test() {
	ping_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V6} big pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_srcdst_0 ${NET0_FAKE_ADDR_V6} ${SENDER_NET0_ADDR_V6} frag
	count=$?
	count=$((count))
	if [[ $count != 12 ]] ; then
		print - "-- ERROR packets count ($count) not 12"
		return 1
	fi
	print - "-- OK correct packet count ($count/12) seen"
	return 0;
}
