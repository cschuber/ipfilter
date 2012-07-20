capture_net1=0;
preserve_net1=0;

gen_ipf_conf() {
	generate_test_hdr
	cat << __EOF__
block in quick on ${SUT_NET0_IFP_NAME} inet6 proto ipv6-icmp from any to ${SUT_NET0_ADDR_V6}/${NET0_NETMASK_V6}
block out quick on ${SUT_NET0_IFP_NAME} inet6 proto ipv6-icmp from ${SUT_NET0_ADDR_V6}/${NET0_NETMASK_V6} to any
__EOF__
	generate_pass_rules
	return 0;
}

gen_ipnat_conf() {
	return 1;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	ping_test ${SENDER_CTL_HOSTNAME} ${SUT_NET0_ADDR_V6} big block
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_src_0 ${SUT_NET0_ADDR_V6} frag
	count=$?
	if [[ $count != 0 ]] ; then
		print - "-- ERROR $count packets when 0 should be seen"
		return 1;
	fi
	print - "-- OK no packets seen"
	return 0;
}
