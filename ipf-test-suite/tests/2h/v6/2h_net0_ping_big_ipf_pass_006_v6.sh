capture_net1=0;
preserve_net1=0;

gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET0_IFP_NAME} inet6 proto ipv6-icmp from any to any icmp-type echo
pass in on ${SUT_NET0_IFP_NAME} inet6 proto ipv6-icmp from any to any with frag-body
pass out on ${SUT_NET0_IFP_NAME} inet6 proto ipv6-icmp from any to any icmp-type echorep
pass out on ${SUT_NET0_IFP_NAME} inet6 proto ipv6-icmp from any to any with frag-body
__EOF__
	return 0;
}

gen_ipnat_conf() {
	return 1;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	ping_test ${SENDER_CTL_HOSTNAME} ${SUT_NET0_ADDR_V6} big pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_srcdst_0 ${SENDER_NET0_ADDR_V6} ${SUT_NET0_ADDR_V6} frag
	count=$?
	if [[ $count != 12 ]] ; then
		print - "-- ERROR $count packets when 12 should be seen"
		return 1;
	fi
	print - "-- OK correct packet count (12) seen"
	return 0;
}
