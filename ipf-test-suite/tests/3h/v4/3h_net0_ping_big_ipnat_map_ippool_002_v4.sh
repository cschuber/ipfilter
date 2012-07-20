
gen_ipf_conf() {
	generate_pass_rules
	generate_test_hdr
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET1_IFP_NAME} from pool/nattest to any -> ${NET1_FAKE_ADDR_V4}
__EOF__
	return 0;
}

gen_ippool_conf() {
	cat <<__EOF__
pool nat/tree (name nattest;) { ${NET0_NET_V4}.0/${NET0_NETMASK_V4}; };
__EOF__
	return 0;
}

do_test() {
	ping_test ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} big pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_srcdst_1 ${NET1_FAKE_ADDR_V4} ${RECEIVER_NET1_ADDR_V4} frag
	count=$?
	if [[ $count != 12 ]] ; then
		print - "-- ERROR packets count ${count} not 12"
		if [[ $count -ge 0 ]] ; then
			dumpcap_srcdst_0 ${NET1_FAKE_ADDR_V4} \
			    ${SENDER_NET0_ADDR_V4} frag
		fi
		return 1
	fi
	print - "-- OK correct packet count (12) seen"
	return 0;
}
