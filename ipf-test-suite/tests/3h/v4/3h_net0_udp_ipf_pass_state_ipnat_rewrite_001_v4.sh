
gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat <<__EOF__
pass in on ${SUT_NET0_IFP_NAME} proto udp from any to any keep state
__EOF__
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
	basic_udp_test ${RECEIVER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4_A1} \
	    5051 ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_srcdst_1 ${NET1_FAKE_ADDR_V4} ${RECEIVER_NET1_ADDR_V4_A1} 5051
	if [[ $? -eq 0 ]] ; then
		print - "-- ERROR no packets ${NET1_FAKE_ADDR_V4},${SENDER_NET0_ADDR_V4_A1}"
		return 1
	fi
	print - "-- OK"
	return 0;
}
