
gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET0_IFP_NAME} proto udp from any to any port = 5057 keep state
__EOF__
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET1_IFP_NAME} ${SENDER_NET0_ADDR_V4} -> ${NET1_FAKE_ADDR_V4} udp
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	basic_udp_test ${RECEIVER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} \
	    5057 ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_srcdst_1 ${NET1_FAKE_ADDR_V4} ${RECEIVER_NET1_ADDR_V4}
	count=$?
	count=$((count))
	if [[ $count -eq 0 ]] ; then
		print - "-- ERROR no packets seen matching ${NET0_FAKE_ADDR_V4},${SENDER_NET0_ADDR_V4}"
		return 1
	fi
	print - "-- OK $count matching packets seen"
	return 0;
}
