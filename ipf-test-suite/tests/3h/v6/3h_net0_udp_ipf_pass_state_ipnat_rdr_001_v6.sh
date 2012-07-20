
gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET0_IFP_NAME} proto udp from any to any port = 5050 keep state
__EOF__
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
rdr ${SUT_NET0_IFP_NAME} ${NET0_FAKE_ADDR_V6} -> ${RECEIVER_NET1_ADDR_V6} udp
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
        basic_udp_test ${RECEIVER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V6} \
            5050 ${SENDER_CTL_HOSTNAME} ${NET0_FAKE_ADDR_V6} pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
