
gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET0_IFP_NAME} proto udp from any to any port = 5059 keep state
__EOF__
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET1_IFP_NAME} ${SENDER_NET0_ADDR_V6} -> ${NET1_FAKE_ADDR_V6} portmap udp auto
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
        basic_udp_test ${RECEIVER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V6} \
            5059 ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V6} pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_srcdst_1 ${NET1_FAKE_ADDR_V6} ${RECEIVER_NET1_ADDR_V6}
	if [[ $? -eq 0 ]] ; then
		echo "No packets ${NET1_FAKE_ADDR_V6},${RECEIVER_NET1_ADDR_V6}"
		return 1
	fi
	return 0;
}
