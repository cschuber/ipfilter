
gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET0_IFP_NAME} inet6 proto tcp from any to any port = 5057 flags S keep state
__EOF__
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET1_IFP_NAME} ${SENDER_NET0_ADDR_V6} -> ${NET1_FAKE_ADDR_V6} tcp
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	start_tcp_server ${RECEIVER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V6} 5057
	sleep 3
	ret=0
	tcp_test ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V6} 5057 pass
	ret=$?
	stop_tcp_server ${RECEIVER_CTL_HOSTNAME} 1
	x=$?
	ret=$((ret + x))
	return $ret;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_srcdst_1 ${NET1_FAKE_ADDR_V6} ${RECEIVER_NET1_ADDR_V6}
	if [[ $? -eq 0 ]] ; then
		echo "No packets ${NET0_FAKE_ADDR_V6},${SENDER_NET0_ADDR_V6}"
		return 1
	fi
	return 0;
}
