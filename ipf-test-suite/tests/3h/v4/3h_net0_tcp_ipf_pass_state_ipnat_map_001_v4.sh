#!/bin/ksh
# ni7
gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET0_IFP_NAME} proto tcp from any to any port = 5057 flags S keep state
__EOF__
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET1_IFP_NAME} ${SENDER_NET0_ADDR_V4} -> ${NET1_FAKE_ADDR_V4} tcp
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	start_tcp_server ${RECEIVER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} 5057
	sleep 3
	tcp_test ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} 5057 pass
	ret=$?
	ret=$((ret))
	stop_tcp_server ${RECEIVER_CTL_HOSTNAME} 1
	ret=$((ret + $?))
	return $ret;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_srcdst_1 ${NET1_FAKE_ADDR_V4} ${RECEIVER_NET1_ADDR_V4}
	count=$?
	count=$((count))
	if [[ $count -eq 0 ]] ; then
		print - "-- EROR no packets found matching ${NET1_FAKE_ADDR_V4},${SENDER_NET0_ADDR_V4}"
		return 1
	fi
	print - "-- OK $count packets seen"
	return 0;
}
