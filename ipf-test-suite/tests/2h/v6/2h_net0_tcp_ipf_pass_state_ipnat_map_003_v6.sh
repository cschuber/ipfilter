#!/bin/ksh
# ni7
capture_net1=0;
preserve_net1=0;

gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass out on ${SUT_NET0_IFP_NAME} inet6 proto tcp from any to any port = 5050 flags S keep state
__EOF__
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET0_IFP_NAME} ${SUT_NET0_ADDR_V6} -> ${NET0_FAKE_ADDR_V6} portmap tcp auto
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	start_tcp_server ${SENDER_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V6} 5050
	sleep 3
	tcp_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V6} 5050 pass
	ret=$?
	stop_tcp_server ${SENDER_CTL_HOSTNAME} 1
	ret=$((ret + $?))
	return $ret;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_srcdst_0 ${NET0_FAKE_ADDR_V6} ${SENDER_NET0_ADDR_V6}
	if [[ $? -eq 0 ]] ; then
		echo "-- ERROR No packets ${NET0_FAKE_ADDR_V6},${SENDER_NET0_ADDR_V6}"
		return 1
	fi
	return 0;
}
