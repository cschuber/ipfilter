#!/bin/ksh

capture_net1=0;
preserve_net1=0;

gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass out on ${SUT_NET0_IFP_NAME} inet6 proto tcp from ${SUT_NET0_ADDR_V6} to any port = 5051 flags S keep state
pass out on ${SUT_NET0_IFP_NAME} inet6 proto tcp from ${SUT_NET0_ADDR_V6_A1} to any port = 5051 flags S keep state
pass out on ${SUT_NET0_IFP_NAME} inet6 proto tcp from ${SUT_NET0_ADDR_V6_A2} to any port = 5051 flags S keep state
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
	start_tcp_server ${SENDER_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V6} 5051 A
	start_tcp_server ${SENDER_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V6_A1} 5051 B
	start_tcp_server ${SENDER_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V6_A2} 5051 C
	tcp_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V6} 5051 pass \
	    ${SUT_NET0_ADDR_V6}
	tcp_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V6_A1} 5051 pass \
	    ${SUT_NET0_ADDR_V6}
	tcp_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V6_A2} 5051 pass \
	    ${SUT_NET0_ADDR_V6}
	echo "ipfstat -Rslm 'ip6.src = ${SUT_NET0_ADDR_V6};'"
	ipfstat -Rslm "ip6.src = ${SUT_NET0_ADDR_V6};" > \
	    ${IPF_TMP_DIR}/ipfstat.out
	echo "-- ipfstat output start"
	cat ${IPF_TMP_DIR}/ipfstat.out
	echo "-- ipfstat output end"
	n=$(egrep '^6:6' ${IPF_TMP_DIR}/ipfstat.out|wc -l)
	n=$((n))
	echo "-- n=$n"
	stop_tcp_server ${SENDER_CTL_HOSTNAME} 1 A
	stop_tcp_server ${SENDER_CTL_HOSTNAME} 1 B
	stop_tcp_server ${SENDER_CTL_HOSTNAME} 1 C
	if [[ $n = 3 ]] ; then
		return 0
	fi
	echo "-- ERROR n != 3"
	return 1;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
