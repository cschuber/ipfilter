#!/bin/ksh

capture_net1=0;
preserve_net1=0;

gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass out on ${SUT_NET0_IFP_NAME} proto tcp from ${SUT_NET0_ADDR_V4} to any port = 5051 flags S keep state
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
	start_tcp_server ${SENDER_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V4} 5051 A
	start_tcp_server ${SENDER_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V4_A1} 5051 B
	start_tcp_server ${SENDER_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V4_A2} 5051 C
	tcp_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V4} 5051 pass
	tcp_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V4_A1} 5051 pass
	tcp_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V4_A2} 5051 pass
	print - "|--- ipfstat -Rslm 'ip.dst = ${SENDER_NET0_ADDR_V4_A1};'"
	ipfstat -Rsl
	ipfstat -Rslm "ip.dst = ${SENDER_NET0_ADDR_V4_A1};" > \
	    ${IPF_TMP_DIR}/ipfstat.out
	print - "|--- ipfstat output start"
	cat ${IPF_TMP_DIR}/ipfstat.out
	print - "|--- ipfstat output end"
	n=$(egrep '^4:6' ${IPF_TMP_DIR}/ipfstat.out|wc -l)
	n=$((n))
	print - "|--- n=$n"
	stop_tcp_server ${SENDER_CTL_HOSTNAME} 1 A
	stop_tcp_server ${SENDER_CTL_HOSTNAME} 1 B
	stop_tcp_server ${SENDER_CTL_HOSTNAME} 1 C
	if [[ $n = 1 ]] ; then
		return 0
	fi
	print - "|--- n != 1"
	return 1;
}

do_tune() {
	return 0;
}

do_verify() {
	return 2;
}
