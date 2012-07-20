
gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET0_IFP_NAME} proto tcp from ${SENDER_NET0_ADDR_V4} to any flags S keep state
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
	start_tcp_server ${RECEIVER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} 5051 A
	start_tcp_server ${RECEIVER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4_A1} 5052 B
	start_tcp_server ${RECEIVER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4_A2} 5053 C
	tcp_test ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4} 5051 pass
	tcp_test ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4_A1} 5052 pass
	tcp_test ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V4_A2} 5053 pass
	${BIN_IPFSTAT} -Rslm 'tcp.dport != 5053;' > ${IPF_TMP_DIR}/ipfstat.out
	print - "|--- ipfstat output start"
	cat ${IPF_TMP_DIR}/ipfstat.out
	print - "|--- ipfstat output end"
	n=$(egrep '^4:6' ${IPF_TMP_DIR}/ipfstat.out|wc -l)
	n=$((n))
	print - "|--- n=$n"
	stop_tcp_server ${RECEIVER_CTL_HOSTNAME} 1 A
	stop_tcp_server ${RECEIVER_CTL_HOSTNAME} 1 B
	stop_tcp_server ${RECEIVER_CTL_HOSTNAME} 1 C
	if [[ $n -ne 2 ]] ; then
		print - "-- ERROR n($n) != 2"
		return 1;
	fi
	print - "-- OK n = 2"
	return 0
}

do_tune() {
	return 0;
}

do_verify() {
	return 2;
}
