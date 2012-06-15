gen_ipf_conf() {
	generate_pass_rules
	generate_test_hdr
	cat << __EOF__
block in on ${SUT_NET1_IFP_NAME} all
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
	ping_test ${SENDER_CTL_HOSTNAME} ${RECEIVER_NET1_ADDR_V6} small block
	ret=$?
	echo "PING result=$ret"
	return $ret;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
