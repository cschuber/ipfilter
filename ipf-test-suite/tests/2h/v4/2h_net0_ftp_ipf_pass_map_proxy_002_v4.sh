#!/bin/ksh

gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass out on ${SUT_NET0_IFP_NAME} proto tcp from any to any port = ftp flags S keep state
__EOF__
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET0_IFP_NAME} 0/0 -> 0/0 proxy port ftp ftp/tcp
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	ftp_test ${SUT_CTL_HOSTNAME} ${SENDER_NET0_ADDR_V4} ${FTP_PATH} pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
