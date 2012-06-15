#!/bin/ksh

gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET0_IFP_NAME} proto tcp from any to any port = ftp flags S keep state
__EOF__
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET1_IFP_NAME} ${SUT_NET0_ADDR_V6} -> 0/0 proxy port 21 ftp/tcp
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	ftp_test ${SENDER_CTL_HOSTNAME} ${SUT_NET0_ADDR_V6} ${FTP_PATH} pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
