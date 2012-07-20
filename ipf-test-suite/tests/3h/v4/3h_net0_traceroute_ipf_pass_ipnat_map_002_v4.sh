#!/bin/ksh

gen_ipf_conf() {
	generate_block_rules
	generate_test_hdr
	cat << __EOF__
pass in on ${SUT_NET0_IFP_NAME} proto udp from any to ${RECEIVER_NET1_ADDR_V4} port > 32768
pass out on ${SUT_NET1_IFP_NAME} proto udp from any to ${RECEIVER_NET1_ADDR_V4} port > 32768
pass out on ${SUT_NET0_IFP_NAME} proto icmp from any to ${SENDER_NET0_ADDR_V4} icmp-type timex
pass in on ${SUT_NET1_IFP_NAME} proto icmp from any to ${SENDER_NET0_ADDR_V4} icmp-type timex
pass out on ${SUT_NET0_IFP_NAME} proto icmp from any to ${SENDER_NET0_ADDR_V4} icmp-type unreach
pass in on ${SUT_NET1_IFP_NAME} proto icmp from any to ${SENDER_NET0_ADDR_V4} icmp-type unreach
__EOF__
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET1_IFP_NAME} ${SENDER_NET0_ADDR_V4} -> ${NET1_FAKE_ADDR_V4}
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	traceroute_test ${SENDER_CTL_HOSTNAME} ${SENDER_NET0_IFP_NAME} \
	    ${SENDER_NET0_ADDR_V4} ${RECEIVER_NET1_ADDR_V4} pass
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
