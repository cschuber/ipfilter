gen_ipf_conf() {
	return 1;
}

gen_ipnat_conf() {
	cat <<__EOF__
rdr ${SUT_NET0_IFP_NAME} 10.0.0.0/8 port 23 -> 2.2.2.2 port 10023 tcp/udp
rdr ${SUT_NET0_IFP_NAME} 10.0.0.0/8 port 23 -> 2.2.2.2 port 1023 tcp/udp
rdr ${SUT_NET0_IFP_NAME} 10.0.0.0/8 port 23 -> 2.2.2.2 port 123 tcp/udp
rdr ${SUT_NET0_IFP_NAME} 10.0.0.0/8 port 23 -> 2.2.2.2 port 13 tcp/udp
rdr ${SUT_NET0_IFP_NAME} 10.0.0.0/8 port 0 -> 2.2.2.2 port 0 tcp/udp
rdr ${SUT_NET0_IFP_NAME} 10.0.0.0/8 port 23 -> 2.2.2.2 port 10023 tcp
rdr ${SUT_NET0_IFP_NAME} 10.0.0.0/8 port 23 -> 2.2.2.2 port 1023 tcp
rdr ${SUT_NET0_IFP_NAME} 10.0.0.0/8 port 23 -> 2.2.2.2 port 123 tcp
rdr ${SUT_NET0_IFP_NAME} 10.0.0.0/8 port 23 -> 2.2.2.2 port 13 tcp
rdr ${SUT_NET0_IFP_NAME} 10.0.0.0/8 port 0 -> 2.2.2.2 port 0 tcp
rdr ${SUT_NET0_IFP_NAME} 10.0.0.0/8 port 23 -> 2.2.2.2 port 10023 udp
rdr ${SUT_NET0_IFP_NAME} 10.0.0.0/8 port 23 -> 2.2.2.2 port 1023 udp
rdr ${SUT_NET0_IFP_NAME} 10.0.0.0/8 port 23 -> 2.2.2.2 port 123 udp
rdr ${SUT_NET0_IFP_NAME} 10.0.0.0/8 port 23 -> 2.2.2.2 port 13 udp
rdr ${SUT_NET0_IFP_NAME} 10.0.0.0/8 port 0 -> 2.2.2.2 port 0 udp
rdr ${SUT_NET0_IFP_NAME} 10.0.0.0/8 port 0 -> 2.2.2.2 port 0 ip
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	validate_loaded_ipnat_conf
	return $?
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
