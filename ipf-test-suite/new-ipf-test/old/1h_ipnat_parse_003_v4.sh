gen_ipf_conf() {
	return 1;
}

gen_ipnat_conf() {
	cat <<__EOF__
map ${SUT_NET0_IFP_NAME} 10.0.0.0/8 -> 10.10.0.0/16 portmap tcp/udp 10000:30000
map ${SUT_NET0_IFP_NAME} 10.0.0.0/8 -> 10.10.0.0/16 portmap tcp/udp 1000:3000
map ${SUT_NET0_IFP_NAME} 10.0.0.0/8 -> 10.10.0.0/16 portmap tcp/udp 1:3
map ${SUT_NET0_IFP_NAME} 10.0.0.0/8 -> 10.10.0.0/16 portmap tcp/udp 1:1
map ${SUT_NET0_IFP_NAME} 10.0.0.0/8 -> 10.10.0.0/16 portmap tcp 10000:30000
map ${SUT_NET0_IFP_NAME} 10.0.0.0/8 -> 10.10.0.0/16 portmap tcp 1000:3000
map ${SUT_NET0_IFP_NAME} 10.0.0.0/8 -> 10.10.0.0/16 portmap tcp 1:3
map ${SUT_NET0_IFP_NAME} 10.0.0.0/8 -> 10.10.0.0/16 portmap tcp 1:1
map ${SUT_NET0_IFP_NAME} 10.0.0.0/8 -> 10.10.0.0/16 portmap udp 10000:30000
map ${SUT_NET0_IFP_NAME} 10.0.0.0/8 -> 10.10.0.0/16 portmap udp 1000:3000
map ${SUT_NET0_IFP_NAME} 10.0.0.0/8 -> 10.10.0.0/16 portmap udp 1:3
map ${SUT_NET0_IFP_NAME} 10.0.0.0/8 -> 10.10.0.0/16 portmap udp 1:1
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
