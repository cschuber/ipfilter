gen_ipf_conf() {
	return 1;
}

gen_ipnat_conf() {
	cat <<__EOF__
rdr ${SUT_NET0_IFP_NAME} 10.10.10.10/32 -> 1.1.1.1
rdr ${SUT_NET0_IFP_NAME} 10.10.10.0/24 -> 1.1.1.1
rdr ${SUT_NET0_IFP_NAME} 10.10.0.0/16 -> 1.1.1.1
rdr ${SUT_NET0_IFP_NAME} 10.0.0.0/8 -> 1.1.1.1
rdr ${SUT_NET0_IFP_NAME} 0/32 -> 0/32
rdr ${SUT_NET0_IFP_NAME} 0/0 -> 0/0
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
