gen_ipf_conf() {
	cat <<__EOF__
pass in inet6 tos {80,0x80} all
pass out inet6 tos {0x80,80} all
block in inet6 ttl {0,1,2,3,4,5,6} all
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
	validate_loaded_ipf_conf
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
