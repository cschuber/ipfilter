gen_ipf_conf() {
	cat <<__EOF__
0 block out inet6 all
100 pass in inet6 all
10101 pass out inet6 proto tcp all
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
