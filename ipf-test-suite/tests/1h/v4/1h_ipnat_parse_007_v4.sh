gen_ipf_conf() {
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
#
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	validate_loaded_ipf_conf
	return 0
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
