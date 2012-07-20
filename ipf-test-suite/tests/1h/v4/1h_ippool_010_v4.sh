gen_ipf_conf() {
	return 1;
}

gen_ipnat_conf() {
	return 1;
}

gen_ippool_conf() {
	cat <<__EOF__
pool nat/tree (name testnata;) {;};
pool nat/hash (name testnatb;) {;};
pool nat/dstlist (name testnatc;) {;};
__EOF__
	return 0;
}

do_test() {
	validate_loaded_ippool_conf
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
