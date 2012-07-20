gen_ipf_conf() {
	return 1;
}

gen_ipnat_conf() {
	return 1;
}

gen_ippool_conf() {
	cat <<__EOF__
pool ipf/tree (name testipfa;) { !1::0/16; 1:1::0/32; !1:1:1::0/48; };
pool ipf/hash (name testipfb;) { 2::0/16; 2:2::0/32; 2:2:2::0/48; };
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
