gen_ipf_conf() {
	return 1;
}

gen_ipnat_conf() {
	return 1;
}

gen_ippool_conf() {
	cat <<__EOF__
pool ipf/dstlist (name testipfc;) { 1:1:1::1; 2:2::2:2; 3::3:3:3;};
pool ipf/dstlist (name testipfd; policy round-robin;) { 4:4:4::4; 5:5:5::5; };
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
