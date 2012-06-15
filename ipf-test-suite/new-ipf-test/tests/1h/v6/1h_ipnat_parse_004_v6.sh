gen_ipf_conf() {
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map-block le0 10::/96 -> 203:1:1::/96
map-block le0 10::/96 -> 203:1:1::/96 ports 0
map-block le0 10::/96 -> 203:1:1::/96 ports 256
map-block le0 10::/96 -> 203:1:1::/96 ports auto
map-block le0 10::/16 -> 203:1:1::/96 ports auto
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
