gen_ipf_conf() {
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
bimap le0 0/0 -> 0/128
bimap le0 1::/128 -> 1::/128
bimap le0 128::/1 -> 0/0
bimap le0 10::/8 -> 1:2:3::/96
bimap le0 10::5:6/96 -> 1:2:3::4/96
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
