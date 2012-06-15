gen_ipf_conf() {
	cat <<__EOF__
pass out on fxp0 inet6 all set-tag(log=100)
pass out on fxp0 inet6 all set-tag(nat=foo)
pass out on fxp0 inet6 all set-tag(log=100, nat=200)
pass out on fxp0 inet6 all set-tag(log=2147483648, nat=overtherainbowisapotof)
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
