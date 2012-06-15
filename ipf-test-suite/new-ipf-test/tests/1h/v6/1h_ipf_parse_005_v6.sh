gen_ipf_conf() {
	cat <<__EOF__
log in inet6 all
pass in on ed0 inet6 tos 64 from ::1 to ::1
block in log on lo0 inet6 ttl 0 from any to any
pass in quick inet6 ttl 1 from any to any
skip 3 out inet6 from ::1 to any
auth out on foo0 inet6 proto tcp from any to any port = 80
preauth out on foo0 inet6 proto tcp from any to any port = 22
nomatch out on foo0 inet6 proto tcp from any port < 1024 to any
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
