gen_ipf_conf() {
	cat <<__EOF__
pass in inet6 from port = 10101
pass out inet6 from any to port != 22
block in inet6 from port 20:21
block out inet6 from any to port 10 <> 100
pass out inet6 from any to port = {3,5,7,9}
block in inet6 from port = {20,25}
pass in inet6 from any port = {11:12, 21:22} to any port = {1:2, 4:5, 8:9}
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
