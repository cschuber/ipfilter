gen_ipf_conf() {
	cat <<__EOF__
log in inet6 proto tcp all
pass in inet6 proto 6 from any to any
pass in inet6 proto udp from ::1 to ::1
block in inet6 proto ipv6 from any to any
block in inet6 proto 17 from any to any
block in inet6 proto 250 from any to any
pass in inet6 proto tcp/udp from any to any
block in inet6 proto tcp-udp from any to any
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
