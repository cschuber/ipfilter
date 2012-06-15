gen_ipf_conf() {
	cat <<__EOF__
100 pass in inet6 all
200 pass in inet6 proto tcp all
110 pass in inet6 proto udp all
110 pass in inet6 from ::1 to any
pass in inet6 all
pass in inet6 from ::1 to any
@0 100 pass in inet6 from ::1 to any
@1 pass in inet6 from any to ::1
@0 pass in inet6 from 1::1:1:1 to any
@1 110 pass in inet6 from 2:2::2:2 to any
@2 pass in inet6 from 3:3:3::3 to any
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
