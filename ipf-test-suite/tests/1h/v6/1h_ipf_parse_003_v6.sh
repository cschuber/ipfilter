gen_ipf_conf() {
	cat <<__EOF__
log in inet6 all
pass in inet6 from 128:16::/64 to 129:10:10::/96
pass in inet6 from 128:0:0::1/96 to 1\
28\
:\
0:0::1/64
pass in inet6 from 128:1:0::1/96 to 128:1:0::1/64
pass in inet6 from 128:0:1::1/96 to 128:0:1::1/64
pass in inet6 from 128:2:0::1/96 to 128:2:2::1/64
pass in inet6 from 128:0:2::1/96 to 128:2:2::1/64
pass in inet6 from ::1 to ::1
block in log inet6 from 0::0/0 to 0/0
block in log level auth.info on hme0 inet6 all
log level local5.warn out inet6 all
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
