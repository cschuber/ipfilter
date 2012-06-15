gen_ipf_conf() {
	cat <<__EOF__
pass in on lo0 fastroute inet6 from any to any
pass in on lo0 to qe0 inet6 from ::1 to ::1
pass in on le0 to qe0:10:0::0:1 inet6 from ::1 to ::1
pass in on lo0 dup-to qe0 inet6 from ::1 to ::1
pass in on le0 dup-to qe0:10:0::0:1 inet6 from ::1 to ::1
pass in on le0 to hme0:10:1:1::1 dup-to qe0:127:0:0::1 inet6 from ::1 to ::1
block in quick on qe0 to qe1 inet6 from any to any
block in quick to qe1 inet6 from any to any
pass out quick dup-to hme0 inet6 from any to any
pass out quick on hme0 reply-to hme1 inet6 from any to any
pass in on le0 dup-to qe0:127:0:0::1 reply-to hme1:10:10:10::10 inet6 all
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
