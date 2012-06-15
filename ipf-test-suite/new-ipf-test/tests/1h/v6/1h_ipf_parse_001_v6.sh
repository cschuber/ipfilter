gen_ipf_conf() {
	cat <<__EOF__
pass in inet6 all
block out inet6 \
all
log in inet6 all
log body in inet6 all
pass in inet6 from !any to any pps 10
pass in on ed0 inet6 from ::1 to ::1
pass in on ed0,vx0 inet6 from ::1 to ::1
block in log first on lo0 inet6 from any to any
pass in log body or-block quick inet6 from any to any
block in inet6 from any to !any
block return-rst in quick on le0 inet6 proto tcp from any to any
block return-icmp in on qe0 inet6 from any to any
block return-icmp(1) in on qe0 inet6 from any to any
block return-icmp-as-dest in on le0 inet6 from any to any
block return-icmp-as-dest(port-unr) in on qe0 inet6 from any to any
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
