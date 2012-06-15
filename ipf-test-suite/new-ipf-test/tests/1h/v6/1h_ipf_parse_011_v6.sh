gen_ipf_conf() {
	cat <<__EOF__
pass in on ed0 inet6 proto tcp from ::1 to ::1 port = telnet keep state
block in log first on lo0 inet6 proto tcp/udp from any to any port = echo keep state
pass in inet6 proto udp from ::1 to ::1 port = 20499 keep frag
pass in inet6 proto udp from ::1 to ::1 port = 2049 keep frag(strict)
pass in inet6 proto udp from ::1 to ::1 port = 53 keep state keep frags
pass in on ed0 out-via vx0 inet6 proto udp from any to any keep state
pass out on ppp0 in-via le0 inet6 proto tcp from any to any keep state
pass in on ed0,vx0 out-via vx0,ed0 inet6 proto udp from any to any keep state
pass in inet6 proto tcp from any port gt 1024 to ::1 port eq 1024 keep state
pass in inet6 proto tcp all flags S keep state(strict,newisn,no-icmp-err,limit 101,age 600)
pass in inet6 proto tcp all flags S keep state(loose,newisn,no-icmp-err,limit 101,age 600)
pass in inet6 proto udp all keep state(age 10/20,sync)
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
