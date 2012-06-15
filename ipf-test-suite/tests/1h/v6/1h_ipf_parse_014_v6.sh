gen_ipf_conf() {
	cat <<__EOF__
block in on eri0 inet6 all head 1
pass in on eri0 inet6 proto icmp all group 1
pass out on ed0 inet6 all head 1000000
block out on ed0 inet6 proto udp all group 1000000
block in on vm0 inet6 proto tcp/udp all head 101
pass in inet6 from 1:1::1:1 to 2:2:2::2 group 101
pass in inet6 proto tcp from 1:0::0:1 to 2:0::0:2 group 101
pass in inet6 proto udp from 2:0::0:2 to 3:0::0:3 group 101
block in on vm0 inet6 proto tcp/udp all head vm0-group
pass in inet6 from 1:1::1:1 to 2:2:2::2 group vm0-group
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
