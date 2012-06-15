gen_ipf_conf() {
	cat <<__EOF__
pass in proto icmp all
pass out proto tcp all
block in proto udp all
block out proto 255 all
pass in proto tcp from 1.2.3.0/24 to 5.6.0.0/16
pass out proto icmp from 9.10.11.12/32 to 13.0.0.0/8
block in proto icmp from 127.0.0.0/20 to 223.255.254.0/23
block out proto icmp from 0.0.0.0 to 255.255.255.255
pass in proto tcp from 1.2.3.4 to 5.6.7.8
pass out proto icmp from 9.10.11.12 to 13.14.15.16
block in proto icmp from 127.0.0.1 to 223.255.255.255
block out proto icmp from 0.0.0.0 to 255.255.255.255
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
	return $?
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
