gen_ipf_conf() {
	cat <<__EOF__
pass in proto tcp from 1.2.3.4 port > 1 to 5.6.7.8 port < 2
pass out proto udp from 9.10.11.12 port >= 3 to 13.14.15.16 port <= 512
block in proto tcp from 127.0.0.1 port = 512 to 223.255.255.255 port = 1024
block out proto udp from 0.0.0.0 port != 2048 to 255.255.255.255 port 100:200
pass in proto icmp from 17.18.19.20 to 21.22.23.24 icmp-type echo
pass in proto icmp from 25.26.27.28 to 29.30.31.32 icmp-type unreach code proto-unr
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
