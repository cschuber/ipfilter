gen_ipf_conf() {
	cat <<__EOF__
log in proto tcp from any port > 0 to any
log in proto tcp from any to any port > 0
pass in proto 6 from any port != 0 to any port 0 >< 65535
pass in proto 17 from localhost port > 32000 to localhost port < 29000
block in proto udp from any port != \ntp to any port < echo
block in proto tcp from any port = smtp to any port > 25
pass in proto tcp/udp from any port 1 >< 3 to any port 1 <> 3
pass in proto tcp/udp from any port 2:2 to any port 10:20
pass in log first quick proto tcp from any port > 1023 to any port = 1723 flags S keep state
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