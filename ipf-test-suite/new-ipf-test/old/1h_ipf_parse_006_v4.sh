gen_ipf_conf() {
	cat <<__EOF__
pass in proto tcp from any to any flags S keep state
pass out proto tcp from any to any flags S/SA keep state(strict)
pass in proto udp from 127.1.0.1 to 192.1.1.1 keep state(loose)
pass in proto udp from 127.0.1.1 to 192.0.1.1 keep state(no-icmp-err)
pass in proto tcp from 127.1.0.1 to 192.0.0.1 keep state(limit 101)
pass in from 127.0.0.1 to 192.168.0.0.1 keep state(age 600)
pass in proto udp from 127.0.0.1 to 192.168.0.0.1 keep state(strict, limit 10, no-icmp-err, age 300)
pass in from 127.0.0.1 to 192.168.0.0.1 keep state(age 10/20)
pass in from any to any port = 2049 keep frag
pass in from any to any port = 2049 keep frag(strict)
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
