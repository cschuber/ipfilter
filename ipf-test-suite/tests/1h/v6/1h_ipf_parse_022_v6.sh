gen_ipf_conf() {
	cat <<__EOF__
pass in exp { "ip6.src != 1:1:1::0/96; tcp.dport = 80;" }
pass in exp { "ip6.addr = 1:2:3:4:5:6:7:8,10:20:30:40:50:60:70:80;" }
block out exp { "ip6.dst= 127::/32;" }
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
