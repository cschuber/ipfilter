gen_ipf_conf() {
	cat <<__EOF__
pass in log proto tcp all
pass in log first proto udp all
pass in log or-block proto tcp from any to any flags S
pass in log body proto icmp all
block return-rst in quick proto tcp from any to any flags S
block return-rst in log quick proto tcp from any to any flags S
block return-icmp in quick proto udp from any to any
block return-icmp(proto-unr) in quick proto udp from 1.1.1.1 to 2.2.2.2
block return-icmp-as-dest in quick proto udp from any to any
block return-icmp-as-dest(port-unr) in quick proto udp from any to any
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
