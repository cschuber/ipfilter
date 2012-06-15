gen_ipf_conf() {
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map zx0 10:1:1::1/128 -> 10:2::2:2/128 purge
map zx0 10:1:1::1/128 -> 10:2::2:2/128 tcp purge
map zx0 10:1:1::1/128 -> 10:2::2:2/128 mssclamp 1000 purge
map zx0 10:1:1::1/128 -> 10:2::2:2/128 portmap tcp/udp 10000:11000 purge
map zx0 10:1:1::1/128 -> 10:2::2:2/128 portmap tcp/udp 10000:11000 sequential purge
map zx0 10:1:1::1/128 -> 10:2::2:2/128 portmap tcp/udp 10000:11000 sequential purge
__EOF__
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	validate_loaded_ipf_conf
	return 0
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
