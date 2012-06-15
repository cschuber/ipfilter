gen_ipf_conf() {
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map foo0 from any port = 1 to any port != 0 -> 0/128 udp
map foo0 from any port eq 1 to any port ne 0 -> 0/128 udp
map foo0 from any port < 1 to any port > 0 -> 0/128 tcp
map foo0 from any port lt 1 to any port gt 0 -> 0/128 tcp
map foo0 from any port <= 1 to any port >= 0 -> 0/128 tcp/udp
map foo0 from any port le 1 to any port ge 0 -> 0/128 tcp/udp
map foo0 from any port 1 >< 20 to any port 20 <> 40 -> 0/128 tcp/udp
map foo0 from any port 10:20 to any port 30:40 -> 0/128 tcp/udp
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
