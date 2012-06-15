gen_ipf_conf() {
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map le0 inet6 from 9:8:7::6/128 port > 1024 to any -> 1:1:1::1 portmap 10000:20000 tcp
map le0 inet6 from 9:8:7::6/128 port > 1024 to ! 1:2::3:4 -> 1:1:1::1 portmap 10000:20000 tcp
rdr le0 inet6 from any to 9:8:7::6/128 port = 0 -> 1:1:1::1 port 0 tcp
rdr le0 inet6 from any to 9:8:7::6/128 port = 0 -> 1:1:1::1 port 0 ip
rdr le0 inet6 ! from 1:2::3:4 to 9:8:7::6 port = 8888 -> 1:1:1::1 port 888 tcp
rdr le0 inet6 from any to 9:8:7::6/128 port = 8888 -> 1:1:1::1 port 888 ip
rdr le0 inet6 from any to 9:8:7::6/128 port = 8888 -> 1:1:1::1 port 888 tcp
rdr le0 inet6 from any to 9:8:7::6/128 port = 8888 -> 1:1:1::1 port 888 udp
rdr le0 inet6 from any to 9:8:7::6/128 port = 8888 -> 1:1:1::1 port 888 tcp/udp
rdr le0 inet6 from any to 9:8:7::6/128 -> 1:1:1::1 port 888 icmp
rdr le0 inet6 from any to 9:8:7::6/128 port = 8888 -> 1:1:1::1,1:1:1::2 port 888 tcp
rdr le0 inet6 from any to 9:8:7::6/128 port = 8888 -> 1:1:1::1 port 888 tcp round-robin
rdr le0 inet6 from any to 9:8:7::6/128 port = 8888 -> 1:1:1::1,1:1:1::2 port 888 tcp round-robin
rdr le0 inet6 from any to 9:8:7::6/128 -> 1:1:1::1 port 0 ip frag
rdr le0 inet6 from any to 9:8:7::6/128 port = 8888 -> 1:1:1::1 port 888 icmp frag
rdr le0 inet6 from any to 9:8:7::6/128 port = 8888 -> 1:1:1::1,1:1:1::2 port 888 tcp frag
rdr le0 inet6 from any to 9:8:7::6/128 port = 8888 -> 1:1:1::1 port 888 tcp round-robin frag
rdr le0 inet6 from any to 9:8:7::6/128 port = 8888 -> 1:1:1::1,1:1:1::2 port 888 tcp round-robin frag
rdr le0 inet6 from any to 9:8:7::6/128 -> 1:1:1::1 port 0 ip frag age 10
rdr le0 inet6 from any to 9:8:7::6/128 port = 0 -> 1:1:1::1 port 0 ip frag age 10/20
rdr le0 inet6 from any to 9:8:7::6/128 port = 8888 -> 1:1:1::1 port 888 icmp frag age 10
rdr le0 inet6 from any to 9:8:7::6/128 port = 8888 -> 1:1:1::1,1:1:1::2 port 888 tcp frag age 20
rdr le0 inet6 from any to 9:8:7::6/128 port = 8888 -> 1:1:1::1 port 888 tcp round-robin frag age 30
rdr le0 inet6 from any to 9:8:7::6/128 port = 8888 -> 1:1:1::1,1:1:1::2 port 888 tcp round-robin frag age 40
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
