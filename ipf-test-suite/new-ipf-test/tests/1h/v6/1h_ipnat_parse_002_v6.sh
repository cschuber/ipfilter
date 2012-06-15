gen_ipf_conf() {
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
rdr le0 9:8::7:6/128 port 0 -> 1:1:1::1 port 0 tcp
rdr le0 9:8::7:6/128 port 0 -> 1:1:1::1 port 0 255
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 tcp
rdr le0 9:8::7:6/128 -> 1:1:1::1 ip
rdr le0 9:8::7:6/16 -> 1:1:1::1 ip
rdr le0 9:8::7:6/64 -> 1:1:1::1 ip
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 tcp
rdr le0 9:8::7:6/128 port 80 -> 0/0 port 80 tcp
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 udp
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 tcp/udp
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 icmp
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1,1:1:1::2 port 80 tcp
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 tcp round-robin
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1,1:1:1::2 port 80 tcp round-robin
rdr le0 9:8::7:6/128 port 0 -> 1:1:1::1 port 0 ip frag
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 icmp frag
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1,1:1:1::2 port 80 tcpudp frag
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 tcp round-robin frag
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1,1:1:1::2 port 80 tcp round-robin frag
rdr le0 9:8::7:6/128 -> 1:1:1::1 ip frag age 10
rdr le0 9:8::7:6/128 port 0 -> 1:1:1::1 port 0 ip frag age 10/20
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 icmp frag age 10
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1,1:1:1::2 port 80 tcp frag age 20
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 tcp round-robin frag age 30
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1,1:1:1::2 port 80 tcp round-robin frag age 40
rdr le0 9:8::7:6/128 port 0 -> 1:1:1::1 port 0 ip sticky
rdr le0 9:8::7:6/128 port 0 -> 1:1:1::1 port 0 ip frag sticky
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 icmp frag sticky
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1,1:1:1::2 port 80 tcp frag sticky
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 tcp round-robin frag sticky
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1,1:1:1::2 port 80 tcp round-robin frag sticky
rdr le0 9:8::7:6/128 port 0 -> 1:1:1::1 port 0 ip frag age 10 sticky
rdr le0 9:8::7:6/128 port 0 -> 1:1:1::1 port 0 ip frag age 10/20 sticky
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 icmp frag age 10 sticky
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1,1:1:1::2 port 80 tcp frag age 20 sticky
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 tcp round-robin frag age 30 sticky
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1,1:1:1::2 port 80 tcp round-robin frag age 40 sticky
rdr le0 9:8::7:6/128 port 0 -> 1:1:1::1 port 0 ip mssclamp 1000
rdr le0 9:8::7:6/128 port 0 -> 1:1:1::1 port 0 ip sticky mssclamp 1000
rdr le0 9:8::7:6/128 port 0 -> 1:1:1::1 port 0 ip frag sticky mssclamp 1000
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 icmp frag sticky mssclamp 1000
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1,1:1:1::2 port 80 tcp frag sticky mssclamp 1000
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 tcp round-robin frag sticky mssclamp 1000
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1,1:1:1::2 port 80 tcp round-robin frag sticky mssclamp 1000
rdr le0 9:8::7:6/128 port 0 -> 1:1:1::1 port 0 ip frag age 10 sticky mssclamp 1000
rdr le0 9:8::7:6/128 port 0 -> 1:1:1::1 port 0 ip frag age 10/20 sticky mssclamp 1000
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 icmp frag age 10 sticky mssclamp 1000
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1,1:1:1::2 port 80 tcp frag age 20 sticky mssclamp 1000
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 tcp round-robin frag age 30 sticky mssclamp 1000
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1,1:1:1::2 port 80 tcp round-robin frag age 40 sticky mssclamp 1000
rdr le0 9:8::7:6/128 port 0 -> 1:1:1::1 port 0 ip tag nattagcacheline
rdr le0 9:8::7:6/128 port 0 -> 1:1:1::1 port 0 ip mssclamp 1000 tag nattagcacheline
rdr le0 9:8::7:6/128 port 0 -> 1:1:1::1 port 0 ip sticky mssclamp 1000 tag nattagcacheline
rdr le0 9:8::7:6/128 port 0 -> 1:1:1::1 port 0 ip frag sticky mssclamp 1000 tag nattagcacheline
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 icmp frag sticky mssclamp 1000 tag nattagcacheline
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1,1:1:1::2 port 80 tcp frag sticky mssclamp 1000 tag nattagcacheline
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 tcp round-robin frag sticky mssclamp 1000 tag nattagcacheline
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1,1:1:1::2 port 80 tcp round-robin frag sticky mssclamp 1000 tag nattagcacheline
rdr le0 9:8::7:6/128 port 0 -> 1:1:1::1 port 0 ip frag age 10 sticky mssclamp 1000 tag nattagcacheline
rdr le0 9:8::7:6/128 port 0 -> 1:1:1::1 port 0 ip frag age 10/20 sticky mssclamp 1000 tag nattagcacheline
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 icmp frag age 10 sticky mssclamp 1000 tag nattagcacheline
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1,1:1:1::2 port 80 tcp frag age 20 sticky mssclamp 1000 tag nattagcacheline
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1 port 80 tcp round-robin frag age 30 sticky mssclamp 1000 tag nattagcacheline
rdr le0 9:8::7:6/128 port 80 -> 1:1:1::1,1:1:1::2 port 80 tcp round-robin frag age 40 sticky mssclamp 1000 tag nattagcacheline
rdr ge0 9:8::7:6/128 -> 1:1:1::1 proxy port 21 ftp/tcp
rdr ge0 9:8::7:6/128 port 21 -> 1:1:1::1 port 21 tcp proxy ftp
rdr le0 9:8::7:6/128 port 1000-2000 -> 1:1:1::1 port 5555 tcp
rdr le0 9:8::7:6/128 port 1000-2000 -> 1:1:1::1 port = 5555 tcp
rdr le0 0/0 -> test.host.dots
rdr le0 any -> test.host.dots,test.host.dots
rdr adsl0,ppp0 9:8::7:6/128 port 1000-2000 -> 1:1:1::1 port 5555-7777 tcp
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
