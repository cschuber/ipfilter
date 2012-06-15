gen_ipf_conf() {
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
map le0 inet6 0/0 -> 0/128
map le0 inet6 1/128 -> 1/128
map le0 inet6 fec0::/1 -> 0/0
map le0 inet6 10:10::/32 -> 1234:5678::1234/96
map le0 inet6 10:10::/32 -> 1234::1234/96
map le0 inet6 10:10::/32 -> 1234:5678:89ab::1234/96
map le0 inet6 10:10::10/0xff -> 1234:5678:89ab::1234/96
map le0 inet6 fec0::/16 -> range 1234::5678-1234::abce
map ppp0 inet6 fec0::/16 -> 0/128 portmap tcp 10000:19999
map ppp0 inet6 fec0::/16 -> 0/128 portmap udp 20000:29999
map ppp0 inet6 fec0::/16 -> 0/128 portmap tcp/udp 30000:39999
map ppp0 inet6 fec0::/16 -> 0/128 portmap tcp auto
map ppp0 inet6 fec0::/16 -> 0/128 portmap udp auto
map ppp0 inet6 fec0::/16 -> 0/128 portmap tcpudp auto
map ppp0 inet6 fec0::/16 -> 0/128 proxy port ftp ftp/6
map ppp0 inet6 fec0::/16 -> 0/128 proxy port 1010 ftp/tcp
map le0 inet6 0/0 -> 0/128 frag
map le0 inet6 fec0::/16 -> range 1234::5678-1234::abce frag
map ppp0 inet6 fec0::/16 -> 0/128 portmap tcp 10000:19999 frag
map ppp0 inet6 fec0::/16 -> 0/128 proxy port ftp ftp/tcp frag
map le0 inet6 0/0 -> 0/128 age 10
map le0 inet6 fec0::/16 -> range 1234::5678-1234::abce age 10/20
map ppp0 inet6 fec0::/16 -> 0/128 portmap tcp 10000:19999 age 30
map le0 inet6 0/0 -> 0/128 frag age 10
map le0 inet6 fec0::/16 -> range 1234::5678-1234::abce frag age 10/20
map ppp0 inet6 fec0::/16 -> 0/128 portmap tcp 10000:19999 frag age 30
map fxp0 inet6 from fec0::/18 to 0/0 port = 21 -> 1234::1234/128 proxy port 21 ftp/tcp
map thisisalonginte inet6 0/0 -> 0/128 mssclamp 1452 tag freddyliveshere
map bar0 inet6 0/0 -> 0/128 icmpidmap icmp 1000:2000
map ppp0,adsl0 inet6 0/0 -> 0/128
map ppp0 inet6 from fec0::/16 to any port = 123 -> 0/128 age 30/1 udp
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
