gen_ipf_conf() {
	cat <<__EOF__
pass in on ppp0 inet6 from ppp0/peer to ppp0/128
block in on hme0 inet6 from any to hme0/broadcast
pass in on bge0 inet6 from bge0/network to bge0/128
block in on eri0 inet6 from any to eri0/netmasked
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
