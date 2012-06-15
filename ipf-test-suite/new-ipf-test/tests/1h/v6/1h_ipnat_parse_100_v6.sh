gen_ipf_conf() {
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
rewrite in on bge0 from 1:1:1::1 to 2:2::2:2 -> src 3::3:3:3 dst 4:4:4:4::;
rewrite out on bge0 from 1:1:1::1/128 to 2:2::2:2 -> src 3.3.3.0/24 dst 4:4:4:4::;
rewrite in on bge0 from 1:1:1::1/128 to 2:2::2:2/128 -> src 3.3.3.0/24 dst 4.4.4.0/24;
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
