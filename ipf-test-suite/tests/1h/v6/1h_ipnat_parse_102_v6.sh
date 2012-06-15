gen_ipf_conf() {
	return 0;
}

gen_ipnat_conf() {
	cat <<__EOF__
rewrite in on bge0 proto tcp from any to any -> src 0/0 dst dstlist/a;
rewrite in on bge0 proto tcp from 1:1:1::1 to any -> src 0/0 dst dstlist/bee;
rewrite in on bge0 proto tcp from 1:1:1::1 to 2:2::2:2 -> src 0/0 dst dstlist/cat;
rewrite in on bge0 proto tcp from pool/a to 2:2::2:2 -> src 0/0 dst dstlist/bat;
rewrite in on bge0 proto tcp from pool/a to pool/1 -> src 0/0 dst dstlist/ant;
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
