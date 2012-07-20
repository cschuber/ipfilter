no_base_ruleset=1
capture_net0=0
capture_net1=0
capture_ipmon=0
capture_sender=0
capture_receiver=0
preserve_net0=0
preserve_net1=0
preserve_ipmon=0
preserve_sender=0
preserve_receiver=0
dump_stats=0

gen_ipf_conf() {
	return 1;
}

gen_ipnat_conf() {
	cat 1h/v4/1h_ipnat_parse_102_v4.data
	return 0;
}

gen_ippool_conf() {
	cat <<__EOF__
pool nat/tree (number 1;) {;};
pool nat/tree (name a;) {;};
pool nat/dstlist (name a;) {;};
pool nat/dstlist (name ant;) {;};
pool nat/dstlist (name bat;) {;};
pool nat/dstlist (name bee;) {;};
pool nat/dstlist (name cat;) {;};
__EOF__
	return 0;
}

do_test() {
	validate_loaded_ipnat_conf
	return 0
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
