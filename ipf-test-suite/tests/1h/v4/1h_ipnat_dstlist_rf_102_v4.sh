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
pool nat/tree (name a;) {;};
pool nat/tree (number 1;) {;};
pool nat/dstlist (name a;) {;};
pool nat/dstlist (name bee;) {;};
pool nat/dstlist (name cat;) {;};
pool nat/dstlist (name bat;) {;};
pool nat/dstlist (name ant;) {;};
__EOF__
	return 0;
}

do_test() {
	dump_ipnat_rules
	ret=$?
	if [[ $ret != 0 ]] ; then
		return $ret
	fi
	${BIN_IPNAT} -rf ${IPF_TMP_DIR}/ipnat.conf.a
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_ipnat_rulecount_0
	return $?;
}
