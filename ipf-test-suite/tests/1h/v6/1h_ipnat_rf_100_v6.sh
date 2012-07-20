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
	cat 1h/v6/1h_ipnat_parse_100_v6.data
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	dump_ipnat_rules 2>&1
	ret=$?
	if [[ $ret != 0 ]] ; then
		print - "-- ERROR dumping ipnat rules returned an error"
		return $ret
	fi
	${BIN_IPNAT} -rf ${IPF_TMP_DIR}/ipnat.conf.a 2>&1
	ret=$?
	if [[ $ret != 0 ]] ; then
		print - "-- ERROR removing ipnat rules returned an error"
		${BIN_IPNAT} -l 2>&1
		return $ret
	fi
	print - "-- OK ipnat rules removed"
	return 0;
}

do_tune() {
	return 0;
}

do_verify() {
	count_ipnat_rules 2>&1
	active=$?
	if [[ $active != 0 ]] ; then
		print - "-- ERROR $active ipnat rules were not removed"
		${BIN_IPNAT} -l
		return 1
	fi
	return 0;
}
