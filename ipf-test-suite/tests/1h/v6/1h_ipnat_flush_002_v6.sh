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
	cat 1h/v6/1h_ipnat_parse_002_v6.data
	return 0;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	count_ipnat_rules 2>&1
	active=$?
	active=$((active))
	if [[ $active = 0 ]] ; then
		print - "-- ERROR no ipnat rules loaded prior to flush"
		return 1
	fi
	${BIN_IPNAT} -C 2>&1
	count_ipnat_rules 2>&1
	active=$?
	active=$((active))
	if [[ $active != 0 ]] ; then
		print - "-- ERROR $active ipnat rules remaining after flush"
		${BIN_IPNAT} -l 2>&1
		return 1;
	fi
	print - "-- OK no ipnat rules remaining"
	return 0
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
