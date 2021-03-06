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

gen_ipf_conf() {
	cat 1h/v4/1h_ipf_parse_022_v4.data
	return 0;
}

gen_ipnat_conf() {
	return 1;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	${BIN_IPFSTAT} -io > ${IPF_TMP_DIR}/ipf.conf.a
	ret=$?
	if [[ $ret != 0 ]] ; then
		print - "|  error dumping active ipf.conf rules"
		return $ret
	fi
	${BIN_IPF} -rf ${IPF_TMP_DIR}/ipf.conf.a 2>&1
	ret=$?
	if [[ $ret != 0 ]] ; then
		print - "-- ERROR removing ${IPF_TMP_DIR}/ipf.conf.a rules"
		return $ret
	fi
	print - "-- OK rules removed"
	return 0;
}

do_tune() {
	return 0;
}

do_verify() {
	verify_ipf_rulecount_0
	return $?;
}
