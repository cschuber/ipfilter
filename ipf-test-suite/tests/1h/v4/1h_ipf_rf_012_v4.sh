no_base_ruleset=1

gen_ipf_conf() {
	cat 1h/v4/1h_ipf_parse_012_v4.data
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
		echo "-- error dumping active ipf.conf rules"
		return $ret
	fi
	${BIN_IPF} -rf ${IPF_TMP_DIR}/ipf.conf.a
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	count_ipf_rules
	if [[ $? != 0 ]] ; then
		echo "-- Not all rules removed"
		${BIN_IPFSTAT} -io
		return 1
	fi
	return 0;
}
