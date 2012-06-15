gen_ipf_conf() {
	return 1;
}

gen_ipnat_conf() {
	cat 1h/v4/1h_ipnat_parse_100_v4.data
	return 0;
}

gen_ippool_conf() {
	return 1;
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
	dump_ipnat_rules
	ret=$?
	if [[ $ret != 0 ]] ; then
		return $ret
	fi
	active=$(ccat < ${IPF_TMP_DIR}/ipnat.conf.a | wc -l)
	active=$((active))
	if [[ $active != 0 ]] ; then
		echo "-- Not all ipnat rules removed"
		${BIN_IPNAT} -l
		return 1
	fi
	return 0;
}
