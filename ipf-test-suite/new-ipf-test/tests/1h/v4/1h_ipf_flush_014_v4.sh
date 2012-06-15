gen_ipf_conf() {
	cat 1h/v4/1h_ipf_parse_014_v4.data
	return 0;
}

gen_ipnat_conf() {
	return 1;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	count_ipf_rules
	active=$?
	if [[ $active = 0 ]] ; then
		echo "-- no rules loaded prior to flush"
		return 1
	fi
	${BIN_IPF} -Fa
	count_ipf_rules
	active=$?
	if [[ $active = 0 ]] ; then
		return 0
	fi
	echo "-- rules remaining after flush"
	return 1;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
