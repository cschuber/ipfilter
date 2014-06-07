gen_ipf_conf() {
	cat 1h/v4/1h_ipf_parse_001_v4.data
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
	if [[ $active = -1 ]] ; then
		print - "-- ERROR cannot count ipf rules"
		return 1
	fi
	if [[ $active = 0 ]] ; then
		print - "-- ERROR no rules loaded prior to switch"
		return 1
	fi
	${BIN_IPF} -IFa
	${BIN_IPF} -s
	count_ipf_rules
	active=$?
	if [[ $active != 0 ]] ; then
		print - "-- ERROR rules present after switch"
		return 1
	fi
	return 0;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
