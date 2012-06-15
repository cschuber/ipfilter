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
	count_ipnat_rules
	active=$?
	if [[ $active = 0 ]] ; then
		echo "-- no ipnat rules loaded prior to flush"
		return 1
	fi
	${BIN_IPNAT} -C
	count_ipnat_rules
	active=$?
	if [[ $active = 0 ]] ; then
		return 0
	fi
	echo "-- ipnat rules remaining after flush"
	return 1;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
