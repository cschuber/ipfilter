no_base_ruleset=1

gen_ipf_conf() {
	cat <<__EOF__
pass in all
pass in proto udp from 10.3.1.1 to 10.4.2.2 head 100
pass in proto tcp from 10.1.1.1 to 10.2.2.2 group 200
pass out all
pass out proto udp from 10.3.1.1 to 10.4.2.2 head 300
pass out proto tcp from 10.1.1.1 to 10.2.2.2 group 400
__EOF__
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
	if [[ $active != 6 ]] ; then
		print - "-- ERROR  incorrect rule count prior to flush"
		return 1
	fi
	${BIN_IPF} -Fo
	count_ipf_rules
	active=$?
	if [[ $active = 3 ]] ; then
		return 0
	fi
	print - "-- ERROR  incorrect rule count after flush"
	return 1;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
