no_base_ruleset=1

gen_ipf_conf() {
	cat <<__EOF__
pass in from 10.0.0.0/8 to 10.0.0.0/8 head 100
pass in proto udp from 10.3.1.1 to 10.4.2.2 group 100
pass in proto tcp from 10.1.1.1 to 10.2.2.2 head 200 group 100
pass out from 10.0.0.0/8 to 10.0.0.0/8 head 300
pass out proto udp from 10.3.1.1 to 10.4.2.2 group 300
pass out proto tcp from 10.1.1.1 to 10.2.2.2 head 400 group 300
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
	${BIN_IPFSTAT} -io > ${IPF_TMP_DIR}/ipf.conf.a
	ret=$?
	if [[ $ret != 0 ]] ; then
		return $ret
	fi
	grep ' group ' ${IPF_TMP_DIR}/ipf.conf.a > ${IPF_TMP_DIR}/ipf.conf.b
	count=$(ccat < ${IPF_TMP_DIR}/ipf.conf.b | wc -l)
	count=$((count))
	if [[ $count != 4 ]] ; then
		print - "-- ERROR incorrect group rule count ($count)"
		return 1
	fi
	${BIN_IPF} -rf ${IPF_TMP_DIR}/ipf.conf.b
	ret=$?
	if [[ $ret != 0 ]] ; then
		print - "-- ERROR error removing rules with group"
		return $ret
	fi
	return 0
}

do_tune() {
	return 0;
}

do_verify() {
	${BIN_IPFSTAT} -io > ${IPF_TMP_DIR}/ipf.conf.a
	ret=$?
	if [[ $ret != 0 ]] ; then
		return $ret
	fi
	count=$(ccat < ${IPF_TMP_DIR}/ipf.conf.a | wc -l)
	count=$((count))
	if [[ $count != 2 ]] ; then
		print - "-- ERROR incorrect rule count ($count) after group removal"
		return 1
	fi
	return 0;
}
