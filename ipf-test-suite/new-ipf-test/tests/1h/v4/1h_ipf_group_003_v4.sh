gen_ipf_conf() {
	cat <<__EOF__
pass in proto udp from 10.3.1.1 to 10.4.2.2 group 100
pass in proto tcp from 10.1.1.1 to 10.2.2.2 group 100 head 200
pass out proto udp from 10.3.1.1 to 10.4.2.2 group 300
pass out proto tcp from 10.1.1.1 to 10.2.2.2 group 300 head 400
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
	count=$(ccat < ${IPF_TMP_DIR}/ipf.conf.a | wc -l)
	count=$((count))
	if [[ $count != 4 ]] ; then
		echo "-- incorrect rule count ($count)"
		return 1
	fi
	return 0
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
