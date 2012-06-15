gen_ipf_conf() {
	cat <<__EOF__
pass in from 127.0.0.1 to 127.0.0.1 with opt sec
pass in from 127.0.0.1 to 127.0.0.1 with opt lsrr not opt sec
block in from 127.0.0.1 to 127.0.0.1 with not opt sec-class topsecret
block in from 127.0.0.1 to 127.0.0.1 with not opt sec-class topsecret,secret
pass in from 1.1.1.1 to 2.2.2.2 with opt sec-class topsecret,confid not opt sec-class unclass
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
	validate_loaded_ipf_conf
	return $?
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
