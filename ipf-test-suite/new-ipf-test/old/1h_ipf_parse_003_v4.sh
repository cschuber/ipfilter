gen_ipf_conf() {
	cat <<__EOF__
block out proto icmp from 0.0.0.0 to 255.255.255.255
log in all
pass in from 128.16/16 to 129.10.10/24
pass in from 128.0.0.1/24 to 1\
28\
.\
0.0.1/16
pass in from 128.0.0.1/0xffffff00 to 128.0.0.1/0xffff0000
pass in from 128.0.0.1/255.255.255.0 to 128.0.0.1/255.255.0.0
pass in from 128.0.0.1 mask 0xffffff00 to 128.0.0.1 mask 0xffff0000
pass in from 128.0.0.1 mask 255.255.255.0 to 128.0.0.1 mask 255.255.0.0
pass in from localhost to localhost
block in log from 0/0 to 0/0
block in log level auth.info on hme0 all
log level local5.warn out all
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
