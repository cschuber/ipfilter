gen_ipf_conf() {
	cat <<__EOF__
pass in on ed0 inet6 proto tcp from ::1 to ::1 port = 23 flags S/SA
block in on lo0 inet6 proto tcp from any to any flags A
pass in on lo0 inet6 proto tcp from any to any flags /SAP
block in on lo0 inet6 proto tcp from any to any flags 0x80/A
pass in on lo0 inet6 proto tcp from any to any flags S/18
block in on lo0 inet6 proto tcp from any to any flags 2/18
pass in on lo0 inet6 proto tcp from any to any flags 2
block in on lo0 inet6 proto tcp from any to any flags S
pass in on lo0 inet6 proto tcp from any to any flags 2/SAF
block in on lo0 inet6 proto tcp from any to any flags /16
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
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
