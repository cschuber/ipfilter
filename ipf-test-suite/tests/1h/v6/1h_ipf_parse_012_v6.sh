gen_ipf_conf() {
	cat <<__EOF__
pass in inet6 from 1:1::1:1/128 to 2:2::2:2/128
pass in inet6 from {2:2::2:2/24,3::3:3:3/128} to 4:4:4:4::/128
pass in inet6 from {2:2::2:2/24,3::3:3:3/128} to {::5:5:5:5/128,6:6:6::6/128}
pass in inet6 from {2:2::2:2/24,3::3:3:3/128} to {::5:5:5:5/128,6:6:6::6/128} port = {22,25}
pass in inet6 proto tcp from {2:2::2:2/24,3::3:3:3/128} port = {53,9} to {::5:5:5:5/128,6:6:6::6/128}
pass in inet6 proto udp from {2:2::2:2/24,3::3:3:3/128} to {::5:5:5:5/128,6:6:6::6/128} port = {53,9}
pass in inet6 from 10:10:10::10 to 11:11:11::11
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
