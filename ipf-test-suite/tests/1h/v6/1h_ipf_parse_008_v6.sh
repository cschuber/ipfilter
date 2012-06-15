gen_ipf_conf() {
	cat <<__EOF__
block in inet6 proto ipv6-icmp from any to any icmp-type unreach code 1
pass in inet6 proto ipv6-icmp all icmp-type unreach code cutoff-preced
pass in inet6 proto ipv6-icmp all icmp-type unreach code filter-prohib
pass in inet6 proto ipv6-icmp all icmp-type unreach code isolate
pass in inet6 proto ipv6-icmp all icmp-type unreach code needfrag
pass in inet6 proto ipv6-icmp all icmp-type unreach code net-prohib
pass in inet6 proto ipv6-icmp all icmp-type unreach code net-tos
pass in inet6 proto ipv6-icmp all icmp-type unreach code host-preced
pass in inet6 proto ipv6-icmp all icmp-type unreach code host-prohib
pass in inet6 proto ipv6-icmp all icmp-type unreach code host-tos
pass in inet6 proto ipv6-icmp all icmp-type unreach code host-unk
pass in inet6 proto ipv6-icmp all icmp-type unreach code host-unr
pass in inet6 proto ipv6-icmp all icmp-type unreach code {net-unk,net-unr}
pass in inet6 proto ipv6-icmp all icmp-type unreach code port-unr
pass in inet6 proto ipv6-icmp all icmp-type unreach code proto-unr
pass in inet6 proto ipv6-icmp all icmp-type unreach code srcfail
pass in inet6 proto ipv6-icmp all icmp-type {echo,echorep}
pass in inet6 proto ipv6-icmp all icmp-type inforeq
pass in inet6 proto ipv6-icmp all icmp-type inforep
pass in inet6 proto ipv6-icmp all icmp-type paramprob
pass in inet6 proto ipv6-icmp all icmp-type redir
pass in inet6 proto ipv6-icmp all icmp-type unreach
pass in inet6 proto ipv6-icmp all icmp-type routerad
pass in inet6 proto ipv6-icmp all icmp-type routersol
pass in inet6 proto ipv6-icmp all icmp-type timex
pass in inet6 proto ipv6-icmp all icmp-type 254
pass in inet6 proto ipv6-icmp all icmp-type 253 code 254
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
