gen_ipf_conf() {
	cat <<__EOF__
pass in inet6 from ::1 to ::1 with short,frags
block in inet6 from any to any with v6hdrs
pass in inet6 from ::1 to ::1 and not frag
block in inet6 from any to any with not v6hdrs
pass in inet6 from ::1 to ::1 with frags,frag-body
pass in inet6 proto tcp all flags S with not oow keep state
block in inet6 proto tcp all with oow
pass in inet6 proto tcp all flags S with not bad,bad-src,bad-nat
block in inet6 proto tcp all flags S with bad,not bad-src,not bad-nat
pass in quick inet6 all with not short
block in quick inet6 all with not nat
pass in quick inet6 all with not frag-body
block in quick inet6 all with not lowttl
pass in inet6 all with mbcast,not bcast,multicast,not state,not v6hdrs
block in inet6 all with not mbcast,bcast,not multicast,state
pass in inet6 from any to any with v6hdr dstopts, esp, hopopts, ipv6, none, routing, frag, mobility
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



