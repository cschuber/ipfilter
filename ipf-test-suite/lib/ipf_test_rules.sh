#!/bin/ksh
#
# This script outputs to stdout the ipf rules that are to be tested
#
generate_inet6_rules() {
	cat << __EOF__
#
# IPv6 rules required to allow hosts to talk
#
pass in quick inet6 proto ipv6-icmp all icmp-type neighborsolicit
pass in quick inet6 proto ipv6-icmp all icmp-type neighadvert
pass out quick inet6 proto ipv6-icmp all icmp-type neighborsolicit
pass out quick inet6 proto ipv6-icmp all icmp-type neighadvert
__EOF__
}
#
generate_block_rules() {
	generate_inet6_rules
	#
	# This set of rules is used before pass-quick-less rules and after
	# pass-quick-with rules to ensure that packets passed do in fact
	# get passed because they match rules.
	#
	cat << __EOF__
#
# Catch all rules to force test
#
block in log on ${SUT_NET0_IFP_NAME} all
block out log on ${SUT_NET0_IFP_NAME} all
__EOF__
	if [[ -n ${SUT_NET1_IFP_NAME} ]] ; then
		cat << __EOF__
block in log on ${SUT_NET1_IFP_NAME} all
block out log on ${SUT_NET1_IFP_NAME} all
__EOF__
	fi
}

generate_pass_rules() {
	generate_inet6_rules
	#
	# This set of rules is used before block-quick-less rules and after
	# block-quick-with rules to ensure that packets blocked do in fact
	# get blocked because they match rules.
	#
	cat << __EOF__
#
# Catch all rules to force test
#
pass in on ${SUT_NET0_IFP_NAME} all
pass out on ${SUT_NET0_IFP_NAME} all
__EOF__
	if [[ -n ${SUT_NET1_IFP_NAME} ]] ; then
		cat << __EOF__
pass in on ${SUT_NET1_IFP_NAME} all
pass out on ${SUT_NET1_IFP_NAME} all
__EOF__
	fi
}

generate_test_hdr() {
	cat << __EOF__
#
# Rule(s) being tested follow
#
__EOF__
}
