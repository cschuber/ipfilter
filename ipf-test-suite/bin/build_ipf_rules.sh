#!/bin/ksh
#
# This script is only run on the SUT
#
. ${IPF_LIB_DIR}/ipf_test_rules.sh

myname=${0%%/*}

#
if [[ -z ${SUT_CTL_IFP_NAME} ]] ; then
	print "| ${myname}: SUT_CTL_IFP_NAME not defined"
	exit 1
fi
if [[ -f ${2}.sh ]] ; then
	. ${2}.sh
else
	p=$(pwd)
	print "| PWD: $p"
	print "| ${myname}: MISSING TEST FILE ${2}.sh"
	exit 1
fi
#

if [[ -z $no_base_ruleset ]] ; then
	cat > ${TEST_IPF_CONF} << __EOF__
#
# Allow all traffic on the control network, without restruition.
#
pass in quick on ${SUT_CTL_IFP_NAME} all
pass out quick on ${SUT_CTL_IFP_NAME} all
#
# Log all traffic on the network 0
#
log in on ${SUT_NET0_IFP_NAME} all
log out on ${SUT_NET0_IFP_NAME} all
__EOF__

	if [[ -n ${SUT_NET1_IFP_NAME} ]] ; then
		cat >> ${TEST_IPF_CONF} << __EOF__
#
# Log all traffic on the network 1
#
log in on ${SUT_NET1_IFP_NAME} all
log out on ${SUT_NET1_IFP_NAME} all
__EOF__
	fi
else
	print > ${TEST_IPF_CONF}
fi
#
gen_ipf_conf >> ${TEST_IPF_CONF}
ret=$?
#
print "================================================================="
print "|                                                               |"
print "| Generated ipf.conf file                                       |"
print "|---------------------------------------------------------------|"
if [[ $ret == 0 ]] ; then
	cat ${TEST_IPF_CONF}
else
	print "| UNUSED ipf.conf"
fi
print "|---------------------------------------------------------------|"
print "================================================================="
if [[ $ret == 0 ]] ; then
	${BIN_IPF} -If ${TEST_IPF_CONF} -s 2>&1
	ret=$?
	if [[ $ret != 0 ]] ; then
		print - "-- ERROR loading ipf conf file ${TEST_IPF_CONT}"
	fi
else
	ret=0
fi
#
exit $ret
