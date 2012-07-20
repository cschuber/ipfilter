#!/bin/ksh
#
# This script is only run on the SUT
#
myname=$(basename $0)

if [[ -z ${SUT_CTL_IFP_NAME} ]] ; then
	print "| ${myname}: SUT_CTL_IFP_NAME not defined"
	exit 1
fi
#
print > ${TEST_IPNAT_CONF}

if [[ -f $2.sh ]]; then
	. $2.sh
	gen_ipnat_conf > ${TEST_IPNAT_CONF}
	ret=$?
else
	p=$(pwd)
	echo "PWD: $p"
	echo "${myname}: MISSING TEST FILE: $2.sh"
fi
print "================================================================="
print "|                                                               |"
print "| Generated ipnat.conf file                                     |"
print "|---------------------------------------------------------------|"
if [[ $ret = 0 ]]; then
	cat ${TEST_IPNAT_CONF}
	${BIN_IPNAT} -f ${TEST_IPNAT_CONF} 2>&1
	ret=$?
	if [[ $ret != 0 ]] ; then
		print - "-- ERROR loading ipnat conf file ${TEST_IPNAT_CONF}"
	fi
else
	print "| UNUSED ipnat.conf"
	ret=0
fi
print "|---------------------------------------------------------------|"
print "================================================================="
exit $ret
