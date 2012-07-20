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
print > ${TEST_IPPOOL_CONF}

if [[ -f $2.sh ]]; then
	. $2.sh
	gen_ippool_conf > ${TEST_IPPOOL_CONF}
	ret=$?
else
	p=$(pwd)
	print "| PWD: $p"
	print "| ${myname}: MISSING TEST FILE: $2.sh"
fi

print "================================================================="
print "|                                                               |"
print "| Generated ippool.conf file                                    |"
print "|---------------------------------------------------------------|"
if [[ $ret = 0 ]]; then
	cat ${TEST_IPPOOL_CONF}
	${BIN_IPPOOL} -f ${TEST_IPPOOL_CONF} 2>&1
	ret=$?
	if [[ $ret != 0 ]] ; then
		print - "-- ERRROR loading ippool conf file ${TEST_IPPOOL_CONF}"
	fi
else
	print "| UNUSED ippool.conf"
	ret=0
fi
print "|---------------------------------------------------------------|"
print "================================================================="
exit $ret
