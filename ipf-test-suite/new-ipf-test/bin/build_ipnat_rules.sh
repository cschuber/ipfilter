#!/bin/ksh
#
# This script is only run on the SUT
#
if [[ -z ${SUT_CTL_IFP_NAME} ]] ; then
	echo "SUT_CTL_IFP_NAME not defined"
	exit 1
fi
#
echo > ${TEST_IPNAT_CONF}

if [[ -f $2.sh ]]; then
	. $2.sh
	gen_ipnat_conf > ${TEST_IPNAT_CONF}
	ret=$?
else
	echo "MISSING TEST FILE: $2.sh"
fi

echo "================================================================="
echo "|                                                               |"
echo "| Generated ipnat.conf file                                     |"
echo "|---------------------------------------------------------------|"
if [[ $ret = 0 ]]; then
	cat ${TEST_IPNAT_CONF}
	${BIN_IPNAT} -f ${TEST_IPNAT_CONF} 2>&1
	ret=$?
else
	echo "UNUSED ipnat.conf"
	ret=0
fi
echo "|---------------------------------------------------------------|"
echo "================================================================="
exit $ret
