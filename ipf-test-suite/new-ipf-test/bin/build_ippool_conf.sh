#!/bin/ksh
#
# This script is only run on the SUT
#
if [[ -z ${SUT_CTL_IFP_NAME} ]] ; then
	echo "SUT_CTL_IFP_NAME not defined"
	exit 1
fi
#
echo > ${TEST_IPPOOL_CONF}

if [[ -f $2.sh ]]; then
	. $2.sh
	gen_ippool_conf > ${TEST_IPPOOL_CONF}
	ret=$?
else
	echo "MISSING TEST FILE: $2.sh"
fi

echo "================================================================="
echo "|                                                               |"
echo "| Generated ippool.conf file                                    |"
echo "|---------------------------------------------------------------|"
if [[ $ret = 0 ]]; then
	cat ${TEST_IPPOOL_CONF}
	${BIN_IPPOOL} -f ${TEST_IPPOOL_CONF}
	ret=$?
else
	echo "UNUSED ippool.conf"
	ret=0
fi
echo "|---------------------------------------------------------------|"
echo "================================================================="
exit $ret
