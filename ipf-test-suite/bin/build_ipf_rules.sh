#!/bin/ksh
#
# This script is only run on the SUT
#
. ${IPF_LIB_DIR}/ipf_test_rules.sh
. ${IPF_LIB_DIR}/ipf_lib.sh

#
if [[ -z ${SUT_CTL_IFP_NAME} ]] ; then
	echo "SUT_CTL_IFP_NAME not defined"
	exit 1
fi
if [[ -f ${2}.sh ]] ; then
	. ${2}.sh
else
	pwd
	echo "MISSING TEST FILE ${2}.sh"
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
	echo > ${TEST_IPF_CONF}
fi
#
gen_ipf_conf >> ${TEST_IPF_CONF}
#
echo "================================================================="
echo "|                                                               |"
echo "| Generated ipf.conf file                                       |"
echo "|---------------------------------------------------------------|"
cat ${TEST_IPF_CONF}
echo "|---------------------------------------------------------------|"
echo "================================================================="
${BIN_IPF} -If ${TEST_IPF_CONF} -s
#
exit $?
