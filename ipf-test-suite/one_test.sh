#!/bin/ksh
#
# This script is always run on SUT - $SUT_CTL_HOSTNAME
#
case $1 in
/*/)
	cd "$1"
	shift
	;;
*)
	;;
esac

FULLNAME=${1%.sh}
TESTNAME=${FULLNAME#*h/v?/}

no_base_ruleset=0
capture_net0=1
capture_net1=1
capture_ipmon=1
capture_sender=1
capture_receiver=1
preserve_net0=1
preserve_net1=1
preserve_ipmon=1
preserve_sender=1
preserve_receiver=1
dump_stats=1
export no_base_ruleset dump_stats
export capture_net0 capture_net1 capture_ipmon
export capture_sender capture_receiver
export preserve_net0 preserve_net1 preserve_ipmon
export preserve_sender preserve_receiver

trap one_interrupt_test USR1

one_interrupt_test() {
	print "TEST RUN INTERTUPTED" >&2
	print "TEST RUN INTERTUPTED"
	. ../config.sh
	abort_test
}

abort_test() {
	logging_stop ${testprefix}
	print "#"
	reset_ipfilter
	print "#"
	date '+# end time %c'
	print "#"
	print "RESULT FAIL ${TESTNAME} ABORTED"
	print "#"
	print '#################################################################'
	return 1
}

if [[ $# -lt 1 ]] ; then
	print "No test name supplied [$#][$@]" >&2
	return 1
fi

if [[ $TESTNAME = $FULLNAME ]] ; then
	group=${FULLNAME%${FULLNAME##?h}}
	proto=${FULLNAME##*_}
	FULLNAME="$group/$proto/$TESTNAME"
fi

indir=$(pwd)
case $indir in
*tests)
	;;
*)
	cd tests
	if [[ -z ${IPT_VAR_DIR} ]]; then
		. ../config.sh
	fi
	;;
esac
. ${IPF_VAR_DIR}/lib/ipf_lib.sh
. ${IPF_VAR_DIR}/bin/log.sh

print '#################################################################'
print "#"
date '+# start time %c'
print "#"
print "START ${TESTNAME}"
print "#"
print "FULLNAME=${FULLNAME}"
print "TESTNAME=${TESTNAME}"
print "#"

if ! reset_ipfilter; then
	print "ABORT: Enabling ipfilter failed."
	return 1
fi
cleanup_ipfilter

testprefix=${1%${1#?h}}
#
# run test
#
. ${FULLNAME}.sh

logging_start ${testprefix} 2>&1

#
# build test configuration
#
${IPF_BIN_DIR}/build_ippool_conf.sh ${TESTNAME} ${FULLNAME} 2>&1
if [[ $? -ne 0 ]] ; then
	print 'FAIL Loading ippool configuration'
	abort_test
fi
${IPF_BIN_DIR}/build_ipf_rules.sh ${TESTNAME} ${FULLNAME} 2>&1
if [[ $? -ne 0 ]] ; then
	print 'FAIL Loading ipf configuration'
	abort_test
fi
${IPF_BIN_DIR}/build_ipnat_rules.sh ${TESTNAME} ${FULLNAME} 2>&1
if [[ $? -ne 0 ]] ; then
	print 'FAIL Loading ipnat configuration'
	abort_test
fi
#
netstat -s > ${IPF_TMP_DIR}/netstat.1
${BIN_IPFSTAT} > ${IPF_TMP_DIR}/ipfstat.1
${BIN_IPFSTAT} -s >> ${IPF_TMP_DIR}/ipfstat.1
${BIN_IPNAT} -s >> ${IPF_TMP_DIR}/ipfstat.1
do_test 2>&1
ret=$?
netstat -s > ${IPF_TMP_DIR}/netstat.2
${BIN_IPFSTAT} > ${IPF_TMP_DIR}/ipfstat.2
${BIN_IPFSTAT} -s >> ${IPF_TMP_DIR}/ipfstat.2
${BIN_IPNAT} -s >> ${IPF_TMP_DIR}/ipfstat.2
#
logging_stop ${testprefix}
#
if [[ $ret -eq 0 ]] ; then
	do_verify
	ret=$?
	if [[ $ret -eq 2 ]] ; then
		print -- "-- OK no verify present"
		ret=0
	fi
else
	print "|--- test failed for ${TESTNAME}, verify not performed"
fi
#
if [[ $ret = 0 ]] ; then
	print "RESULT PASS ${TESTNAME}"
else
	print - '-----------------------------------------------------------------'
	if [[ $dump_stats -eq 1 ]]  then
		print '|'
		print '| netstat changes'
		print '|'
		diff -u ${IPF_TMP_DIR}/netstat.1 ${IPF_TMP_DIR}/netstat.2
		print '|'
		print '| ipfstat changes'
		print '|'
		diff -u ${IPF_TMP_DIR}/ipfstat.1 ${IPF_TMP_DIR}/ipfstat.2
		print '|'
		print - '-----------------------------------------------------------------'
		dump_all
		print - '-----------------------------------------------------------------'
	else
		print "| dumping statistical changes disabled"
	fi
	print "| Preserving log files in ${IPF_LOG_DIR}/${TESTNAME}"
	logging_preserve ${testprefix} "${IPF_LOG_DIR}/${TESTNAME}"
	print "RESULT FAIL ${TESTNAME}"
fi
#
print "#"
date '+# end time %c'
print '#'
print '#################################################################'
#
return 0
