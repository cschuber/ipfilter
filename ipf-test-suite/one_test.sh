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

trap one_interrupt_test USR1

one_interrupt_test() {
	echo "TEST RUN INTERTUPTED" >&2
	echo "TEST RUN INTERTUPTED"
	. ../vars.sh
	abort_test
}

abort_test() {
	${IPF_VAR_DIR}/bin/log.sh stop ${testprefix}
#	echo "#"
#	date '+# end time %c'
	echo "#"
	reset_ipfilter
	echo "#"
	echo "RESULT FAIL ${TESTNAME} ABORTED"
	echo "#"
	echo '#################################################################'
	exit 1
}

if [[ $# -lt 1 ]] ; then
	echo "No test name supplied [$#][$@]" >&2
	exit 1
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
		. ../vars.sh
	fi
	;;
esac
. ${IPF_VAR_DIR}/lib/ipf_lib.sh

echo '#################################################################'
#echo "#"
#date '+# start time %c'
echo "#"
echo "START ${TESTNAME}"
echo "#"
echo "FULLNAME=${FULLNAME}"
echo "TESTNAME=${TESTNAME}"
echo "#"

if ! reset_ipfilter; then
	echo "ABORT: Enabling ipfilter failed."
	exit 1
fi
cleanup_ipfilter

testprefix=${1%${1#?h}}

${IPF_VAR_DIR}/bin/log.sh start ${testprefix} 2>&1

#
# build test configuration
#
${IPF_BIN_DIR}/build_ippool_conf.sh ${TESTNAME} ${FULLNAME} 2>&1
if [[ $? -ne 0 ]] ; then
	echo 'FAIL Loading ippool configuration'
	abort_test
fi
${IPF_BIN_DIR}/build_ipf_rules.sh ${TESTNAME} ${FULLNAME} 2>&1
if [[ $? -ne 0 ]] ; then
	echo 'FAIL Loading ipf configuration'
	abort_test
fi
${IPF_BIN_DIR}/build_ipnat_rules.sh ${TESTNAME} ${FULLNAME} 2>&1
if [[ $? -ne 0 ]] ; then
	echo 'FAIL Loading ipnat configuration'
	abort_test
fi

#
# run test
#
. ${FULLNAME}.sh
#
#ipf -T ftp_debug=10
netstat -s > ${IPF_TMP_DIR}/netstat.1
do_test
ret=$?
netstat -s > ${IPF_TMP_DIR}/netstat.2
#ipf -T ftp_debug=0
#
${IPF_VAR_DIR}/bin/log.sh stop ${testprefix}
#
do_verify
#
if [[ $ret = 0 ]] ; then
	echo "RESULT PASS ${TESTNAME}"
else
	echo '-----------------------------------------------------------------'
	echo '|'
	echo '| netstat changes'
	echo '|'
	diff -u ${IPF_TMP_DIR}/netstat.1 ${IPF_TMP_DIR}/netstat.2
	echo '|'
	echo '-----------------------------------------------------------------'
	dump_all
	echo '-----------------------------------------------------------------'
	echo "| Preserving log files in ${IPF_LOG_DIR}/${TESTNAME}"
	${IPF_BIN_DIR}/log.sh preserve ${testprefix} \
	    "${IPF_LOG_DIR}/${TESTNAME}"
	echo "RESULT FAIL ${TESTNAME}"
fi
#
#echo '#'
#date '+# end time %c'
echo '#'
echo '#################################################################'
#
exit 0
