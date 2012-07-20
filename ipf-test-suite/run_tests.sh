#!/bin/ksh
#
. ./vars.sh
. ./config.sh
. lib/ipf_lib.sh

${BIN_IPF} -V >/dev/null 2>&1
if [[ $? -ne 0 ]] ; then
	print "ABORT: Cannot query IP Filter in the kernel"
	exit 1
fi
trap interrupt_testing INT HUP

IPF_TEST_LIST=${IPF_TMP_DIR}/test_list.txt
IPF_LOG_ALL=${IPF_LOG_DIR}/$$.log
mkdir -p ${IPF_LOG_DIR}
> ${IPF_LOG_ALL}
> ${IPF_TEST_LIST}

stop_tests=0
counter=1
testjob=0
total=0
RUNHOST=$(uname -n)
export RUNHOST

interrupt_testing() {
	print "TESTING INTERRUPTED"
	stop_tests=1
	if [[ $testjob != 0 ]] ; then
		print "kill -INT ${testjob}"
		kill -USR1 ${testjob}
		wait $testjob
	fi
}

dotest() {
	name=${1##*/}
	print -n "Running $name $counter/$total"
	rsh_sut ${IPF_VAR_DIR}/one_test.sh ${IPF_VAR_DIR}/ $1 > \
	    ${IPF_LOG_DIR}/$$.$name 2>&1 &
	testjob=$!
	wait $testjob
	testjob=0
	cat ${IPF_LOG_DIR}/$$.$name >> ${IPF_LOG_ALL}
	res=$(awk ' /^RESULT/ { print $2; } ' ${IPF_LOG_DIR}/$$.$name)
	print " $res"
	counter=$((counter + 1))
	return 0
}

runtests() {
	rev=$1
	for name in $(cat ${IPF_TEST_LIST}); do
		dotest ${name}
		if [[ $stop_tests -eq 1 ]] ; then
			return
		fi
	done
}

counttests() {
	sort -u -o ${IPF_TEST_LIST}.sort ${IPF_TEST_LIST}
	mv ${IPF_TEST_LIST}.sort ${IPF_TEST_LIST}
	total=$(wc -l < ${IPF_TEST_LIST})
	total=$((total + 0))
}

buildtestlist() {
	name=$(print "$1" | sed -e 's/__/_\*_/g')
	find . -name "${name}".sh | sed -e 's@\./@@' >> ${IPF_TEST_LIST}
}

cd tests

while [[ $# -gt 0 ]] ; do
	case $1 in
	./*|/*)
		cat $1 >> ${IPF_TEST_LIST}
		;;
	?hv?)
		v=${1#?h}
		h=${1%${v}}
		buildtestlist "${h}*${v}"
		;;
	?h*v?)
		buildtestlist "${1}"
		;;
	*v?)
		buildtestlist "*_${1}"
		;;
	?h*)
		buildtestlist "${1}_*"
		;;
	all)
		buildtestlist "*"
		;;
	*)
		buildtestlist "*_${1}_*"
		;;
	esac
	shift
done

counttests

print "LOG FILE ${IPF_LOG_ALL}"

runtests

${IPF_BIN_DIR}/summary.sh ${IPF_LOG_ALL}
print "LOG FILE ${IPF_LOG_ALL}"

exit 0
