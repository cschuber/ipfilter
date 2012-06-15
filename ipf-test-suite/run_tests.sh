#!/bin/ksh
#
. ./vars.sh
. lib/ipf_lib.sh

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
	echo "TESTING INTERRUPTED"
	stop_tests=1
	if [[ $testjob != 0 ]] ; then
		echo "kill -INT ${testjob}"
		kill -USR1 ${testjob}
		wait $testjob
	fi
}

dotest() {
	name=$(basename $1)
	echo "Running $name $counter/$total"
	rsh_sut ${IPF_VAR_DIR}/one_test.sh ${IPF_VAR_DIR}/ $1 > \
	    ${IPF_LOG_DIR}/$$.$name 2>&1 &
	testjob=$!
	wait $testjob
	testjob=0
	cat ${IPF_LOG_DIR}/$$.$name >> ${IPF_LOG_ALL}
	counter=$((counter + 1))
}

runtests() {
	rev=$1
	cat ${IPF_TEST_LIST} | while [[ $stop_tests = 0 ]] && read name; do
		dotest ${name} 
	done
}

counttests() {
	sort -u -o ${IPF_TEST_LIST}.sort ${IPF_TEST_LIST}
	mv ${IPF_TEST_LIST}.sort ${IPF_TEST_LIST}
	total=$(wc -l < ${IPF_TEST_LIST})
	total=$((total + 0))
}

buildtestlist() {
	find . -name "${1}".sh | sed -e 's@\./@@' >> ${IPF_TEST_LIST}
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

echo "LOG FILE ${IPF_LOG_ALL}"

runtests

echo "LOG FILE ${IPF_LOG_ALL}"
${IPF_BIN_DIR}/summary.sh ${IPF_LOG_ALL}

exit 0
