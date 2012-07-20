#!/bin/ksh

reset_ipfilter() {
	if ${BIN_IPF} -D; then
		if ${BIN_IPF} -V; then
			if ${BIN_IPF} -E; then
				${BIN_IPF} -V
				return 0;
			fi
		fi
	fi
	return 1;
}

cleanup_ipfilter() {
	/bin/rm -f ${IPF_TMP_DIR}/*.pid
	/bin/rm -f ${IPF_TMP_DIR}/*.out
	/bin/rm -f ${IPF_TMP_DIR}/*.conf
	/bin/rm -f ${IPF_TMP_DIR}/*.conf.?
}

load_config() {
	if ${BIN_IPPOOL} -f ${TEST_IPPOOL_CONF} 2>&1; then
		if ${BIN_IPF} -f ${TEST_IPF_CONF} 2>&1; then
			if ${BIN_IPNAT} -f ${TEST_IPNAT_CONF} 2>&1; then
				return 0;
			else
				print "FAIL error loading ipnat ${TEST_IPNAT_CONF}"
				return 1;
			fi
		else
			print "FAIL error loading ipf ${TEST_IPF_CONF}"
			return 1;
		fi
	else
		print "FAIL error loading ippool ${TEST_IPPOOL_CONF}"
		return 1;
	fi
}

clear_config() {
	${BIN_IPF} -Fa 2>&1
	${BIN_IPNAT} -FC 2>&1
	${BIN_POOL} -F 2>&1
	return 0;
}

generate_empty_ipnat_conf() {
	> ${IPF_TMP_DIR}/${TEST_IPNAT_CONF}
}

generate_empty_ippool_conf() {
	> ${IPF_TMP_DIR}/${TEST_IPPOOL_CONF}
}

dump_rules() {
	print "|--- DUMP v4 rules (in)"
	${BIN_IPFSTAT} -Rih 2>&1
	print "|---"
	print "|--- DUMP v4 rules (out)"
	${BIN_IPFSTAT} -Roh 2>&1
	print "|---"
	print "|--- DUMP v6 rules (in)"
	${BIN_IPFSTAT} -R6ih 2>&1
	print "|---"
	print "|--- DUMP v6 rules (out)"
	${BIN_IPFSTAT} -R6oh 2>&1
	print "|---"
	print "|--- DUMP groups"
	${BIN_IPFSTAT} -g 2>&1
	print "|---"
	return 0;
}

dump_state() {
	print "|--- DUMP state"
	${BIN_IPFSTAT} -slvR 2>&1
	print "|---"
	return 0;
}

dump_frag() {
	print "|--- DUMP frag"
	${BIN_IPFSTAT} -f 2>&1
	print "|---"
	return 0;
}

dump_nat() {
	print "|--- DUMP nat"
	${BIN_IPNAT} -lvdR 2>&1
	print "|---"
	return 0;
}

dump_pool() {
	print "|--- DUMP pool"
	${BIN_IPPOOL} -lv 2>&1
	print "|---"
	return 0;
}

dump_all() {
	print "|--- DUMP ALL"
	dump_pool
	dump_rules
	dump_state
	dump_frag
	dump_nat
}

dump_ipnat_rules() {
	${BIN_IPNAT} -l > ${IPF_TMP_DIR}/ipnat.conf.b
	ret=$?
	if [[ $ret != 0 ]] ; then
		print - "-- ERROR dumping ipnat rules ($ret)"
		return 1
	fi
	egrep '^rdr|^map|^bimap|^rewrite|^divert' ${IPF_TMP_DIR}/ipnat.conf.b >\
	    ${IPF_TMP_DIR}/ipnat.conf.a
	return 0
}

validate_loaded_ippool_conf() {
	${BIN_IPPOOL} -l > ${IPF_TMP_DIR}/ippool.conf.a
	${BIN_IPPOOL} -f ${TEST_IPPOOL_CONF} -nv > ${IPF_TMP_DIR}/ippool.conf.b
	cmp ${IPF_TMP_DIR}/ippool.conf.a ${IPF_TMP_DIR}/ippool.conf.b
	ret=$?
	if [[ $ret != 0 ]] ; then
		print "| ippool.conf.a (ippool -l)"
		ccat < ${IPF_TMP_DIR}/ippool.conf.a
		print "| ippool.conf.b (ippool -f -nv)"
		ccat < ${IPF_TMP_DIR}/ippool.conf.b
	fi
	return $ret
}

validate_loaded_ipf_conf() {
	${BIN_IPFSTAT} -vio | \
		sed -e '/^#/d' -e 's/(\!)//g' > ${IPF_TMP_DIR}/ipf.conf.b
	${BIN_IPFSTAT} -6vio | grep inet6 | \
		sed -e '/^#/d' -e 's/(\!)//g' >> ${IPF_TMP_DIR}/ipf.conf.b
	sort -u ${IPF_TMP_DIR}/ipf.conf.b -o ${IPF_TMP_DIR}/ipf.conf.a
	${BIN_IPF} -nvf ${TEST_IPF_CONF} | sed -e 's/(\!)//g' | \
		sort > ${IPF_TMP_DIR}/ipf.conf.b
	ret=$?
	if [[ $ret != 0 ]] ; then
		print - "-- ERROR parsing ipf.conf.b"
		return 1;
	fi
	cmp ${IPF_TMP_DIR}/ipf.conf.a ${IPF_TMP_DIR}/ipf.conf.b 2>&1
	ret=$?
	if [[ $ret != 0 ]] ; then
		print "| ipf.conf.a (ipfstat -io)"
		ccat < ${IPF_TMP_DIR}/ipf.conf.a
		print "| ipf.conf.b (ipf -nvf)"
		ccat < ${IPF_TMP_DIR}/ipf.conf.b
	fi
	return $ret
}

validate_loaded_ipnat_conf() {
	${BIN_IPNAT} -l | egrep '^map|^rdr|^bimap|^encap|^divert|^rewrite' | \
		sort > ${IPF_TMP_DIR}/ipnat.conf.a
	${BIN_IPNAT} -nvf ${TEST_IPNAT_CONF} | \
		sort > ${IPF_TMP_DIR}/ipnat.conf.b
	ret=$?
	if [[ $ret != 0 ]] ; then
		print - "-- ERROR parsing ipnat.conf.b"
		return 1;
	fi
	cmp ${IPF_TMP_DIR}/ipnat.conf.a ${IPF_TMP_DIR}/ipnat.conf.b
	ret=$?
	if [[ $ret != 0 ]] ; then
		print "| ipnat.conf.a (ipnat -l)"
		ccat < ${IPF_TMP_DIR}/ipnat.conf.a
		print "| ipnat.conf.b (ipnat -nvf)"
		ccat < ${IPF_TMP_DIR}/ipnat.conf.b
	fi
	return $ret
}

verify_src_0() {
	x=$2
	arg=${x:=$1}
	n=$(${IPF_BIN_DIR}/dumpcap.sh ${LOG0_FILE} "${arg}" | \
	    egrep "${1}.*> .*" | wc -l)
	n=$((n))
	print "| Packets matching ${1},dst ${2}: $n"
	return $n
}

verify_src_1() {
	x=$2
	arg=${x:=$1}
	n=$(${IPF_BIN_DIR}/dumpcap.sh ${LOG1_FILE} "${arg}" | \
	    egrep "${1}.*> .*" | wc -l)
	n=$((n))
	print "| Packets matching ${1},dst ${2}: $n"
	return $n
}

verify_srcdst_0() {
	x=$3
	arg=${x:=$1}
	n=$(${IPF_BIN_DIR}/dumpcap.sh ${LOG0_FILE} "${arg}" | \
	    egrep "${1}.*> .*${2}|${2}.*> .*${1}" | wc -l)
	n=$((n))
	print "| Packets matching ${1},${2} ${3}: $n"
	return $n
}

verify_srcdst_1() {
	x=$3
	arg=${x:=$1}
	n=$(${IPF_BIN_DIR}/dumpcap.sh ${LOG1_FILE} "${arg}" | \
	    egrep "${1}.*> .*${2}|${2}.*> .*${1}" | wc -l)
	n=$((n))
	print "| Packets matching ${1},${2} ${3}: $n"
	return $n
}

dumpcap_src_0() {
	x=$2
	arg=${x:=$1}
	${IPF_BIN_DIR}/dumpcap.sh ${LOG0_FILE} "${arg}" | \
	    egrep "${1}.*> .*"
}

dumpcap_src_1() {
	x=$2
	arg=${x:=$1}
	${IPF_BIN_DIR}/dumpcap.sh ${LOG0_FILE} "${arg}" | \
	    egrep "${1}.*> .*"
}

dumpcap_srcdst_0() {
	x=$3
	arg=${x:=$1}
	${IPF_BIN_DIR}/dumpcap.sh ${LOG0_FILE} "${arg}" | \
	    egrep "${1}.*> .*${2}|${2}.*> .*${1}"
}

dumpcap_srcdst_1() {
	x=$3
	arg=${x:=$1}
	${IPF_BIN_DIR}/dumpcap.sh ${LOG1_FILE} "${arg}" | \
	    egrep "${1}.*> .*${2}|${2}.*> .*${1}"
}

get_result() {
	result=$(awk '/^FAIL|^PASS/ { print $1; } ' ${1})
	if [[ $result = PASS ]] ; then
		print "PASS because result=$result"
		print - "-- OK test passed"
		return 0;
	fi
	print "FAIL because result=$result"
	print - "-- ERROR test failed"
	return 1
}

ping_test() {
	host=$1
	shift
	rrsh ${host} "${IPF_BIN_DIR}/ping.sh $@" > ${IPF_TMP_DIR}/ping.out 2>&1
	print "| ping output"
	ccat < ${IPF_TMP_DIR}/ping.out
	print "| end ping output"
	get_result ${IPF_TMP_DIR}/ping.out
	ret=$?
	print "|--- PING result=$ret"
	return $ret
}

traceroute_test() {
	host=$1
	shift
	rrsh ${host} "${IPF_BIN_DIR}/traceroute.sh $@" > \
	    ${IPF_TMP_DIR}/traceroute.out 2>& 1
	ccat < ${IPF_TMP_DIR}/traceroute.out
	get_result ${IPF_TMP_DIR}/traceroute.out
	return $?
}

start_tcp_server() {
	host=$1
	addr=$2
	port=$3

	print "| start tcp server ($4) on ${host}"
	rrsh ${host} ${IPF_BIN_DIR}/tcp_server.sh ${addr} ${port} $4 >\
	    ${IPF_TMP_DIR}/tcp_server.out.$4 2>&1 &
}

stop_tcp_server() {
	host=$1
	print "| stop tcp server on ${host}"
	rrsh ${host} ${IPF_BIN_DIR}/stop_tcp_server.sh $3
	print "| tcp server output from ${host}"
	ccat < ${IPF_TMP_DIR}/tcp_server.out.$3
	x=$(awk '/CLIENTCOUNT/ { print $2; } ' ${IPF_TMP_DIR}/tcp_server.out.$3)
	if [[ $x -ne $2 ]] ; then
		print - "-- ERROR CLIENTCOUNT mismatch $x != $2"
		return 1
	fi
	print - "-- OK CLIENTCOUNT correct"
	return 0
}

tcp_test() {
	host=$1
	addr=$2
	port=$3
	pass=$4
	print "| start tcp client on ${host}"
	rrsh ${host} ${IPF_BIN_DIR}/tcp_client.sh ${addr} ${port} $5 >\
	    ${IPF_TMP_DIR}/tcp_client.out 2>&1
	print "| tcp client returned"
	ccat < ${IPF_TMP_DIR}/tcp_client.out
	x=$(tail -1 ${IPF_TMP_DIR}/tcp_client.out)
	set $x
	if [[ $pass = pass && $1 = CLIENT ]] ; then
		print - "-- OK pass = CLIENT"
		return 0;
	fi
	if [[ $pass = block && ( $1 = DIED  || $1 = FAILED ) ]] ; then
		print - "-- OK block = $1"
		return 0;
	fi
	print - "-- ERROR pass $pass client $1"
	return 1;
}

start_udp_server() {
	host=$1
	addr=$2
	port=$3

	print "| start udp server on ${host}"
	rrsh ${host} ${IPF_BIN_DIR}/udp_server.sh ${addr} ${port} $4 >\
	    ${IPF_TMP_DIR}/udp_server.out.$4 2>&1 &
}

stop_udp_server() {
	host=$1
	print "| stop udp server on ${host}"
	rrsh ${host} ${IPF_BIN_DIR}/stop_udp_server.sh $3
	print "| udp server output from ${host}"
	ccat < ${IPF_TMP_DIR}/udp_server.out.$3
	x=$(awk '/CLIENTCOUNT/ { print $2; } ' ${IPF_TMP_DIR}/udp_server.out.$3)
	if [[ $x -ne $2 ]] ; then
		print - "-- ERROR CLIENTCOUNT mismatch $x != $2"
		return 1
	fi
	print - "-- OK $x = $2"
	return 0
}

udp_test() {
	host=$1
	addr=$2
	port=$3
	pass=$4
	print "| start udp client on ${host}"
	rrsh ${host} ${IPF_BIN_DIR}/udp_client.sh ${addr} ${port} >\
	    ${IPF_TMP_DIR}/udp_client.out 2>&1
	print "| udp client returned"
	ccat < ${IPF_TMP_DIR}/udp_client.out
	x=$(tail -1 ${IPF_TMP_DIR}/udp_client.out)
	set $x
	if [[ $pass = pass && $1 = CLIENT ]] ; then
		print - "-- OK pass = CLIENT"
		return 0;
	fi
	if [[ $pass = block && ( $1 = DIED  || $1 = FAILED ) ]] ; then
		print - "-- OK block = $1"
		return 0;
	fi
	print - "-- ERROR pass $pass client $1"
	return 1;
}

ftp_test() {
	host=$1
	addr=$2
	path=$3
	pass=$4

	rrsh ${host} ${IPF_BIN_DIR}/ftp.sh ${addr} ${path} ${IPF_TMP_DIR}> \
	    ${IPF_TMP_DIR}/ftp-task.out
	x=$(egrep '^PASS|^FAIL' ${IPF_TMP_DIR}/ftp-task.out|tail -1)
	print "| ftp client output"
	ccat < ${IPF_TMP_DIR}/ftp-task.out
	print "| ftp client returned"
	print "| x=$x"
	if [[ -n "$x" ]] ; then
		set $x
	else
		set FAIL
	fi
	print "| ftp"
	if [[ $pass = pass && $1 = PASS ]] ; then
		return 0;
	fi
	if [[ $pass = block && $1 = FAIL ]] ; then
		return 0;
	fi
	print - "-- ERROR test expected $pass returned $1"
	return 1;
}

rcmd_test() {
	host=$1
	addr=$2
	pass=$3

	print "${RRSH} -n ${host} rsh -l ${RCMD_USER} -n ${addr} ${IPF_BIN_DIR}/pass_stderr.sh"
	sleep 1
	${RRSH} -n ${host} rsh -l ${RCMD_USER} -n ${addr} \
	    ${IPF_BIN_DIR}/pass_stderr.sh 2>${IPF_TMP_DIR}/stderr >/dev/null &
	job=$!
	(sleep 6 && kill -TERM $job 2>/dev/null || print "ping kill failed") &
	wait $job
	x=$(cat ${IPF_TMP_DIR}/stderr)
	print "| rcmd returned"
	if [[ -n "$x" ]] ; then
		set $x
	else
		set FAIL
	fi
	print "1=$1 pass=$pass"
	print "| rcmd"
	if [[ $pass = pass && $1 = PASS ]] ; then
		return 0;
	fi
	return 1;
}

tftp_test() {
	host=$1
	addr=$2
	path=$3
	pass=$4
	rrsh ${host} ${IPF_BIN_DIR}/tftp.sh ${addr} ${path} ${IPF_TMP_DIR} > \
	    ${IPF_TMP_DIR}/tftp-task.out 2>&1
	print "| tftp client output"
	ccat < ${IPF_TMP_DIR}/tftp-task.out
	print "| tftp client returned"
	x=$(grep BYTES ${IPF_TMP_DIR}/tftp-task.out)
	if [[ -z $x ]] ; then
		print - "-- ERROR could not find BYTES output from tftp"
		return 1
	fi
	set $x
	if [[ $2 -eq 0 ]] ; then
		print - "-- ERRROR got ($x) zero bytes via tftp"
		return 1
	fi
	print - "-- OK got ($x) bytes via tftp"
	return 0
}

rrsh() {
	if [[ ${RUNHOST} = ${1} ]] ; then
		shift
		print "$*"
		$@
		rval=$?
	else
		print "${RRSH} -n $*"
		${RRSH} -n $@
		rval=$?
	fi
	return $rval
}

rrcp() {
	dhost=${1%:*}
	if [[ ${RUNHOST} = ${dhost} ]] ; then
		srcfile=${1#*:}
		if [[ "${srcfile}" != "$2" ]] ; then
			cp -p "${srcfile}" "$2"
			rval=$?
		else
			rval=0
		fi
	else
		print "${RRCP} $*"
		${RRCP} $@
		rval=$?
	fi
	return $rval
}

rsh_sut() {
	rrsh ${SUT_CTL_HOSTNAME} $@
	return $?
}

rsh_sender() {
	rrsh ${SENDER_CTL_HOSTNAME} $@
	return $?
}

rsh_receiver() {
	rrsh ${RECEIVER_CTL_HOSTNAME} $@
	return $?
}

ccat() {
	while read i; do
		print - "$i"
	done
}

count_ipf_rules() {
	${BIN_IPFSTAT} -io > ${IPF_TMP_DIR}/ipf.conf.a
	ret=$?
	if [[ $ret != 0 ]] ; then
		return -1
	fi
	nrules=$(egrep -v 'empty list' ${IPF_TMP_DIR}/ipf.conf.a | wc -l)
	nrules=$((nrules + 0))
	return $nrules;
}

count_ipf6_rules() {
	${BIN_IPFSTAT} -6io > ${IPF_TMP_DIR}/ipf.conf.a
	ret=$?
	if [[ $ret != 0 ]] ; then
		return -1
	fi
	nrules=$(egrep -v 'empty list' ${IPF_TMP_DIR}/ipf.conf.a | wc -l)
	nrules=$((nrules + 0))
	return $nrules;
}
count_ipnat_rules() {
	dump_ipnat_rules
	ret=$?
	if [[ $ret != 0 ]] ; then
		return -1
	fi
	nrules=$(cat ${IPF_TMP_DIR}/ipnat.conf.a | wc -l)
	nrules=$((nrules + 0))
	return $nrules;
}

count_logged_nat_sessions() {
	lines=$(egrep 'NAT:NEW' ${IPF_TMP_DIR}/ipmon.out | wc -l)
	lines=$((lines + 0))
	return $lines
}

count_purged_nat_sessions() {
	lines=$(egrep 'NAT:PURGE' ${IPF_TMP_DIR}/ipmon.out | wc -l)
	lines=$((lines + 0))
	return $lines
}

count_expired_nat_sessions() {
	lines=$(egrep 'NAT:EXPIRE' ${IPF_TMP_DIR}/ipmon.out | wc -l)
	lines=$((lines + 0))
	return $lines
}

count_logged_state_sessions() {
	lines=$(egrep 'STATE:NEW' ${IPF_TMP_DIR}/ipmon.out | wc -l)
	lines=$((lines + 0))
	return $lines
}

count_expired_state_sessions() {
	lines=$(egrep 'STATE:EXPIRE' ${IPF_TMP_DIR}/ipmon.out | wc -l)
	lines=$((lines + 0))
	return $lines
}

init() {
	myname=${0##*/}
}

basic_udp_test() {
	receiver=${1}
	recvaddr=${2}
	port=$3
	sender=${4}
	dest=${5}
	goal=${6}
        start_udp_server ${receiver} ${recvaddr} ${port}
        sleep 1
        udp_test ${sender} ${dest} ${port} ${goal}
        ret=$?
        stop_udp_server ${receiver} 1
        x=$?
        ret=$((ret + x))
        return $ret;
}

basic_tcp_test() {
	receiver=${1}
	recvaddr=${2}
	port=$3
	sender=${4}
	goal=${5}
        start_tcp_server ${receiver} ${recvaddr} ${port}
        sleep 1
        tcp_test ${sender} ${recvaddr} ${port} ${goal}
        ret=$?
        stop_tcp_server ${receiver} 1
        x=$?
        ret=$((ret + x))
        return $ret;
}

