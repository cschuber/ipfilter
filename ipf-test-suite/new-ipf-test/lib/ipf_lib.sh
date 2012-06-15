#!/bin/ksh

load_config() {
	if ${BIN_IPPOOL} -f ${TEST_IPPOOL_CONF}; then
		if ${BIN_IPF} -f ${TEST_IPF_CONF}; then
			if ${BIN_IPNAT} -f ${TEST_IPNAT_CONF}; then
				return 0;
			else
				echo "FAIL error loading ipnat ${TEST_IPNAT_CONF}"
				return 1;
			fi
		else
			echo "FAIL error loading ipf ${TEST_IPF_CONF}"
			return 1;
		fi
	else
		echo "FAIL error loading ippool ${TEST_IPPOOL_CONF}"
		return 1;
	fi
}

clear_config() {
	${BIN_IPF} -Fa
	${BIN_IPNAT} -FC
	${BIN_POOL} -F
	return 0;
}

dump_rules() {
	echo "---- dump v4 rules ----"
	${BIN_IPFSTAT} -ioh
	echo "----"
	echo "---- dump v6 rules ----"
	${BIN_IPFSTAT} -6ioh
	echo "----"
	return 0;
}

dump_state() {
	echo "---- dump state ----"
	${BIN_IPFSTAT} -slvR
	echo "----"
	return 0;
}

dump_frag() {
	echo "---- dump frag ----"
	${BIN_IPFSTAT} -f
	echo "----"
	return 0;
}

dump_nat() {
	echo "---- dump nat ----"
	${BIN_IPNAT} -lvdR
	echo "----"
	return 0;
}

dump_pool() {
	echo "---- dump pool ----"
	${BIN_IPPOOL} -lv
	echo "----"
	return 0;
}

dump_all() {
	echo "---- DUMP ALL ----"
	dump_pool
	dump_rules
	dump_state
	dump_frag
	dump_nat
}

dump_ipnat_rules() {
	${BIN_IPNAT} -l | egrep '^rdr|^map|^bimap|^rewrite|^divert' > \
	    ${IPF_TMP_DIR}/ipnat.conf.a
	ret=$?
	if [[ $ret != 0 ]] ; then
		echo "---- error dumping ipnat rules"
	fi
	return $ret
}

validate_loaded_ipf_conf() {
	${RRSH} ${SUT_CTL_HOSTNAME} ${BIN_IPFSTAT} -vio | \
		sed -e '/^#/d' -e 's/(\!)//g' > ${IPF_TMP_DIR}/ipf.conf.b
	${RRSH} ${SUT_CTL_HOSTNAME} ${BIN_IPFSTAT} -6vio | grep inet6 | \
		sed -e '/^#/d' -e 's/(\!)//g' >> ${IPF_TMP_DIR}/ipf.conf.b
	sort -u ${IPF_TMP_DIR}/ipf.conf.b -o ${IPF_TMP_DIR}/ipf.conf.a
	${BIN_IPF} -nvf ${TEST_IPF_CONF} | sed -e 's/(\!)//g' | \
		sort > ${IPF_TMP_DIR}/ipf.conf.b
	ret=$?
	if [[ $ret != 0 ]] ; then
		echo "Error parsing ipf.conf.b"
		return 1;
	fi
	cmp ${IPF_TMP_DIR}/ipf.conf.a ${IPF_TMP_DIR}/ipf.conf.b 2>&1
	ret=$?
	if [[ $ret != 0 ]] ; then
		echo "---- ipf.conf.a (ipfstat -io) ----"
		ccat < ${IPF_TMP_DIR}/ipf.conf.a
		echo "---- ipf.conf.b (ipf -nvf) ----"
		ccat < ${IPF_TMP_DIR}/ipf.conf.b
	fi
	return $ret
}

validate_loaded_ipnat_conf() {
	${RRSH} ${SUT_CTL_HOSTNAME} ${BIN_IPNAT} -l | \
		egrep '^map|^rdr|^bimap|^encap|^divert|^rewrite' | \
		sort > ${IPF_TMP_DIR}/ipnat.conf.a
	${RRSH} ${SUT_CTL_HOSTNAME} ${BIN_IPNAT} -nvf ${TEST_IPNAT_CONF} | \
		sort > ${IPF_TMP_DIR}/ipnat.conf.b
	ret=$?
	if [[ $ret != 0 ]] ; then
		echo "Error parsing ipnat.conf.b"
		return 1;
	fi
	cmp ${IPF_TMP_DIR}/ipnat.conf.a ${IPF_TMP_DIR}/ipnat.conf.b
	ret=$?
	if [[ $ret != 0 ]] ; then
		echo "---- ipnat.conf.a (ipnat -l) ----"
		ccat < ${IPF_TMP_DIR}/ipnat.conf.a
		echo "---- ipnat.conf.b (ipnat -nvf) ----"
		ccat < ${IPF_TMP_DIR}/ipnat.conf.b
	fi
	return $ret
}

generate_empty_ipnat_conf() {
	> ${IPF_TMP_DIR}/${TEST_IPNAT_CONF}
}

generate_empty_ippool_conf() {
	> ${IPF_TMP_DIR}/${TEST_IPPOOL_CONF}
}

get_result() {
	result=$(awk '/^FAIL|^PASS/ { print $1; } ' ${1})
	if [[ $result = PASS ]] ; then
		echo "PASS because result=$result"
		return 0;
	fi
	echo "FAIL because result=$result"
	return 1
}

ping_test() {
	host=$1
	shift
	rrsh ${host} "${IPF_BIN_DIR}/ping.sh $@" > ${IPF_TMP_DIR}/ping.out 2>&1
	echo '---- ping output ----'
	ccat < ${IPF_TMP_DIR}/ping.out
	echo '---- end ping output ----'
	get_result ${IPF_TMP_DIR}/ping.out
	return $?
}

reset_ipfilter() {
	if ${BIN_IPF} -D; then
		${BIN_IPF} -V
		if ${BIN_IPF} -E; then
			${BIN_IPF} -V
			return 0;
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

start_tcp_server() {
	host=$1
	addr=$2
	port=$3

	echo "---- start tcp server ($4) on ${host}"
	rrsh ${host} ${IPF_BIN_DIR}/tcp_server.sh ${addr} ${port} $4 >\
	    ${IPF_TMP_DIR}/tcp_server.out.$4 2>&1 &
}

stop_tcp_server() {
	host=$1
	echo "---- stop tcp server on ${host}"
	rrsh ${host} perl ${IPF_BIN_DIR}/stop_tcp_server.sh $3
	echo "---- tcp server output from ${host}"
	ccat < ${IPF_TMP_DIR}/tcp_server.out.$3
	x=$(awk '/CLIENTCOUNT/ { print $2; } ' ${IPF_TMP_DIR}/tcp_server.out.$3)
	x=$((x + 0))
	if [[ $x != $2 ]] ; then
		echo "---- CLIENTCOUNT mismatch $x != $2"
		return 1
	fi
	return 0
}

tcp_test() {
	host=$1
	addr=$2
	port=$3
	pass=$4
	echo "---- start tcp client on ${host}"
	rrsh ${host} ${IPF_BIN_DIR}/tcp_client.sh ${addr} ${port} >\
	    ${IPF_TMP_DIR}/tcp_client.out 2>&1
	echo "---- tcp client returned"
	ccat < ${IPF_TMP_DIR}/tcp_client.out
	x=$(tail -1 ${IPF_TMP_DIR}/tcp_client.out)
	set $x
	if [[ $pass = pass && $1 = CLIENT ]] ; then
		return 0;
	fi
	if [[ $pass = block && $1 = DIED ]] ; then
		return 0;
	fi
	return 1;
}

start_udp_server() {
	host=$1
	addr=$2
	port=$3

	echo "---- start udp server on ${host}"
	rrsh ${host} ${IPF_BIN_DIR}/udp_server.sh ${addr} ${port} $4 >\
	    ${IPF_TMP_DIR}/udp_server.out.$4 2>&1 &
}

stop_udp_server() {
	host=$1
	echo "---- stop udp server on ${host}"
	rrsh -n ${host} perl ${IPF_BIN_DIR}/stop_udp_server.sh $3
	echo "---- udp server output from ${host}"
	ccat < ${IPF_TMP_DIR}/udp_server.out.$3
	x=$(awk '/CLIENTCOUNT/ { print $2; } ' ${IPF_TMP_DIR}/udp_server.out.$3)
	x=$((x + 0))
	if [[ $x != $2 ]] ; then
		echo "---- CLIENTCOUNT mismatch $x != $2"
		return 1
	fi
	return 0
}

udp_test() {
	host=$1
	addr=$2
	port=$3
	pass=$4
	echo "---- start udp client on ${host}"
	rrsh ${host} ${IPF_BIN_DIR}/udp_client.sh ${addr} ${port} >\
	    ${IPF_TMP_DIR}/udp_client.out 2>&1
	echo "---- udp client returned"
	ccat < ${IPF_TMP_DIR}/udp_client.out
	x=$(tail -1 ${IPF_TMP_DIR}/udp_client.out)
	set $x
	if [[ $pass = pass && $1 = CLIENT ]] ; then
		return 0;
	fi
	if [[ $pass = block && $1 = DIED ]] ; then
		return 0;
	fi
	return 1;
}

ftp_test() {
	host=$1
	addr=$2
	path=$3
	pass=$4

	rrsh ${host} ${IPF_BIN_DIR}/ftp.sh ${addr} ${path} ${IPF_TMP_DIR}>\
	    ${IPF_TMP_DIR}/ftp.out
	x=$(egrep '^PASS|^FAIL' ${IPF_TMP_DIR}/ftp.out|tail -1)
	echo "---- ftp client output"
	ccat < ${IPF_TMP_DIR}/ftp.out
	echo "---- ftp client returned"
	echo "---- x=$x"
	if [[ -n "$x" ]] ; then
		set $x
	else
		set FAIL
	fi
	echo "1=$1 pass=$pass"
	echo "---- ftp"
	if [[ $pass = pass && $1 = PASS ]] ; then
		return 0;
	fi
	if [[ $pass = block && $1 = FAIL ]] ; then
		return 0;
	fi
	return 1;
}

rcmd_test() {
	host=$1
	addr=$2
	pass=$3

	echo "${RRSH} -n ${host} rsh -l ${RCMD_USER} -n ${addr} ${IPF_BIN_DIR}/pass_stderr.sh"
	sleep 1
	x=$(${RRSH} -n ${host} rsh -l ${RCMD_USER} -n ${addr} ${IPF_BIN_DIR}/pass_stderr.sh 2>&1)
	echo "---- rcmd returned"
	if [[ -n "$x" ]] ; then
		set $x
	else
		set FAIL
	fi
	echo "1=$1 pass=$pass"
	echo "---- rcmd"
	if [[ $pass = pass && $1 = PASS ]] ; then
		return 0;
	fi
	return 1;
}

traceroute_test() {
	${IPF_BIN_DIR}/traceroute.sh $1 ${SENDER_NET0_ADDR_V4} ${2} ${IPF_TMP_DIR}/traceroute.out $3
	get_result ${IPF_TMP_DIR}/traceroute.out
	return $?
}

tftp_test() {
	host=$1
	addr=$2
	pass=$3
	rrsh ${host} ${IPF_BIN_DIR}/tftp.sh ${addr} ${IPF_TMP_DIR} > \
	    ${IPF_TMP_DIR}/tftp.out
	x=$(grep Received ${IPF_TMP_DIR}/ftp.out)
	echo "---- ftp client output"
	ccat < ${IPF_TMP_DIR}/ftp.out
	echo "---- ftp client returned"
	echo "$x"
	set $x
	if [[ $3 -gt 0 ]] ; then
		return 0
	fi
	return 1
}

rrsh() {
	if [[ ${RUNHOST} = ${1} ]] ; then
		shift
		echo "$*"
		$@
		rval=$?
	else
		echo "${RRSH} -n $*"
		${RRSH} -n $@
		rval=$?
	fi
	return $rval
}

rrcp() {
	dhost=${1%:*}
	if [[ ${RUNHOST} = ${dhost} ]] ; then
		srcfile=${$1#*:}
		if [[ "${srcfile}" != "$2" ]] ; then
			cp -p "${srcfile}" "$2"
			rval=$?
		else
			rval=0
		fi
	else
		echo "${RRCP} $*"
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
		echo $i
	done
}

count_ipf_rules() {
	${BIN_IPFSTAT} -io > ${IPF_TMP_DIR}/ipf.conf.a
	nrules=$(egrep -v 'empty list' ${IPF_TMP_DIR}/ipf.conf.a | wc -l)
	nrules=$((nrules))
	return $nrules;
}

count_ipnat_rules() {
	dump_ipnat_rules
	nrules=$(cat ${IPF_TMP_DIR}/ipnat.conf.a | wc -l)
	nrules=$((nrules))
	return $nrules;
}

count_logged_nat_sessions() {
	lines=$(egrep 'NAT:NEW' ${IPF_TMP_DIR}/ipmon.out | wc -l)
	lines=$((lines))
	return $lines
}

count_purged_nat_sessions() {
	lines=$(egrep 'NAT:PURGE' ${IPF_TMP_DIR}/ipmon.out | wc -l)
	lines=$((lines))
	return $lines
}

count_expired_nat_sessions() {
	lines=$(egrep 'NAT:EXPIRE' ${IPF_TMP_DIR}/ipmon.out | wc -l)
	lines=$((lines))
	return $lines
}

count_logged_state_sessions() {
	lines=$(egrep 'STATE:NEW' ${IPF_TMP_DIR}/ipmon.out | wc -l)
	lines=$((lines))
	return $lines
}

count_expired_state_sessions() {
	lines=$(egrep 'STATE:EXPIRE' ${IPF_TMP_DIR}/ipmon.out | wc -l)
	lines=$((lines))
	return $lines
}
