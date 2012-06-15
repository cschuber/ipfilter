#!/bin/ksh
#
# It is assumed that this script is always run on SUT_CTL_HOSTNAME when
# called from one_test.sh
#
PID0_FILE=${IPF_TMP_DIR}/tcpdump.${SUT_NET0_IFP_NAME}.pid
PID1_FILE=${IPF_TMP_DIR}/tcpdump.${SUT_NET1_IFP_NAME}.pid
PIDS_FILE=${IPF_TMP_DIR}/tcpdump.${SENDER_NET0_IFP_NAME}.pid
PIDR_FILE=${IPF_TMP_DIR}/tcpdump.${RECEIVER_NET1_IFP_NAME}.pid
LOG0_FILE=${IPF_TMP_DIR}/tcpdump.${SUT_NET0_IFP_NAME}
LOG1_FILE=${IPF_TMP_DIR}/tcpdump.${SUT_NET1_IFP_NAME}
LOGS_FILE=${IPF_TMP_DIR}/tcpdump.${SENDER_NET0_IFP_NAME}
LOGR_FILE=${IPF_TMP_DIR}/tcpdump.${RECEIVER_NET1_IFP_NAME}

logging_start() {
	if [[ ${LOGGING} = OFF ]] ; then
		echo "| LOGGING OFF - cannot start logging"
		return
	fi
	${IPF_BIN_DIR}/capture.sh \
	    ${SUT_NET0_IFP_NAME} ${LOG0_FILE} ${PID0_FILE} &

	if [[ -n ${SUT_NET1_IFP_NAME} ]] ; then
		${IPF_BIN_DIR}/capture.sh \
		    ${SUT_NET1_IFP_NAME} ${LOG1_FILE} ${PID1_FILE} &
	fi
	ipmon -DP ${IPF_TMP_DIR}/ipmon.pid -Fa ${IPF_TMP_DIR}/ipmon.out

	if [[ $1 = 2h || $1 = 3h ]] ; then
		rsh_sender ${IPF_BIN_DIR}/capture.sh \
		    ${SENDER_NET0_IFP_NAME} ${LOGS_FILE} ${PIDS_FILE} &
	fi
	if [[ $1 = 3h ]] ; then
		rsh_receiver ${IPF_BIN_DIR}/capture.sh \
		    ${RECEIVER_NET1_IFP_NAME} ${LOGR_FILE} ${PIDR_FILE} &
	fi
}

logging_stop() {
	if [[ ${LOGGING} = OFF ]] ; then
		echo "| LOGGING OFF - cannot stop logging"
		return
	fi
	${IPF_BIN_DIR}/killpid.sh ${PID0_FILE}
	if [[ -n ${SUT_NET1_IFP_NAME} ]] ; then
		${IPF_BIN_DIR}/killpid.sh ${PID1_FILE}
	fi
	${IPF_BIN_DIR}/killpid.sh ${IPF_TMP_DIR}/ipmon.pid

	if [[ $1 = 2h || $1 = 3h ]] ; then
		rsh_sender ${IPF_BIN_DIR}/killpid.sh ${PIDS_FILE}
	fi
	if [[ $1 = 3h ]] ; then
		rsh_receiver ${IPF_BIN_DIR}/killpid.sh ${PIDR_FILE}
	fi
}

logging_dump() {
	if [[ ${LOGGING} = OFF ]] ; then
		echo "================================================================="
		echo "| LOGGING OFF - nothing to dump"
		echo "================================================================="
		return
	fi
	echo "================================================================="
	echo "|  tcpdump ouput for SUT_IFP0                                   |"
	echo "|                                                               |"
	${IPF_BIN_DIR}/dumpcap.sh ${LOG0_FILE} 2>&1
	echo "|                                                               |"
	echo "|---------------------------------------------------------------|"
	echo "|  tcpdump ouput for SUT_IFP1                                   |"
	echo "|                                                               |"
	if [[ -n ${SUT_NET1_IFP_NAME} ]] ; then
		${IPF_BIN_DIR}/dumpcap.sh ${LOG1_FILE} 2>&1
	else
		echo "NO CAPTURE ON SUT_IFP1"
	fi
	echo "|                                                               |"
	echo "|---------------------------------------------------------------|"
	echo "|                                                               |"
	cat ${IPF_TMP_DIR}/ipmon.out
	echo "|                                                               |"
	echo "================================================================="
}

logging_cleanup() {
	/bin/rm -f ${LOG0_FILE}
	/bin/rm -f ${PID0_FILE}
	/bin/rm -f ${LOG1_FILE}
	/bin/rm -f ${PID1_FILE}
	/bin/rm -f ${IPF_TMP_DIR}/ipmon.out
	/bin/rm -f ${IPF_TMP_DIR}/ipmon.pid
}

logging_preserve() {
	if [[ ${LOGGING} = OFF ]] ; then
		echo "================================================================="
		echo "| LOGGING OFF - nothing to preserve"
		echo "================================================================="
		return
	fi
	mkdir -p $2
	echo "| Preserving ${LOG0_FILE} -> $2/net0.cap"
	cp ${LOG0_FILE} $2/net0.cap
	echo "| Preserving ${LOG1_FILE} -> $2/net1.cap"
	cp ${LOG1_FILE} $2/net1.cap
	echo "| Preserving ${IPF_TMP_DIR}/ipmon.out -> $2/ipmon_out.txt"
	cp ${IPF_TMP_DIR}/ipmon.out $2/ipmon_out.txt
	if [[ $1 = 2h || $1 = 3h ]] ; then
		echo "| Preserving ${LOGS_FILE} -> $2/sender.cap"
		${RRCP} ${SENDER_CTL_HOSTNAME}:${LOGS_FILE} $2/sender.cap
	fi
	if [[ $1 = 3h ]] ; then
		echo "| Preserving ${LOGR_FILE} -> $2/receiver.cap"
		${RRCP} ${RECEIVER_CTL_HOSTNAME}:${LOGR_FILE} $2/receiver.cap
	fi
}

logging_verify_srcdst_0() {
	if [[ ${LOGGING} = OFF ]] ; then
		echo "================================================================="
		echo "| LOGGING OFF - srcdst verify always succeeds"
		echo "================================================================="
		return 0
	fi
	n=$(${IPF_BIN_DIR}/dumpcap.sh ${LOG0_FILE} 2>&1 | \
	    egrep "${1}.*>.*${2}|${2}.*>.*${1}" | wc -l)
	n=$((n))
	echo "Packets matching ${1},${2}: $n"
	return $n
}

logging_verify_srcdst_1() {
	if [[ ${LOGGING} = OFF ]] ; then
		echo "================================================================="
		echo "| LOGGING OFF - srcdst verify always succeeds"
		echo "================================================================="
		return 0
	fi
	n=$(${IPF_BIN_DIR}/dumpcap.sh ${LOG1_FILE} 2>&1 2>&1 | \
	    egrep "${1}.*>.*${2}|${2}.*>.*${1}" | wc -l)
	n=$((n))
	echo "Packets matching ${1},${2}: $n"
	return $n
}

exitval=0
mkdir -p ${IPF_LOG_DIR}

case $1 in
cleanup)
	logging_cleanup
	;;
dump)
	logging_dump
	;;
preserve)
	logging_preserve $2 $3
	;;
start)
	logging_start $2
	;;
stop)
	logging_stop $2
	;;
verify_srcdst_0)
	logging_verify_srcdst_0 $2 $3
	exitval=$?
	;;
verify_srcdst_1)
	logging_verify_srcdst_1 $2 $3
	exitval=$?
	;;
esac
exit $exitval
