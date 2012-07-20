#!/bin/ksh
#
# It is assumed that this script is always run on SUT_CTL_HOSTNAME when
# called from one_test.sh
#
PID0_FILE=${IPF_TMP_DIR}/tcpdump.${SUT_NET0_IFP_NAME}.pid
PID1_FILE=${IPF_TMP_DIR}/tcpdump.${SUT_NET1_IFP_NAME}.pid
PIDS_FILE=${IPF_TMP_DIR}/tcpdump.${SENDER_NET0_IFP_NAME}.pid
PIDR_FILE=${IPF_TMP_DIR}/tcpdump.${RECEIVER_NET1_IFP_NAME}.pid

mkdir -p ${IPF_LOG_DIR}

logging_start() {
echo "capture_net0=$capture_net0"
	if [[ $capture_net0 -eq 1 ]] ; then
		${IPF_BIN_DIR}/capture.sh \
		    ${SUT_NET0_IFP_NAME} ${LOG0_FILE} ${PID0_FILE} &
	fi

	if [[ $capture_net1 -eq 1 ]] ; then
		if [[ -n ${SUT_NET1_IFP_NAME} ]] ; then
			${IPF_BIN_DIR}/capture.sh \
			    ${SUT_NET1_IFP_NAME} ${LOG1_FILE} ${PID1_FILE} &
		fi
	fi
	if [[ $capture_ipmon -eq 1 ]] ; then
		ipmon -DP ${IPF_TMP_DIR}/ipmon.pid -Fa ${IPF_TMP_DIR}/ipmon.out
	fi

	if [[ $capture_sender -eq 1 ]] ; then
		if [[ $1 = 2h || $1 = 3h ]] ; then
			${RRSH} ${SENDER_CTL_HOSTNAME} \
			    ${IPF_BIN_DIR}/capture.sh ${SENDER_NET0_IFP_NAME} \
			    ${LOGS_FILE} ${PIDS_FILE} &
		fi
	fi

	if [[ $capture_receiver -eq 1 ]] ; then
		if [[ $1 = 3h ]] ; then
			${RRSH} ${RECEIVER_CTL_HOSTNAME} \
			    ${IPF_BIN_DIR}/capture.sh \
			    ${RECEIVER_NET1_IFP_NAME} ${LOGR_FILE} \
			    ${PIDR_FILE} &
		fi
	fi
}

logging_stop() {
	if [[ $capture_net0 -eq 1 ]] ; then
		${IPF_BIN_DIR}/killpid.sh ${PID0_FILE}
	fi

	if [[ $capture_net1 -eq 1 ]] ; then
		if [[ -n ${SUT_NET1_IFP_NAME} ]] ; then
			${IPF_BIN_DIR}/killpid.sh ${PID1_FILE}
		fi
	fi

	if [[ $capture_ipmon -eq 1 ]] ; then
		${IPF_BIN_DIR}/killpid.sh ${IPF_TMP_DIR}/ipmon.pid
	fi

	if [[ $capture_sender -eq 1 ]] ; then
		if [[ $1 = 2h || $1 = 3h ]] ; then
			${RRSH} ${SENDER_CTL_HOSTNAME} \
			    ${IPF_BIN_DIR}/killpid.sh ${PIDS_FILE}
		fi
	fi
	if [[ $capture_receiver -eq 1 ]] ; then
		if [[ $1 = 3h ]] ; then
			${RRSH} ${RECEIVER_CTL_HOSTNAME} \
			    ${IPF_BIN_DIR}/killpid.sh ${PIDR_FILE}
		fi
	fi
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
	mkdir -p $2
	if [[ $preserve_net0 -eq 1 ]] ; then
		print "| Preserving ${LOG0_FILE} ->"
		print "|  $2/net0.cap"
		cp ${LOG0_FILE} $2/net0.cap
	else
		print "| Preserving ${LOG0_FILE} disabled"
	fi
	if [[ $preserve_net1 -eq 1 ]] ; then
		print "| Preserving ${LOG1_FILE} ->"
		print "|  $2/net1.cap"
		cp ${LOG1_FILE} $2/net1.cap
	else
		print "| Preserving ${LOG1_FILE} disabled"
	fi
	if [[ $preserve_ipmon -eq 1 ]] ; then
		print "| Preserving ${IPF_TMP_DIR}/ipmon.out ->"
		print "|  $2/ipmon_out.txt"
		cp ${IPF_TMP_DIR}/ipmon.out $2/ipmon_out.txt
	else
		print "| Preserving ${IPF_TMP_DIR}/ipmon.out disabled"
	fi
	if [[ $preserve_sender -eq 1 ]] ; then
		if [[ $1 = 2h || $1 = 3h ]] ; then
			print "| Preserving ${LOGS_FILE} ->"
			print "|  $2/sender.cap"
			${RRCP} ${SENDER_CTL_HOSTNAME}:${LOGS_FILE} $2/sender.cap
		fi
	else
		print "| Preserving ${SENDER_CTL_HOSTNAME}:${LOGS_FILE} disabled"
	fi
	if [[ $preserve_receiver -eq 1 ]] ; then
		if [[ $1 = 3h ]] ; then
			print "| Preserving ${LOGR_FILE} ->"
			print "|  $2/receiver.cap"
			${RRCP} ${RECEIVER_CTL_HOSTNAME}:${LOGR_FILE} $2/receiver.cap
		fi
	else
		print "| Preserving ${RECEIVER_CTL_HOSTNAME}:${LOGR_FILE} disabled"
	fi
}
