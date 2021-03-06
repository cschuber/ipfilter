#!/bin/ksh
#
NET0_NET_V4=192.168.100
NET0_NETMASK_V4=255.255.255.0
NET0_NET_V6=192:168:100
NET0_NETMASK_V6=48
NET1_NET_V4=192.168.101
NET1_NETMASK_V4=255.255.255.0
NET1_NET_V6=192:168:101
NET1_NETMASK_V6=48
TUNNEL_NET_V4=10.0.0
TUNNEL_NET_V6=10
#
# To exclude a particular host from testing and system test configuration,
# set the name to "DONOTUSE".
#
SUT_CTL_HOSTNAME=s10u7-vbox
SENDER_CTL_HOSTNAME=netbsd-vbox
#RECEIVER_CTL_HOSTNAME=DONOTUSE
RECEIVER_CTL_HOSTNAME=freebsd-vbox
#
SUT_CTL_IFP_NAME=e1000g1
SUT_NET0_IFP_NAME=e1000g2
SUT_NET1_IFP_NAME=e1000g3
#
SENDER_CTL_IFP_NAME=wm1
SENDER_NET0_IFP_NAME=wm2
SENDER_NET1_IFP_NAME=SETME
#
RECEIVER_CTL_IFP_NAME=em1
RECEIVER_NET0_IFP_NAME=SETME
RECEIVER_NET1_IFP_NAME=em3
#
PING_TRIES=3
PING_SIZE_LARGE=2000
PING_SIZE_SMALL=200
#
# A route to this address is added to SENDER via SUT and is used in NAT tests
#
NET0_FAKE_ADDR_V4=1.1.1.1
NET0_FAKE_NET_V4=1.1.1.0
NET0_FAKE_NETMASK_V4=255.255.255.0
NET0_FAKE_ADDR_V6=1:1:1::1
NET0_FAKE_NET_V6=1:1:1::0
NET0_FAKE_NETMASK_V6=48
#
# A route to this address is added to RECEIVER via SUT and is used in NAT tests
#
NET1_FAKE_ADDR_V4=2.2.2.2
NET1_FAKE_NET_V4=2.2.2.0
NET1_FAKE_NETMASK_V4=255.255.255.0
NET1_FAKE_ADDR_V6=2:2:2::2
NET1_FAKE_NET_V6=2:2:2::0
NET1_FAKE_NETMASK_V6=48
#
# The FTP/TFTP tests will attempt to download this file
#
FTP_PATH=/pub/test_data.txt
#
TCP_TIMEOUT=6
#
# This username is the target for testing of the rcmd proxy
#
RCMD_USER=root
#
# Because FreeBSD's rcmd(3) uses $RSH internally and does not behave properly
# when $RSH = rsh
#
RRCP=rcp
#RRCP=scp
RRSH=rsh
#RRSH=ssh
#
BIN_IPF=/usr/sbin/ipf
BIN_IPFSTAT=/usr/sbin/ipfstat
BIN_IPNAT=/usr/sbin/ipnat
BIN_IPPOOL=/usr/sbin/ippool
BIN_IPMON=/usr/sbin/ipmon
#
IPF_VAR_DIR=/var/tmp/ipf_test
IPF_BIN_DIR=${IPF_VAR_DIR}/bin
IPF_LIB_DIR=${IPF_VAR_DIR}/lib
IPF_LOG_DIR=${IPF_VAR_DIR}/log/`date +'%Y_%m_%d_%H%M'`
IPF_TMP_DIR=${IPF_VAR_DIR}/tmp
IPF_LOG_FILE=${IPF_LOG_DIR}/$1.$$.log
#
TEST_IPF_CONF=ipf_test.conf
TEST_IPNAT_CONF=ipnat_test.conf
TEST_IPPOOL_CONF=ippool_test.conf
#
# -------- END OF CONFIGURATION VARIABLES --------
#
LOG0_FILE=${IPF_TMP_DIR}/tcpdump.${SUT_NET0_IFP_NAME}
LOG1_FILE=${IPF_TMP_DIR}/tcpdump.${SUT_NET1_IFP_NAME}
LOGS_FILE=${IPF_TMP_DIR}/tcpdump.${SENDER_NET0_IFP_NAME}
LOGR_FILE=${IPF_TMP_DIR}/tcpdump.${RECEIVER_NET1_IFP_NAME}
#
SUT_NET0_ADDR_V4=${NET0_NET_V4}.2
SUT_NET0_ADDR_V6=${NET0_NET_V6}::2
SENDER_NET0_ADDR_V4=${NET0_NET_V4}.3
SENDER_NET0_ADDR_V6=${NET0_NET_V6}::3
SENDER_TUNNEL_ADDR_V4=${TUNNEL_NET_V4}.3
SENDER_TUNNEL_ADDR_V6=${TUNNEL_NET_V6}::3
#
SUT_NET1_ADDR_V4=${NET1_NET_V4}.130
SUT_NET1_ADDR_V6=${NET1_NET_V6}::130
RECEIVER_NET1_ADDR_V4=${NET1_NET_V4}.131
RECEIVER_NET1_ADDR_V6=${NET1_NET_V6}::131
RECEIVER_TUNNEL_ADDR_V4=${TUNNEL_NET_V4}.131
RECEIVER_TUNNEL_ADDR_V6=${TUNNEL_NET_V6}::131
#
export SUT_NET0_DOT=2
export SUT_NET1_DOT=130
export SENDER_NET0_DOT=3
export RECEIVER_NET1_DOT=131
#
for i in SUT SENDER RECEIVER; do
	for j in NET0 NET1; do
		name=${i}_${j}_ADDR_V4
		dot=$(eval echo \$${i}_${j}_DOT)
		x=$(eval echo \$$name)
		if [[ -n $x && -n $dot ]] ; then
			alias=1
			for k in 16 32 48 64 80 96 112; do
				addr=$((dot + k))
				name="${i}_${j}_ADDR_V4_A${alias}"
				eval "${name}=\$${j}_NET_V4.${addr}"
				eval "export ${name}"
				name="${i}_${j}_ADDR_V6_A${alias}"
				eval "${name}=\$${j}_NET_V6::${addr}"
				eval "export ${name}"
				alias=$((alias + 1))
			done
		fi
	done
done
#
for i in SUT SENDER RECEIVER; do
	for j in CTL_IFP_NAME CTL_HOSTNAME NET0_HOSTNAME NET1_HOSTNAME \
	    NET0_IFP_NAME NET0_ADDR_V4 NET0_ADDR_V6 \
	    NET1_IFP_NAME NET1_ADDR_V4 NET1_ADDR_V6\
	    SENDER_TUNNEL_ADDR_V4 SENDER_TUNNEL_ADDR_V6 \
	    RECEIVER_TUNNEL_ADDR_V4 RECEIVER_TUNNEL_ADDR_V6 \
	    ; do
		name=${i}_$j
		x=$(eval "echo \$$name")
		if [[ -n $x && $x != SETME ]] ; then
			eval "export $name";
		fi
	done
done
#
print > config.sh
#
for i in \
    SUT_CTL_HOSTNAME SENDER_CTL_HOSTNAME RECEIVER_CTL_HOSTNAME \
    SUT_CTL_IFP_NAME SENDER_CTL_IFP_NAME RECEIVER_CTL_IFP_NAME \
    SENDER_CTL_IFP_NAME SENDER_NET0_IFP_NAME SENDER_NET1_IFP_NAME \
    SUT_CTL_IFP_NAME SUT_NET0_IFP_NAME SUT_NET1_IFP_NAME \
    SUT_NET0_ADDR_V4 SUT_NET1_ADDR_V4 SUT_NET0_ADDR_V6 SUT_NET1_ADDR_V6 \
    RECEIVER_CTL_IFP_NAME RECEIVER_NET0_IFP_NAME RECEIVER_NET1_IFP_NAME \
    SENDER_NET0_ADDR_V4 SENDER_NET1_ADDR_V4 \
    SENDER_NET0_ADDR_V6 SENDER_NET1_ADDR_V6 \
    RECEIVER_NET0_ADDR_V4 RECEIVER_NET1_ADDR_V4 \
    RECEIVER_NET0_ADDR_V6 RECEIVER_NET1_ADDR_V6 \
    LOG0_FILE LOG1_FILE LOGS_FILE LOGR_FILE \
    RRCP RRSH BIN_IPF BIN_IPFSTAT BIN_IPNAT BIN_IPPOOL BIN_IPMON \
    PING_TRIES PING_SIZE_LARGE PING_SIZE_SMALL \
    TEST_IPF_CONF TEST_IPNAT_CONF TEST_IPPOOL_CONF \
    IPF_LOG_DIR IPF_LOG_FILE IPF_TMP_DIR IPF_BIN_DIR \
    IPF_LIB_DIR IPF_VAR_DIR \
    TCP_TIMEOUT \
    FTP_PATH RCMD_USER \
    SUT_NET0_ADDR_V4_A1 SUT_NET0_ADDR_V4_A2 SUT_NET0_ADDR_V4_A3 \
    SUT_NET0_ADDR_V4_A4 SUT_NET0_ADDR_V4_A5 SUT_NET0_ADDR_V4_A6 \
    SUT_NET0_ADDR_V4_A7 \
    SUT_NET0_ADDR_V6_A1 SUT_NET0_ADDR_V6_A2 SUT_NET0_ADDR_V6_A3 \
    SUT_NET0_ADDR_V6_A4 SUT_NET0_ADDR_V6_A5 SUT_NET0_ADDR_V6_A6 \
    SUT_NET0_ADDR_V6_A7 \
    SUT_NET1_ADDR_V4_A1 SUT_NET1_ADDR_V4_A2 SUT_NET1_ADDR_V4_A3 \
    SUT_NET1_ADDR_V4_A4 SUT_NET1_ADDR_V4_A5 SUT_NET1_ADDR_V4_A6 \
    SUT_NET1_ADDR_V4_A7 \
    SUT_NET1_ADDR_V6_A1 SUT_NET1_ADDR_V6_A2 SUT_NET1_ADDR_V6_A3 \
    SUT_NET1_ADDR_V6_A4 SUT_NET1_ADDR_V6_A5 SUT_NET1_ADDR_V6_A6 \
    SUT_NET1_ADDR_V6_A7 \
    SENDER_NET0_ADDR_V4_A1 SENDER_NET0_ADDR_V4_A2 SENDER_NET0_ADDR_V4_A3 \
    SENDER_NET0_ADDR_V4_A4 SENDER_NET0_ADDR_V4_A5 SENDER_NET0_ADDR_V4_A6 \
    SENDER_NET0_ADDR_V4_A7 \
    SENDER_NET0_ADDR_V6_A1 SENDER_NET0_ADDR_V6_A2 SENDER_NET0_ADDR_V6_A3 \
    SENDER_NET0_ADDR_V6_A4 SENDER_NET0_ADDR_V6_A5 SENDER_NET0_ADDR_V6_A6 \
    SENDER_NET0_ADDR_V6_A7 \
    RECEIVER_NET1_ADDR_V4_A1 RECEIVER_NET1_ADDR_V4_A2 RECEIVER_NET1_ADDR_V4_A3 \
    RECEIVER_NET1_ADDR_V4_A4 RECEIVER_NET1_ADDR_V4_A5 RECEIVER_NET1_ADDR_V4_A6 \
    RECEIVER_NET1_ADDR_V4_A7 \
    RECEIVER_NET1_ADDR_V6_A1 RECEIVER_NET1_ADDR_V6_A2 RECEIVER_NET1_ADDR_V6_A3 \
    RECEIVER_NET1_ADDR_V6_A4 RECEIVER_NET1_ADDR_V6_A5 RECEIVER_NET1_ADDR_V6_A6 \
    RECEIVER_NET1_ADDR_V6_A7 \
    NET0_NET_V4 NET0_NETMASK_V4 NET0_NET_V6 NET0_NETMASK_V6 \
    NET1_NET_V4 NET1_NETMASK_V4 NET1_NET_V6 NET1_NETMASK_V6 \
    NET0_FAKE_ADDR_V4 NET0_FAKE_NET_V4 NET0_FAKE_NETMASK_V4 \
    NET1_FAKE_ADDR_V4 NET1_FAKE_NET_V4 NET1_FAKE_NETMASK_V4 \
    NET0_FAKE_ADDR_V6 NET0_FAKE_NET_V6 NET0_FAKE_NETMASK_V6 \
    NET1_FAKE_ADDR_V6 NET1_FAKE_NET_V6 NET1_FAKE_NETMASK_V6 \
    SENDER_TUNNEL_ADDR_V4 SENDER_TUNNEL_ADDR_V6 \
    RECEIVER_TUNNEL_ADDR_V4 RECEIVER_TUNNEL_ADDR_V6 \
    TUNNEL_NET_V4 TUNNEL_NET_V6 \
	; do
	x=$(eval print \$$i)
	if [[ -n $x ]] ; then
		print "$i=$x; export $i" >> config.sh
	fi
done
