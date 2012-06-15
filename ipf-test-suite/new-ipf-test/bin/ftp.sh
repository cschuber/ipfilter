#!/bin/ksh
#
# Both active and passive FTP are tested.
#
PATH=/usr/local/bin:/usr/bin:/bin:/usr/pkg/bin:/usr/sfw/bin:/opt/sfw/bin
#
WGETOPTS="-d -t 1 -T 3 -O /dev/null"

case $1 in
*:*)
	wget="wget -6"
	addr="[$1]"
	;;
*)
	wget="wget -4"
	addr="$1"
	;;
esac
#
URL=ftp://${addr}${2}

FTP_OUTPUT=${3}/ftp.out
echo "PASSIVE FTP download test"
echo "${wget} ${WGETOPTS} ${URL} > ${FTP_OUTPUT}"
${wget} ${WGETOPTS} ${URL} >${FTP_OUTPUT} 2>&1
if [[ $? -ne 0 ]] ; then
	cat ${FTP_OUTPUT}
	echo "FAIL passive ftp downloaded ${URL}"
	exit 1
fi
echo "ACTIVE FTP download test"
echo "${wget} --no-passive-ftp ${WGETOPTS} ${URL} >> ${FTP_OUTPUT}"
${wget} --no-passive-ftp ${WGETOPTS} ${URL} >> ${FTP_OUTPUT} 2>&1
if [[ $? -ne 0 ]] ; then
	cat ${FTP_OUTPUT}
	echo "FAIL active ftp downloaded ${URL}"
	exit 1
fi
cat ${FTP_OUTPUT}
echo "PASS ftp downloaded ${URL}"
exit 0
