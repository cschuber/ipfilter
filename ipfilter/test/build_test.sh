#!/bin/sh
NIC0=nic0
NIC1=nic1
NIC2=nic2
NIC3=nic3
RESDIR=user
export NIC0 NIC1 NIC2 NIC3 RESDIR

mkdir -p input/${RESDIR} expected/${RESDIR} regress/${RESDIR}

findfile () {
	eval `echo ${1}_target=$1/$2`
	if [ -f $1/$2 ]; then
		eval `echo $1=$1/$2`
		eval `echo ${1}_result=$1/${RESDIR}/$2`
	else
		if [ -f $1/$2.dist ] ; then
			eval `echo $1=$1/$2.dist`
			eval `echo ${1}_result=$1/${RESDIR}/$2`
		else
			eval `echo $1=_`
			if [ -f $1/$2.ipf.dist ] ; then
				eval `echo ${1}_ipf=$1/$2.ipf.dist`
				eval `echo ${1}_ipf_result=$1/${RESDIR}/$2`
			fi
			if [ -f $1/$2.nat.dist ] ; then
				eval `echo ${1}_nat=$1/$2.nat.dist`
				eval `echo ${1}_nat_result=$1/${RESDIR}/$2`
			fi
		fi
	fi
}

sedfile() {
	sed \
	    -e "s/NIC0HEXADDR/${NIC0HEXADDR}/g" \
	    -e "s/NIC1HEXADDR/${NIC1HEXADDR}/g" \
	    -e "s/NIC0ADDR/${NIC0ADDR}/g" \
	    -e "s/NIC1ADDR/${NIC1ADDR}/g" \
	    -e "s/NIC0/${NIC0}/g" \
	    -e "s/NIC1/${NIC1}/g" \
	    -e "s/NIC2/${NIC2}/g" \
	    -e "s/NIC3/${NIC3}/g" \
	    -e 's/_/ /g' ${1} > ${2}
}

cksumfile() {
	if [ -z "${1}" ] ; then
		return
	fi
	if [ -f ${1} ] ; then
		sums=`grep CKSUM ${1} | wc -l`
		if [ $sums -gt 0 ] ; then
			mv ${1} ${1}.tmp
			perl ./fillcksum.pl ${1}.tmp > ${1}
		fi
	fi
}

fixfile() {
	if [ -f ${1} -a ${1} = ${2} ] ; then
		return
	fi
	if [ -n "${1}" -a -n "${3}" ] ; then
		x=`find ${1} -newer ${3}`
		if [ -z "${x}" ] ; then
			return
		fi
	fi

	if [ -n "${4}" -a -n "${5}" ] ; then
		if [ -f ${4} ]; then
			sedfile ${4} ${5}
		fi
	fi

	if [ -n "${6}" -a -n "${7}" ] ; then
		if [ -f ${6} ]; then
			sedfile ${6} ${7}
		fi
	fi

	if [ ${1} != _ -a ${2} != ${1} ] ; then
		sedfile ${1} ${3}
	fi

	cksumfile $2
	cksumfile $3
}

fixtest() {
	findfile expected $1
	findfile input $1
	findfile regress $1

	if [ -f ${input} ]; then
		nics=`sed -n -e 's/^\[.*,\(.*=[^]]*\).*/\1/p' ${input}`
	else
		nics=""
	fi

	if [ -n "${nics}" ] ; then
		SIFS=$IFS
		IFS='='
		set $nics
		IFS=$SIFS
		while [ $# -gt 0 ] ; do
			name=$1
			addr=$2
			shift
			shift
			hex=`echo ${addr} | awk -F. ' { printf "%02x%02x %02x%02x", $1, $2, $3, $4; } ' -`
			eval `echo ${name}HEXADDR='$hex'`
			eval `echo ${name}ADDR=${addr}_____________| \
			      sed -e 's/^\(........................\).*/\1/'`
		done
	fi

	fixfile ${expected} ${expected_target} ${expected_result} \
		${expected_ipf} ${expected_ipf_result} \
		${expected_nat} ${expected_nat_result}
	if [ ${input} != _ ] ; then
		fixfile ${input} ${input_target} ${input_result} \
			${input_ipf} ${input_ipf_result} \
			${input_nat} ${input_nat_result}
	fi
	fixfile ${regress} ${regress_target} ${regress_result} \
		${regress_ipf} ${regress_ipf_result} \
		${regress_nat} ${regress_nat_result}
}

echo "Fixing $1"
fixtest $1
exit 0

+ fixfile _ regress/p1
+ set -x
+ [ -f _ -a _ = regress/p1 ]
+ [ -f _ -a -f ]

