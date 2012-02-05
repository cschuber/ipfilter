#!/bin/sh
#
# (C)opyright 2012 by Darren Reed.
#
# See the IPFILTER.LICENCE file for details on licencing.
#
test_init() {
	todo=`expr ${testitem} : '.*\/\(.*\)$'`
	resdir=`expr ${testitem} : '\(.*\)\/.*$'`
	args=`awk "/^${todo} / { print; } " test.format`

	if [ ! -d ${resdir}/results ] ; then
		mkdir ${resdir}/results
	fi
	if [ ! -d results ] ; then
		mkdir -p results
	fi
	find_touch

	if [ -n "${FINDLEAKS}" -a -x /bin/mdb ] ; then
		_findleaks=1
		_corenum=1
		set_core ${todo} ${_corenum}
	else
		_corenum=0
		_findleaks=0
	fi
}

set_core() {
	unset _corename
	if [ ${_findleaks} = 1 ] ; then
		if [ -x /bin/coreadm ] ; then
			_corename="$1.${_corenum}.core"
			coreadm -p "${PWD}/${_corename}"
		fi
	fi
}

test_end_leak() {
	if [ $1 -ne 0 ] ; then
		if [ ${_findleaks} = 1 -a -f ${_corename} ] ; then
			echo "==== ${todo}:${n} ====" >> leaktest
			echo '::findleaks' | mdb ../i86/ipftest ${_corename} >> leaktest
			rm ${_corename}
		else
			exit 2;
		fi
	fi
}

check_results() {
	cmp ${expected} ${results}
	status=$?
	if [ $status = 0 ] ; then
		${TOUCH} ${resdir}/${todo}
	fi
}

find_touch() {
	if [ -f /bin/touch ] ; then
		TOUCH=/bin/touch
	else
		if [ -f /usr/bin/touch ] ; then
			TOUCH=/usr/bin/touch
		else
			if [ -f /usr/ucb/touch ] ; then
				TOUCH=/usr/ucb/touch
			fi
		fi
	fi
}

next_core() {
	_corenum=`expr ${_corenum} + 1`
	set_core ${todo} ${_corenum}
}
