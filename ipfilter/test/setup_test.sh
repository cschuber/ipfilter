#!/bin/sh

if [ -f regress/${todo} ] ; then
	regress=regress/${todo}
else
	if [ -f regress/${todo}.dist ] ; then
		regress=regress/${TESTMODE}/${todo}
	fi
fi
if [ -f regress/${todo}.ipf ] ; then
	regress_ipf=regress/${todo}.ipf
else
	if [ -f regress/${todo}.ipf.dist ] ; then
		regress_ipf=regress/${TESTMODE}/${todo}.ipf
	fi
fi
if [ -f regress/${todo}.nat ] ; then
	regress_nat=regress/${todo}.nat
else
	if [ -f regress/${todo}.nat.dist ] ; then
		regress_nat=regress/${TESTMODE}/${todo}.nat
	fi
fi

if [ -f expected/${todo} ] ; then
	expected=expected/${todo}
else
	if [ -f expected/${todo}.dist ] ; then
		expected=expected/${TESTMODE}/${todo}
	fi
fi

if [ -f input/${todo} ] ; then
	input=input/${todo}
else
	if [ -f input/${todo}.dist ] ; then
		input=input/${TESTMODE}/${todo}
	fi
fi
results=${resdir}/results/${todo}
/bin/cp /dev/null ${results}
