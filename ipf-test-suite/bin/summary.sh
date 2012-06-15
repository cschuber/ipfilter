#!/bin/sh
#
awk '
BEGIN { pass = 0; fail = 0; }
/^RESULT / {
if ($2 == "FAIL") { fail++; }
if ($2 == "PASS") { pass++; }
print $2,$3;
}
END { print "TOTAL: PASS",pass,"FAIL",fail; }
' ${1}
exit $?
