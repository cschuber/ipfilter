#!/bin/ksh
PATH=/sbin:/usr/sbin:${PATH}
os=$(uname -s)
cmd=$1
shift

if [[ $cmd = flush ]] ; then
	case $os in
	SunOS)
		print "Cmd: route -f 2>&1"
		exec route -f 2>&1
		;;
	*BSD)
		print "Cmd: route flush 2>&1"
		exec route flush 2>&1
		;;
	esac
fi
family=$1
shift
what=$1
shift
target=$1
shift
mod=$1
if [[ "$mod" = "-netmask" ]] ; then
	print "Cmd: route $cmd $family $what $target $@ 2>&1"
	exec route $cmd $family $what $target $@ 2>&1
else
	if [[ "$mod" = "-prefixlen" ]] ; then
		shift
		case $os in
		SunOS)
			mask=$1
			shift
			print "Cmd: route $cmd $family $what $target/$mask $@ 2>&1"
			exec route $cmd $family $what $target/$mask $@ 2>&1
			;;
		*BSD)
			print "Cmd: route $cmd $family $what $target $mod $@ 2>&1"
			exec route $cmd $family $what $target $mod $@ 2>&1
		esac
	else
		print "Cmd: route $cmd $family $what $target $@ 2>&1"
		exec route $cmd $family $what $target $@ 2>&1
	fi
fi
exit 1
