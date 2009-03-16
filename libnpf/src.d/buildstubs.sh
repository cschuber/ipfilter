#!/bin/sh
#
# $Id$
#

make_file() {
	base=$1
	proto=`sed -n -e "/extern .*$base/s/[^(]*(\(.*\)).*/\1/p" ../npf.h`
	old="$proto"
	count=0
	new=""
	while [ -n "$old" ] ; do
		o1=`echo "$old" | sed -n -e '/,/s/^\([^,]*,\).*/\1/p'`
		if [ -z "$o1" ] ; then
			o1=$old
			old=""
		else
			o2=`echo "$o1" | sed -e 's/\\*/\\\\\*/g'`
			old=`echo "$old" | sed -n -e "s/^$o2//p"`
		fi
		o1=`echo "$o1" | sed -e "s/,/ arg$count,/"`
		new="$new$o1"
		count=`expr $count + 1`
	done
	new="${new}arg${count}"

	if [ -f npf_s_$base.c ] ; then
		file=`find npf_s_$base.c -newer ../npf.h`
		if [ ! -z $file ] ; then
			file=""
		else
			file=npf_s_$base.c
		fi
	else
		file=npf_s_$base.c
	fi

	if [ ! -z $file ] ; then
		echo "Creating npf_s_$base.c"
		cat <<__EOF__ > npf_s_$base.c
#include <npf.h>

int
npf_s_$base(npf_handle_t *handle, void *param, const char *options)
{
	return (-1);
}
__EOF__
	fi

	if [ -f npf_$base.c ] ; then
		file=`find npf_$base.c -newer ../npf.h`
		if [ ! -z $file ] ; then
			file=""
		else
			file=npf_$base.c
		fi
	else
		file=npf_$base.c
	fi

	if [ ! -z $file ] ; then
		type=`awk "/extern int npf_$base/ { print \\\$5; } " ../npf.h`
		if [ ! -z $type ] ; then
			echo "Creating npf_$base.c"
			cat <<__EOF__ > npf_$base.c
#include <npf.h>

int
npf_$base(npf_handle_t *handle, $type *param, const char *options)
{
	return (handle->$base(handle, param, options));
}
__EOF__
		fi
	fi
}

IMPL=`sed -n -e '/^extern /s/^.*npf_\([fwnat]*_[^(]*\)(.*/\1/p' ../npf.h`

LIST="$IMPL
init_lib \
fini_lib \
"

BASE=`sed -n -e '/^extern /s/^.*npf_\([^(]*\)(.*/\1/p' ../npf.h | egrep -v '^nat_|^fw_'`
PRIVATE="$BASE
s_init_lib \
s_fini_lib \
"

if [ $# -eq 0 ] ; then
	for i in $LIST; do
		make_file $i
	done
else
	while [ $# -gt 0 ] ; do
		if [ $1 = clean ] ; then
			for i in $LIST; do
				/bin/rm -f npf_s_$i.c npf_$i.c
			done
		else
			make_file $1
		fi
		shift
	done
fi

echo '#' > Makefile.o
echo 'O_D=' >> Makefile.o
for i in $PRIVATE; do
	cat << __EOF__ >> Makefile.o
O_D+= o.d/npf_${i}.o
o.d/npf_${i}.o: src.d/npf_${i}.c npf.h
	\$(CC) \$(CFLAGS) -g -c src.d/npf_${i}.c -o \$@
__EOF__
done

echo '#' > Makefile.so
echo 'SO_D=' >> Makefile.so
for i in $PRIVATE; do
	cat << __EOF__ >> Makefile.so
SO_D+= so.d/npf_${i}.so
so.d/npf_${i}.so: src.d/npf_${i}.c npf.h
	\$(CC) \$(SO_CFLAGS) -g -c src.d/npf_${i}.c -o \$@
__EOF__
done
for i in $LIST; do
	case $i in
	*lib)
		;;
	*)
		echo "O_D+= o.d/npf_${i}.o" >> Makefile.o
		echo "SO_D+= so.d/npf_${i}.so" >> Makefile.so
		;;
	esac
done
echo '#' >> Makefile.o
echo '#' >> Makefile.so
for i in $LIST; do
	cat <<__EOF__ >> Makefile.o
o.d/npf_${i}.o: src.d/npf_${i}.c npf.h
	\$(CC) \$(CFLAGS) -c src.d/npf_${i}.c -o \$@
__EOF__
	cat <<__EOF__ >> Makefile.so
so.d/npf_${i}.so: src.d/npf_${i}.c npf.h
	\$(CC) \$(SO_CFLAGS) -c src.d/npf_${i}.c -o \$@
__EOF__
done
exit 0
