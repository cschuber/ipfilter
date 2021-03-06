#
ARCH=
PFILDEBUG=-DPFILDEBUG
#
OBJS=pfil.o qif.o pfildrv.o pfilstream.o pkt.o misc.o ndd.o
VPATH=..
DO=xxx
#
HPDEFS=-U__hp9000s700 -DKERNEL -DHPUX_IPFILTER_HOOKS \
-D_KERNEL_BUILD=1 -D__STDC_EXT__ -D_XPG4_EXTENDED -D_HPUX_SOURCE \
-D__hp9000s800 -D_KERNEL
KFLAGS=-Ae +ES1.Xindirect_calls -Wp,-H300000 +XixdU +Hx0 +R500 \
-Wl,-a,archive +ESsfc -q +DD`getconf KERNEL_BITS` $(PFILDEBUG)
HINC=-I.. -I. -I/usr/conf/gen
HPUXREV="`uname -r | sed -e 's/^[A-Z]\.\([0-9]*\)\.\([0-9]\)/\1\2/'`"
HFLAGS=${HINC} ${HPDEFS} -DHPUXREV=${HPUXREV}
DEPOT=PFIL.v2.1.8.depot
DEPOTDIR=/var/spool/sw
HBITS=`getconf KERNEL_BITS`
#
SOLARIS="`uname -r | sed -e 's/[0-9]*\.\([0-9]*\).*/\1/'`"
SFLAGS=-I.. -I. -D_KERNEL -DSUNDDI -DSOLARIS2=${SOLARIS} $(PFILDEBUG)
SBITS:sh=optisa sparcv9 >/dev/null 2>&1; if [ "$?" -eq 0 ] ; then echo "64"; else echo "32"; fi
MIOCPULLUP:sh=/usr/ccs/bin/nm -p /dev/ksyms|/usr/xpg4/bin/grep -q miocpullup; if [ "$?" -ne 0 ] ; then echo -DNEED_MIOCPULLUP; fi
# For Sun's C compiler in /opt/SUNWSpro cc:
S64FLAGS=-xildoff -xarch=v9 -xchip=ultra -dalign -xcode=abs32 -DDO=pfil${SBITS}
# For GCC
#S64FLAGS=-m64 -mcmodel=medlow -DDO=pfil${SBITS}
#
TMP=/tmp
PKG=pfil

all:
	i=`uname -s`; case $$i in HP-UX) make hpux;; *) make $$i;; esac

quick:
	cp Makefile `uname -s`
	make `uname -s`

HP-UX hpux: HP-UX/Makefile
	if [ ! -f HP-UX/Makefile ] ; then ln Makefile HP-UX; fi
	(cd HP-UX; make mod.o "BITS=${HBITS}" OS=hpux DO=pfil "ADEF=${HFLAGS} ${KFLAGS}")

SunOS: SunOS/Makefile
	-make SunOS${SBITS}

SunOS32: SunOS/Makefile
	(cd SunOS; make pfil "BITS=32" OS=solaris DO=pfil "ADEF=${SFLAGS}")

SunOS64 sparc64 sunos64: SunOS/Makefile
	(cd SunOS; make pfil "BITS=32" OS=solaris DO=pfil "ADEF=${SFLAGS}")
	/bin/rm -f SunOS/*.o
	(cd SunOS; make pfil${SBITS} "BITS=64" OS=solaris DO=pfil64 "ADEF=${SFLAGS} ${S64FLAGS}")
	touch SunOS/pfil32

$(DO): $(OBJS)
	ld -r $(OBJS) -o pfil${BITS}

mod.o: $(OBJS)
	ld -r $(OBJS) -o $@

.c.o:
	$(CC) $(ARCH) $(CFLAGS) $(ADEF) -c $< -o $@

pfildrv.o: pfildrv.c
	$(CC) $(ARCH) $(CFLAGS) $(ADEF) $(MIOCPULLUP) -c $< -o $@

clean:
	/bin/rm -rf $(TMP)/$(PKG) */Makefile
	/bin/rm -f HP-UX/*.o HP-UX/mod.o HP-UX/pfil.pkg HP-UX/pfil.psf
	/bin/rm -f SunOS/*.o SunOS/pfil SunOS/pfil32 SunOS/pfil64
	/bin/rm -f SunOS/pkginfo SunOS/prototype SunOS/*.ln
	(for i in *.c; do /bin/rm -f */$$i; done)

depend:
	if [ -z "${OS}" ] ; then make OS=`uname -s` depend-os; fi

depend-os:
	make depend-${OS}

depend-SunOS SunOS/Makefile:
	cp Makefile SunOS
#	(cd SunOS; ln -s ../*.c .; )
#	(cd SunOS; makedepend ${SFLAGS} *.c)

depend-HP-UX HP-UX/Makefile:
	/bin/cp Makefile HP-UX
	(cd HP-UX; makedepend ${HINC} ${HPDEFS} *.c)
	mv HP-UX/Makefile HP-UX/Makefile.bak
	sed -e 's/DO NOT DELETE/DO_NOT_DELETE/' HP-UX/Makefile.bak > HP-UX/Makefile
	/bin/rm -f HP-UX/Makefile.bak
	makedepend -fHP-UX/Makefile -IHP-UX "${HFLAGS}" *.c

install: all
	(cd `uname -s`; make install-`uname -s`)

package: all
	(cd `uname -s`; make package-`uname -s`)

install-SunOS: package-SunOS
	pkgadd -d $(TMP)/pfil.pkg

package-SunOS: $(DO)
	/bin/rm -f copyright
	ln -s ../copyright .
	(x=`date '+%T %D'`; sed -e "s@RELEASE_DATE@$$x@" \
			-e "s/ARCH=.*/ARCH=`uname -p`/" \
				 pkginfo.dist > pkginfo)
	cat prototype.dist > prototype
	if [ -f pfil64 ] ; then \
		echo 'd none kernel/strmod/sparcv9 ? root sys' >> prototype; \
		echo 'l none kernel/strmod/sparcv9/pfil=../../drv/sparcv9/pfil' >> prototype; \
		echo 'd none kernel/drv/sparcv9 ? root sys' >> prototype; \
		echo 'f none kernel/drv/sparcv9/pfil=pfil64 ? root sys' >> prototype; \
	fi
	pkgmk -o -d $(TMP)
	pkgtrans -s $(TMP) pfil.pkg $(PKG)

install-HP-UX: package-HP-UX
	swinstall -s `pwd`/pfil.pkg -x reinstall=true PFIL-RUN

package-HP-UX:
	sed -e "s/HPREV/`uname -r`/g" pfil.psf.dist > pfil.psf
	swpackage -x media_type=tape -s pfil.psf @ /tmp/${DEPOT}
	mv /tmp/${DEPOT} pfil.pkg

do-cvs:
	find . -type d -name CVS -print | xargs /bin/rm -rf
	find . -type f -name .cvsignore -print | xargs /bin/rm -f

#
# This is here because the Sun "makedepend" breaks on some platforms.
# Furthermore, Sun's make sets $< wrong for "foo.o: ../foo.c"
#
misc.o: ../misc.c ../compat.h os.h
	$(CC) $(ARCH) $(CFLAGS) $(ADEF) -c ../misc.c -o $@
pfil.o: ../pfil.c ../pfil.h ../compat.h os.h
	$(CC) $(ARCH) $(CFLAGS) $(ADEF) -c ../pfil.c -o $@
pfildrv.o: pfildrv.c ../qif.h ../pfil.h ../compat.h os.h
pfilstream.o: ../pfilstream.c ../pfil.h ../qif.h ../compat.h os.h
	$(CC) $(ARCH) $(CFLAGS) $(ADEF) -c ../pfilstream.c -o $@
pkt.o: pkt.c ../compat.h os.h
qif.o: qif.c ../qif.h ../pfil.h ../compat.h os.h
sum.o: ../sum.c ../compat.h os.h
	$(CC) $(ARCH) $(CFLAGS) $(ADEF) -c ../sum.c -o $@
ndd.o: ../ndd.c ../compat.h os.h
	$(CC) $(ARCH) $(CFLAGS) $(ADEF) -c ../ndd.c -o $@
