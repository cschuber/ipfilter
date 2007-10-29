#
# Copyright (c) 2007
#      Darren Reed.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $Id$
#
CFLAGS+=-I. -Wall -Werror
SO_CFLAGS=$(CFLAGS) -fPIC -shared

all: src

include src.d/Makefile.o
include src.d/Makefile.so

NPFOBJSO=$(O_D)

NPFOBJS_SO=$(SO_D)

src:
	(cd src.d; make)
	make build

build: libnpf.a libnpf.so test1 test2
	(cd ipf; make)
	/bin/rm -f libnpf_ipf.a
	ln -s ipf/libnpf_ipf.a .
	/bin/rm -f libnpf_ipf.so
	ln -s ipf/libnpf_ipf.so .

clean:
	/bin/rm -f o.d/*.o o.d/*.a so.d/*.so test1 test2
	/bin/rm -f ipf/*.o ipf/*.so ipf/*.a
	/bin/rm -f *.o *.a *.so
	(cd src.d; make clean)

libnpf.a: $(NPFOBJSO)
	ar cq $@ $(NPFOBJSO)

libnpf.so: $(NPFOBJS_SO)
	ld -shared $(NPFOBJS_SO) -o $@

test1: src.d/test.c libnpf.a
	$(CC) -static -g -I. src.d/test.c -o test1 -L. -lnpf

test2: src.d/test.c libnpf.so
	$(CC) -dy -g -I. src.d/test.c -o test2 -L. -lnpf
