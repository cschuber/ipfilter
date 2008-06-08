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
TOP=..
CFLAGS+=-I$(TOP) -I.
SO_CFLAGS=$(CFLAGS) -fPIC -shared

IPFOBJSO=npf_ipf_fw_rule_to_frentry.o npf_ipf_setv6mask.o \
	 npf_s_fini_lib.o npf_s_init_lib.o \
	 npf_s_nat_lookup_rdr.o
#	 npf_s_delete_filter_rule.o npf_s_delete_nat_rule.o \
#	 npf_s_find_nat_rule.o npf_s_getnext_nat_rule.o \
#	 npf_s_insert_filter_rule.o npf_s_insert_nat_rule.o \

IPFOBJS_SO=npf_ipf_fw_rule_to_frentry.so npf_ipf_setv6mask.so \
	  npf_s_fini_lib.so npf_s_init_lib.so \
	  npf_s_nat_lookup_rdr.so
#	  npf_s_delete_filter_rule.so npf_s_delete_nat_rule.so \
#	  npf_s_find_nat_rule.so npf_s_getnext_nat_rule.so \
#	  npf_s_insert_filter_rule.so npf_s_insert_nat_rule.so \

all: libnpf_ipf.a libnpf_ipf.so

libnpf_ipf.a: $(IPFOBJSO)
	ar cq $@ $(IPFOBJSO)

libnpf_ipf.so: $(IPFOBJS_SO)
	ld -shared $(IPFOBJS_SO) -o $@

npf_ipf_fw_rule_to_frentry.o: npf_ipf_fw_rule_to_frentry.c $(TOP)/npf.h \
			      npf_ipf.h
	$(CC) $(CFLAGS) -c npf_ipf_fw_rule_to_frentry.c -o $@

npf_ipf_setv6mask.o: npf_ipf_setv6mask.c $(TOP)/npf.h npf_ipf.h
	$(CC) $(CFLAGS) -c npf_ipf_setv6mask.c -o $@

npf_s_nat_lookup_rdr.o: npf_s_nat_lookup_rdr.c $(TOP)/npf.h npf_ipf.h
	$(CC) $(CFLAGS) -c npf_s_nat_lookup_rdr.c -o $@

npf_s_fini_lib.o: npf_s_fini_lib.c $(TOP)/npf.h npf_ipf.h
	$(CC) $(CFLAGS) -c npf_s_fini_lib.c -o $@

npf_s_init_lib.o: npf_s_init_lib.c $(TOP)/npf.h npf_ipf.h
	$(CC) $(CFLAGS) -c npf_s_init_lib.c -o $@

npf_ipf_fw_rule_to_frentry.so: npf_ipf_fw_rule_to_frentry.c $(TOP)/npf.h \
			       npf_ipf.h
	$(CC) $(SO_CFLAGS) -c npf_ipf_fw_rule_to_frentry.c -o $@

npf_ipf_setv6mask.so: npf_ipf_setv6mask.c $(TOP)/npf.h npf_ipf.h
	$(CC) $(SO_CFLAGS) -c npf_ipf_setv6mask.c -o $@

npf_s_nat_lookup_rdr.so: npf_s_nat_lookup_rdr.c $(TOP)/npf.h npf_ipf.h
	$(CC) $(SO_CFLAGS) -c npf_s_nat_lookup_rdr.c -o $@

npf_s_fini_lib.so: npf_s_fini_lib.c $(TOP)/npf.h npf_ipf.h
	$(CC) $(CFLAGS) -c npf_s_fini_lib.c -o $@

npf_s_init_lib.so: npf_s_init_lib.c $(TOP)/npf.h npf_ipf.h
	$(CC) $(CFLAGS) -c npf_s_init_lib.c -o $@

clean:
	/bin/rm -f *.o *.a *.so
