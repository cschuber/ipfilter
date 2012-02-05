#
# (C)opyright 1993-1996 by Darren Reed.
#
# See the IPFILTER.LICENCE file for details on licencing.
#
POOLDEP=../ip_lookup.c ../ip_lookup.h ../ip_pool.c ../ip_pool.h \
	../ip_htable.c ../ip_htable.h ../ip_dstlist.c ../ip_dstlist.h \
	../tools/ippool_y.y
BINDEST=/usr/local/bin
SBINDEST=/sbin
MANDIR=/usr/share/man
RESDIR=user
TESTMODE=user
all: usersetup.d results
	make tests RESDIR=user TESTMODE=user NIC0=nic0 NIC1=nic1 NIC2=nic2 NIC3=nic3 NIC0ADDR="192.168.1.188__" NIC0HEXADDR="c0a8 01bc" NIC0ADDR6="c0a8:100::bc" NIC0HEXADDR6="c0a8 0100 0000 0000 0000 0000 0000 00bc"

usersetup.d:
	make setup.d RESDIR=user

setup.d:
	mkdir -p $(RESDIR) expected/$(RESDIR) input/$(RESDIR) regress/$(RESDIR)

#	for i in `egrep '^[a-z]' test.format | cut -f1 -d' '`; do \
#		perl ./build_test.pl all $${i}; \
#	done

results:
	mkdir -p results

tests: ipf nat logtests ipv6 pools

ipf: p_tests ftests

nat: in_tests ntests nitests

first:
	-mkdir -p results

kerntests:
	make setup.d
	make ftests RESDIR=kern TESTMODE=kern
	make ntests RESDIR=kern TESTMODE=kern
	make nitests RESDIR=kern TESTMODE=kern
	make ipv6 RESDIR=kern TESTMODE=kern

kernsetup.d:
	make RESDIR=kern NIC0=$(NIC0) NIC1=$(NIC1) NIC2=$(NIC2) NIC3=$(NIC3) setup.d

#
# IPv4 filtering tests
#
ftests: \
	$(RESDIR)/f1 \
	$(RESDIR)/f2 \
	$(RESDIR)/f3 \
	$(RESDIR)/f4 \
	$(RESDIR)/f5 \
	$(RESDIR)/f6 \
	$(RESDIR)/f7 \
	$(RESDIR)/f8 \
	$(RESDIR)/f9 \
	$(RESDIR)/f10 \
	$(RESDIR)/f11 \
	$(RESDIR)/f12 \
	$(RESDIR)/f13 \
	$(RESDIR)/f14 \
	$(RESDIR)/f15 \
	$(RESDIR)/f17 \
	$(RESDIR)/f18 \
	$(RESDIR)/f19 \
	$(RESDIR)/f21 \
	$(RESDIR)/f22 \
	$(RESDIR)/f24 \
	$(RESDIR)/f25 \
	$(RESDIR)/f26 \
	$(RESDIR)/f27 \
	$(RESDIR)/f28 \
	$(RESDIR)/f29 \
	$(RESDIR)/f30

#
# ipf rule parsing tests
#
p_tests: \
	$(RESDIR)/i1 \
	$(RESDIR)/i2 \
	$(RESDIR)/i3 \
	$(RESDIR)/i4 \
	$(RESDIR)/i5 \
	$(RESDIR)/i6 \
	$(RESDIR)/i7 \
	$(RESDIR)/i8 \
	$(RESDIR)/i9 \
	$(RESDIR)/i10 \
	$(RESDIR)/i11 \
	$(RESDIR)/i12 \
	$(RESDIR)/i13 \
	$(RESDIR)/i14 \
	$(RESDIR)/i15 \
	$(RESDIR)/i16 \
	$(RESDIR)/i17 \
	$(RESDIR)/i18 \
	$(RESDIR)/i19 \
	$(RESDIR)/i20 \
	$(RESDIR)/i21 \
	$(RESDIR)/i22 \
	$(RESDIR)/i23

#
# Basic testing of NAT
#
ntests: \
	$(RESDIR)/n1 \
	$(RESDIR)/n2 \
	$(RESDIR)/n3 \
	$(RESDIR)/n4 \
	$(RESDIR)/n5 \
	$(RESDIR)/n6 \
	$(RESDIR)/n7 \
	$(RESDIR)/n8 \
	$(RESDIR)/n9 \
	$(RESDIR)/n10 \
	$(RESDIR)/n11 \
	$(RESDIR)/n12 \
	$(RESDIR)/n13 \
	$(RESDIR)/n14 \
	$(RESDIR)/n15 \
	$(RESDIR)/n16 \
	$(RESDIR)/n17 \
	$(RESDIR)/n18 \
	$(RESDIR)/n100 \
	$(RESDIR)/n101 \
	$(RESDIR)/n102 \
	$(RESDIR)/n103 \
	$(RESDIR)/n104 \
	$(RESDIR)/n105 \
	$(RESDIR)/n106 \
	$(RESDIR)/n200 \
	$(RESDIR)/n201

#
# Basic IPv6 NAT tests
#
ntests6: \
	$(RESDIR)/n1_6 \
	$(RESDIR)/n2_6 \
	$(RESDIR)/n4_6 \
	$(RESDIR)/n5_6 \
	$(RESDIR)/n6_6 \
	$(RESDIR)/n7_6 \
	$(RESDIR)/n8_6 \
	$(RESDIR)/n9_6 \
	$(RESDIR)/n11_6 \
	$(RESDIR)/n12_6 \
	$(RESDIR)/n15_6

#
# Tests combining ipf rules with NAT
#
nitests: \
	$(RESDIR)/ni1 \
	$(RESDIR)/ni2 \
	$(RESDIR)/ni3 \
	$(RESDIR)/ni4 \
	$(RESDIR)/ni5 \
	$(RESDIR)/ni6 \
	$(RESDIR)/ni7 \
	$(RESDIR)/ni8 \
	$(RESDIR)/ni9 \
	$(RESDIR)/ni10 \
	$(RESDIR)/ni11 \
	$(RESDIR)/ni12 \
	$(RESDIR)/ni13 \
	$(RESDIR)/ni14 \
	$(RESDIR)/ni15 \
	$(RESDIR)/ni16 \
	$(RESDIR)/ni17 \
	$(RESDIR)/ni18 \
	$(RESDIR)/ni19 \
	$(RESDIR)/ni20 \
	$(RESDIR)/ni21 \
	$(RESDIR)/ni23

#
# NAT parser testing
#
in_tests: \
	$(RESDIR)/in1 \
	$(RESDIR)/in2 \
	$(RESDIR)/in3 \
	$(RESDIR)/in4 \
	$(RESDIR)/in5 \
	$(RESDIR)/in6 \
	$(RESDIR)/in7 \
	$(RESDIR)/in8 \
	$(RESDIR)/in100 \
	$(RESDIR)/in101 \
	$(RESDIR)/in102

logtests: \
	$(RESDIR)/l1

pools: \
	$(RESDIR)/p1 \
	$(RESDIR)/p2 \
	$(RESDIR)/p3 \
	$(RESDIR)/p4 \
	$(RESDIR)/p5 \
	$(RESDIR)/p6 \
	$(RESDIR)/p7 \
	$(RESDIR)/p9 \
	$(RESDIR)/p10 \
	$(RESDIR)/p11 \
	$(RESDIR)/p12 \
	$(RESDIR)/p13 \
	$(RESDIR)/ip1 \
	$(RESDIR)/ip2 \
	$(RESDIR)/ip3

ipv6: \
	$(RESDIR)/ipv6_1 \
	$(RESDIR)/ipv6_2 \
	$(RESDIR)/ipv6_3 \
	$(RESDIR)/ipv6_4 \
	$(RESDIR)/ipv6_5 \
	$(RESDIR)/ipv6_6 \
	ntests6

bpf: \
	$(RESDIR)/bpf1 \
	$(RESDIR)/bpf-f1

$(RESDIR)/f1: expected/f1 input/f1 regress/f1
	@/bin/sh ./f_test $@ $(TESTMODE)

$(RESDIR)/f2: expected/f2 input/f2 regress/f2
	@/bin/sh ./f_test $@ $(TESTMODE)

$(RESDIR)/f3: expected/f3 input/f3 regress/f3
	@/bin/sh ./f_test $@ $(TESTMODE)

$(RESDIR)/f4: expected/f4 input/f4 regress/f4
	@/bin/sh ./f_test $@ $(TESTMODE)

$(RESDIR)/f5: expected/f5 input/f5 regress/f5
	@/bin/sh ./f_test $@ $(TESTMODE)

$(RESDIR)/f6: expected/f6 input/f6 regress/f6
	@/bin/sh ./f_test $@ $(TESTMODE)

$(RESDIR)/f7: expected/f7 input/f7 regress/f7
	@/bin/sh ./f_test $@ $(TESTMODE)

$(RESDIR)/f8: expected/f8 input/f8 regress/f8
	@/bin/sh ./f_test $@ $(TESTMODE)

$(RESDIR)/f9: expected/f9 input/f9 regress/f9
	@/bin/sh ./f_test $@ $(TESTMODE)

$(RESDIR)/f10: expected/f10 input/f10 regress/f10
	@/bin/sh ./f_test $@ $(TESTMODE)

$(RESDIR)/f11: expected/$(RESDIR)/f11 input/$(RESDIR)/f11 regress/$(RESDIR)/f11
	@/bin/sh ./f_test $@ $(TESTMODE)

$(RESDIR)/f12: expected/f12 input/f12 regress/f12
	@/bin/sh ./f_test $@ $(TESTMODE)

$(RESDIR)/f13: expected/f13 input/f13 regress/f13
	@/bin/sh ./f_test $@ $(TESTMODE)

$(RESDIR)/f14: expected/f14 input/f14 regress/f14
	@/bin/sh ./f_test $@ $(TESTMODE)

$(RESDIR)/f15: expected/f15 input/$(RESDIR)/f15 regress/$(RESDIR)/f15
	@/bin/sh ./f_m_test $@ $(TESTMODE)

$(RESDIR)/f17: expected/f17 input/$(RESDIR)/f17 regress/$(RESDIR)/f17
	@/bin/sh ./f_m_test $@ $(TESTMODE)

$(RESDIR)/f18: expected/f18 input/$(RESDIR)/f18 regress/f18
	@/bin/sh ./f_m_test $@ $(TESTMODE)

$(RESDIR)/f19: expected/f19 input/f19 regress/f19
	@/bin/sh ./f_test $@ $(TESTMODE)

$(RESDIR)/f21: expected/f21 input/$(RESDIR)/f21 regress/f21
	@/bin/sh ./f_m_test $@ $(TESTMODE)

$(RESDIR)/f22: expected/f22 input/f22 regress/f22
	@/bin/sh ./f_m_test $@ $(TESTMODE)

$(RESDIR)/f24: expected/f24 input/$(RESDIR)/f24 regress/f24
	@/bin/sh ./f_m_test $@ $(TESTMODE)

$(RESDIR)/f25: expected/$(RESDIR)/f25 input/$(RESDIR)/f25 regress/$(RESDIR)/f25
	@/bin/sh ./f_m_test $@ $(TESTMODE)

$(RESDIR)/f26: expected/f26 input/f26 regress/f26
	@/bin/sh ./f_test $@ $(TESTMODE)

$(RESDIR)/f27: expected/f27 input/$(RESDIR)/f27 regress/f27
	@/bin/sh ./f_test $@ $(TESTMODE)

$(RESDIR)/f28: expected/$(RESDIR)/f28 input/$(RESDIR)/f28 regress/$(RESDIR)/f28.ipf regress/f28.pool \
	    $(POOLDEP)
	@/bin/sh ./p_test $@ $(TESTMODE)

$(RESDIR)/f29: expected/$(RESDIR)/f29 input/$(RESDIR)/f29 regress/$(RESDIR)/f29.ipf regress/f29.pool \
	    $(POOLDEP)
	@/bin/sh ./p_test $@ $(TESTMODE)

$(RESDIR)/f30: expected/f30 input/$(RESDIR)/f30 regress/$(RESDIR)/f30
	@/bin/sh ./f_test $@ $(TESTMODE)

$(RESDIR)/i1: expected/i1 regress/i1
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i2: expected/i2 regress/i2
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i3: expected/i3 regress/i3
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i4: expected/i4 regress/i4
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i5: expected/i5 regress/i5
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i6: expected/i6 regress/i6
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i7: expected/i7 regress/i7
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i8: expected/i8 regress/i8
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i9: expected/i9 regress/i9
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i10: expected/i10 regress/i10
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i11: expected/i11 regress/i11
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i12: expected/i12 regress/i12
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i13: expected/i13 regress/i13
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i14: expected/i14 regress/i14
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i15: expected/i15 regress/i15
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i16: expected/i16 regress/i16
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i17: expected/i17 regress/i17
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i18: expected/i18 regress/i18
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i19: expected/i19 regress/i19
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i20: expected/i20 regress/i20
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i21: expected/i21 regress/i21
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i22: expected/i22 regress/i22
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/i23: expected/i23 regress/i23
	@/bin/sh ./i_test $@ $(TESTMODE)

$(RESDIR)/bpf1: expected/bpf1 regress/bpf1
	@/bin/sh ./bpf_test $@ $(TESTMODE)

$(RESDIR)/n1: expected/$(RESDIR)/n1 regress/$(RESDIR)/n1 input/$(RESDIR)/n1
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n2: expected/$(RESDIR)/n2 regress/$(RESDIR)/n2 input/$(RESDIR)/n2
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n3: expected/$(RESDIR)/n3 regress/$(RESDIR)/n3 input/$(RESDIR)/n3
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n4: expected/$(RESDIR)/n4 regress/$(RESDIR)/n4 input/$(RESDIR)/n4
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n5: expected/$(RESDIR)/n5 regress/$(RESDIR)/n5 input/$(RESDIR)/n5
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n6: expected/$(RESDIR)/n6 regress/$(RESDIR)/n6 input/$(RESDIR)/n6
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n7: expected/$(RESDIR)/n7 regress/$(RESDIR)/n7 input/$(RESDIR)/n7
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n8: expected/$(RESDIR)/n8 regress/$(RESDIR)/n8 input/$(RESDIR)/n8
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n9: expected/$(RESDIR)/n9 regress/$(RESDIR)/n9 input/$(RESDIR)/n9
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n10: expected/$(RESDIR)/n10 regress/$(RESDIR)/n10 input/$(RESDIR)/n10
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n11: expected/$(RESDIR)/n11 regress/$(RESDIR)/n11 input/$(RESDIR)/n11
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n12: expected/$(RESDIR)/n12 regress/$(RESDIR)/n12 input/$(RESDIR)/n12
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n13: expected/$(RESDIR)/n13 regress/$(RESDIR)/n13 input/$(RESDIR)/n13
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n14: expected/$(RESDIR)/n14 regress/$(RESDIR)/n14 input/$(RESDIR)/n14
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n15: expected/$(RESDIR)/n15 regress/$(RESDIR)/n15 input/$(RESDIR)/n15
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n16: expected/$(RESDIR)/n16 regress/$(RESDIR)/n16 input/$(RESDIR)/n16
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n17: expected/$(RESDIR)/n17 regress/$(RESDIR)/n17 input/$(RESDIR)/n17
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n18: expected/$(RESDIR)/n18 regress/$(RESDIR)/n18 input/$(RESDIR)/n18
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n100: expected/$(RESDIR)/n100 regress/$(RESDIR)/n100 input/$(RESDIR)/n100
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n101: expected/$(RESDIR)/n101 regress/$(RESDIR)/n101 input/$(RESDIR)/n101
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n102: expected/$(RESDIR)/n102 regress/$(RESDIR)/n102 input/$(RESDIR)/n102
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n103: expected/$(RESDIR)/n103 regress/$(RESDIR)/n103 input/$(RESDIR)/n103
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n104: expected/$(RESDIR)/n104 regress/$(RESDIR)/n104 input/$(RESDIR)/n104
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n105: expected/$(RESDIR)/n105 regress/$(RESDIR)/n105 input/$(RESDIR)/n105
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n106: expected/$(RESDIR)/n106 regress/$(RESDIR)/n106 input/$(RESDIR)/n106
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n200: expected/$(RESDIR)/n200 regress/$(RESDIR)/n200 input/$(RESDIR)/n200
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n201: expected/$(RESDIR)/n201 regress/$(RESDIR)/n201 input/$(RESDIR)/n201
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n202: expected/n202 regress/n202 input/n202
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n1_6: expected/$(RESDIR)/n1_6 regress/$(RESDIR)/n1_6 input/$(RESDIR)/n1_6
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n2_6: expected/$(RESDIR)/n2_6 regress/$(RESDIR)/n2_6 input/$(RESDIR)/n2_6
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n4_6: expected/$(RESDIR)/n4_6 regress/$(RESDIR)/n4_6 input/$(RESDIR)/n4_6
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n5_6: expected/$(RESDIR)/n5_6 regress/$(RESDIR)/n5_6 input/$(RESDIR)/n5_6
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n6_6: expected/$(RESDIR)/n6_6 regress/$(RESDIR)/n6_6 input/$(RESDIR)/n6_6
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n7_6: expected/$(RESDIR)/n7_6 regress/$(RESDIR)/n7_6 input/$(RESDIR)/n7_6
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n8_6: expected/$(RESDIR)/n8_6 regress/$(RESDIR)/n8_6 input/$(RESDIR)/n8_6
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n9_6: expected/$(RESDIR)/n9_6 regress/$(RESDIR)/n9_6 input/$(RESDIR)/n9_6
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n11_6: expected/$(RESDIR)/n11_6 regress/$(RESDIR)/n11_6 input/$(RESDIR)/n11_6
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n12_6: expected/$(RESDIR)/n12_6 regress/$(RESDIR)/n12_6 input/$(RESDIR)/n12_6
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/n15_6: expected/$(RESDIR)/n15_6 regress/$(RESDIR)/n15_6 input/$(RESDIR)/n15_6
	@/bin/sh ./n_test $@ $(TESTMODE)

$(RESDIR)/ni1: expected/ni1 input/$(RESDIR)/ni1 regress/$(RESDIR)/ni1.nat regress/ni1.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) multi

$(RESDIR)/ni2: expected/ni2 input/$(RESDIR)/ni2 regress/$(RESDIR)/ni2.nat regress/ni2.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) single

$(RESDIR)/ni3: expected/ni3 input/$(RESDIR)/ni3 regress/$(RESDIR)/ni3.nat regress/ni3.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) single

$(RESDIR)/ni4: expected/ni4 input/$(RESDIR)/ni4 regress/$(RESDIR)/ni4.nat regress/ni4.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) single

$(RESDIR)/ni5: expected/ni5 input/$(RESDIR)/ni5 regress/$(RESDIR)/ni5.nat regress/$(RESDIR)/ni5.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) single

$(RESDIR)/ni6: expected/$(RESDIR)/ni6 input/$(RESDIR)/ni6 regress/$(RESDIR)/ni6.nat regress/$(RESDIR)/ni6.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) multi

$(RESDIR)/ni7: expected/ni7 input/$(RESDIR)/ni7 regress/$(RESDIR)/ni7.nat regress/ni7.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) single

$(RESDIR)/ni8: expected/ni8 input/$(RESDIR)/ni8 regress/$(RESDIR)/ni8.nat regress/ni8.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) single

$(RESDIR)/ni9: expected/ni9 input/$(RESDIR)/ni9 regress/$(RESDIR)/ni9.nat regress/ni9.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) single

$(RESDIR)/ni10: expected/ni10 input/$(RESDIR)/ni10 regress/$(RESDIR)/ni10.nat regress/ni10.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) single

$(RESDIR)/ni11: expected/ni11 input/$(RESDIR)/ni11 regress/$(RESDIR)/ni11.nat regress/ni11.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) single

$(RESDIR)/ni12: expected/ni12 input/$(RESDIR)/ni12 regress/$(RESDIR)/ni12.nat regress/ni12.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) single

$(RESDIR)/ni13: expected/$(RESDIR)/ni13 input/$(RESDIR)/ni13 regress/$(RESDIR)/ni13.nat regress/$(RESDIR)/ni13.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) single

$(RESDIR)/ni14: expected/ni14 input/$(RESDIR)/ni14 regress/$(RESDIR)/ni14.nat regress/$(RESDIR)/ni14.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) single

$(RESDIR)/ni15: expected/ni15 input/$(RESDIR)/ni15 regress/$(RESDIR)/ni15.nat regress/$(RESDIR)/ni15.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) single

$(RESDIR)/ni16: expected/$(RESDIR)/ni16 input/$(RESDIR)/ni16 regress/$(RESDIR)/ni16.nat regress/$(RESDIR)/ni16.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) single

$(RESDIR)/ni17: expected/$(RESDIR)/ni17 input/$(RESDIR)/ni17 regress/$(RESDIR)/ni17.nat regress/ni17.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) multi

$(RESDIR)/ni18: expected/$(RESDIR)/ni18 input/$(RESDIR)/ni18 regress/$(RESDIR)/ni18.nat regress/ni18.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) multi

$(RESDIR)/ni19: expected/ni19 input/$(RESDIR)/ni19 regress/$(RESDIR)/ni19.nat regress/$(RESDIR)/ni19.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) single

$(RESDIR)/ni20: expected/$(RESDIR)/ni20 input/$(RESDIR)/ni20 regress/$(RESDIR)/ni20.nat regress/$(RESDIR)/ni20.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) single

$(RESDIR)/ni21: expected/$(RESDIR)/ni21 input/$(RESDIR)/ni21 regress/$(RESDIR)/ni21.nat regress/$(RESDIR)/ni21.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) multi

$(RESDIR)/ni23: expected/$(RESDIR)/ni23 input/$(RESDIR)/ni23 regress/$(RESDIR)/ni23.nat regress/$(RESDIR)/ni23.ipf
	@/bin/sh ./ni_test $@ $(TESTMODE) multi

$(RESDIR)/in1: expected/in1 regress/in1
	@/bin/sh ./in_test $@ $(TESTMODE)

$(RESDIR)/in2: expected/in2 regress/in2
	@/bin/sh ./in_test $@ $(TESTMODE)

$(RESDIR)/in3: expected/in3 regress/in3
	@/bin/sh ./in_test $@ $(TESTMODE)

$(RESDIR)/in4: expected/in4 regress/in4
	@/bin/sh ./in_test $@ $(TESTMODE)

$(RESDIR)/in5: expected/in5 regress/in5
	@/bin/sh ./in_test $@ $(TESTMODE)

$(RESDIR)/in6: expected/in6 regress/in6
	@/bin/sh ./in_test $@ $(TESTMODE)

$(RESDIR)/in7: expected/in7 regress/in7
	@/bin/sh ./in_test $@ $(TESTMODE)

$(RESDIR)/in8: expected/in7 regress/in8
	@/bin/sh ./in_test $@ $(TESTMODE)

$(RESDIR)/in100: expected/in100 regress/in100
	@/bin/sh ./in_test $@ $(TESTMODE)

$(RESDIR)/in101: expected/in101 regress/in101
	@/bin/sh ./in_test $@ $(TESTMODE)

$(RESDIR)/in102: expected/in102 regress/in102
	@/bin/sh ./in_test $@ $(TESTMODE)

$(RESDIR)/l1:
	@/bin/sh ./logtest $@ $(TESTMODE)

$(RESDIR)/ipv6_1: expected/ipv6_1 input/$(RESDIR)/ipv6_1 regress/$(RESDIR)/ipv6_1
	@/bin/sh ./ipv6_test $@ $(TESTMODE)

$(RESDIR)/ipv6_2: expected/ipv6_2 input/$(RESDIR)/ipv6_2 regress/ipv6_2
	@/bin/sh ./ipv6_test $@ $(TESTMODE)

$(RESDIR)/ipv6_3: expected/ipv6_3 input/$(RESDIR)/ipv6_3 regress/$(RESDIR)/ipv6_3
	@/bin/sh ./ipv6_test $@ $(TESTMODE)

$(RESDIR)/ipv6_4: expected/ipv6_4 input/$(RESDIR)/ipv6_4 regress/ipv6_4
	@/bin/sh ./ipv6_test $@ $(TESTMODE)

$(RESDIR)/ipv6_5: expected/ipv6_5 input/$(RESDIR)/ipv6_5 regress/ipv6_5
	@/bin/sh ./ipv6_test $@ $(TESTMODE)

$(RESDIR)/ipv6_6: expected/ipv6_6 input/$(RESDIR)/ipv6_6 regress/$(RESDIR)/ipv6_6
	@/bin/sh ./ipv6_test $@ $(TESTMODE)

$(RESDIR)/p1: expected/p1 input/p1 regress/p1.ipf regress/p1.pool $(POOLDEP)
	@/bin/sh ./p_test $@ $(TESTMODE)

$(RESDIR)/p2: expected/p2 input/p2 regress/p2.ipf $(POOLDEP)
	@/bin/sh ./p_test $@ $(TESTMODE)

$(RESDIR)/p3: expected/p3 input/p3 regress/p3.ipf regress/p3.pool $(POOLDEP)
	@/bin/sh ./p_test $@ $(TESTMODE)

$(RESDIR)/p4: expected/p4 input/p4 regress/p4.nat regress/p4.pool $(POOLDEP)
	@/bin/sh ./p_test $@ $(TESTMODE)

$(RESDIR)/p5: expected/p5 input/p5 regress/p5.ipf regress/p5.pool $(POOLDEP)
	@/bin/sh ./p_test $@ $(TESTMODE)

$(RESDIR)/p6: expected/p6 input/p6 regress/p6.ipf regress/p6.pool $(POOLDEP)
	@/bin/sh ./p_test $@ $(TESTMODE)

$(RESDIR)/p7: expected/$(RESDIR)/p7 input/$(RESDIR)/p7 regress/$(RESDIR)/p7.nat regress/p7.pool $(POOLDEP)
	@/bin/sh ./p_test $@ $(TESTMODE)

$(RESDIR)/p9: expected/$(RESDIR)/p9 input/$(RESDIR)/p9 regress/$(RESDIR)/p9.nat regress/p9.pool $(POOLDEP)
	@/bin/sh ./p_test $@ $(TESTMODE)

$(RESDIR)/p10: expected/$(RESDIR)/p10 input/$(RESDIR)/p10 regress/$(RESDIR)/p10.nat regress/p10.pool \
	    $(POOLDEP)
	@/bin/sh ./p_test $@ $(TESTMODE)

$(RESDIR)/p11: expected/$(RESDIR)/p11 input/$(RESDIR)/p11 regress/$(RESDIR)/p11.nat regress/p11.pool \
	    $(POOLDEP)
	@/bin/sh ./p_test $@ $(TESTMODE)

$(RESDIR)/p12: expected/$(RESDIR)/p12 input/$(RESDIR)/p12 regress/$(RESDIR)/p12.nat regress/p12.pool \
	    $(POOLDEP)
	@/bin/sh ./p_test $@ $(TESTMODE)

$(RESDIR)/p13: expected/p13 input/p13 regress/p13.ipf regress/p13.pool \
	    $(POOLDEP)
	@/bin/sh ./p_test $@ $(TESTMODE)

$(RESDIR)/ip1: expected/ip1 regress/ip1 $(POOLDEP)
	@/bin/sh ./ip_test $@ $(TESTMODE)

$(RESDIR)/ip2: expected/ip2 input/ip2.data regress/ip2 $(POOLDEP)
	@/bin/sh ./ip_test $@ $(TESTMODE)

$(RESDIR)/ip3: expected/ip3 regress/ip3 $(POOLDEP)
	@/bin/sh ./ip_test $@ $(TESTMODE)

$(RESDIR)/bpf-f1: expected/bpf-f1 regress/bpf-f1
	/bin/sh ./bpf_test $@ $(TESTMODE)

expected/i19:
	(cd expected; make i19)

clean:
	/bin/rm -rf $(RESDIR)/*
	/bin/rm -f results/* logout
	(cd expected; make clean)
	(cd input; make clean)
	(cd regress; make clean)
	sed -ne '1,/^# APPEND/p' Makefile > Makefile.new
	mv Makefile.new Makefile

diffs:
	-cd expected; for i in *; do if [ -f $$i -a ! -f ../$$i -a -f ../results/$$i ] ; then  diff -c $$i ../results/$$i >> ../diff.out; fi done

n6s:
	for i in 1 2 4 5 6 7 11 13 14 15; do \
		sh i4to6 < input/n$${i} > input/n$${i}_6; \
		sh e4to6 < regress/n$${i} > regress/n$${i}_6; \
		sh e4to6 < expected/n$${i} > expected/n$${i}_6; \
	done
	for i in 8 9 10 12 17; do \
		sh e4to6 < regress/n$${i} > regress/n$${i}_6; \
		perl h4to6 < input/n$${i} > input/n$${i}_6; \
	done

appendixes:
	sed -ne '1,/^# APPEND/p' Makefile > Makefile.new
	find . -name \*.dist | sed -e 's/^\.\///p' -e 's@/@/\$$(RESDIR)/@' -e 's/.dist//' | perl -e 'while(<>){chop;@F=split(/[\/\.]/); $$d=$$_;$$_=<>;chop;print "$$_: $$d\n";print "\tperl ./build_test.pl $$F[0] $$F[1]\n";print "\n";}' >> Makefile.new
	mv Makefile.new Makefile
#
# APPENDIXES
