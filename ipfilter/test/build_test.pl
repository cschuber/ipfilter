#!perl

$debug = 0;
$which = "all";

sub pulenv() {
	if (!defined($ENV{$_[0]})) {
		eval "\$$_[0]=\"$_[1]\";";
		$ENV{$_[0]} = "$_[1]";
	} else {
		eval "\$$_[0]=\"$ENV{$_[0]}\";";
	}
}

&pulenv("RESDIR", "user");
&pulenv("NIC0", "nic0");
&pulenv("NIC1", "nic1");
&pulenv("NIC2", "nic2");
&pulenv("NIC3", "nic3");
&pulenv("NIC0ADDR", "192.168.1.188__");
&pulenv("NIC1ADDR", "");
&pulenv("NIC0ADDR6", "c0a8:100::bc");
&pulenv("NIC1ADDR6", "");
&pulenv("NIC0HEXADDR", "c0a8 01bc");
&pulenv("NIC1HEXADDR", "");
&pulenv("NIC0HEXADDR6", "c0a8 0100 0000 0000 0000 0000 0000 00bc");
&pulenv("NIC1HEXADDR6", "");

mkdir("input/${RESDIR}");
mkdir("expected/${RESDIR}");
mkdir("regress/${RESDIR}");

sub findfile () {
	eval "\$$_[0]_target=$_[0]/$_[1]";
	if ( -f "$_[0]/$_[1]" ) {
		print eval "\$$_[0]=$_[0]/$_[1]";
		print eval "\$$_[0]_result=$_[0]/${RESDIR}/$_[1]";
	} else {
		if ( -f "$_[0]/$_[1].dist" ) {
			eval "\${$_[0]}='$_[0]/$_[1].dist'";
			eval "\${$_[0]_result}='$_[0]/${RESDIR}/$_[1]'";
		} else {
			eval "$_[0]=_";
			if ( -f "$_[0]/$_[1].ipf.dist" ) {
				eval "\${$_[0]_ipf}='$_[0]/$_[1].ipf.dist'";
				eval "\${$_[0]_ipf_result}='$_[0]/${RESDIR}/$_[1].ipf'";
			}
			if ( -f "$_[0]/$_[1].nat.dist" ) {
				eval "\${$_[0]_nat}='$_[0]/$_[1].nat.dist'";
				eval "\${$_[0]_nat_result}='$_[0]/${RESDIR}/$_[1].nat'";
			}
		}
	}
}

sub sedfile {
	open(S, "<$_[0]") || die $!;
	open(W, ">$_[1]") || die $!;
	while (<S>) {
		s/NIC0HEXADDR6/${NIC0HEXADDR6}/g;
		s/NIC1HEXADDR6/${NIC1HEXADDR6}/g;
		s/NIC0HEXADDR/${NIC0HEXADDR}/g;
		s/NIC1HEXADDR/${NIC1HEXADDR}/g;
		s/NIC0ADDR6/${NIC0ADDR6}/g;
		s/NIC1ADDR6/${NIC1ADDR6}/g;
		s/NIC0ADDR/${NIC0ADDR}/g;
		s/NIC1ADDR/${NIC1ADDR}/g;
		s/NIC0/${NIC0}/g;
		s/NIC1/${NIC1}/g;
		s/NIC2/${NIC2}/g;
		s/NIC3/${NIC3}/g;
		s/_/ /g;
		print W;
	}
	close(W);
	close(S);
}

sub cksumfile {
	if ( -f $_[0] ) {
		open(I, "<$_[0]") || die $!;
		$sums = 0;
		while (<I>) {
			$sums++ if (/CKSUM/);
		}
		close(I);
		if ($sums gt 0) {
			rename($_[0], "$_[0].tmp") || die $!;
			system("perl ./fillcksum.pl $_[0].tmp > $_[0]");
		}
	}
}

sub fixfile {
	if ( -f $_[0] && $_[0] eq $_[1]) {
		print "|" if ($debug);
		return
	}
	if (length($_[0]) && -f $_[0] && length($_[2]) && -f $_[2]) {
		@s1 = stat($_[0]);
		@s2 = stat($_[2]);
		if ($s2[9] > $s1[9]) {
			print "-" if ($debug);
			return;
		}
	}

	if (length($_[3]) && length($_[4])) {
		@s1 = stat($_[3]);
		@s2 = stat($_[4]);
		if ($s1[9] gt $s2[9] && -f $_[3]) {
			print "." if ($debug);
			&sedfile($_[3], $_[4]);
		} else {
			print "<" if ($debug);
		}
	}

	if (length($_[5]) && length($_[6])) {
		@s1 = stat($_[5]);
		@s2 = stat($_[6]);
		if ($s1[9] gt $s2[9] && -f $_[5]) {
			print "," if ($debug);
			&sedfile($_[5], $_[6]);
		} else {
			print ">" if ($debug);
		}
	}

	if ( $_[0] ne "_" && $_[1] ne $_[0]) {
		@s1 = stat($_[0]);
		@s2 = stat($_[2]);
		if ($s1[9] gt $s2[9]) {
			print "_" if ($debug);
			&sedfile($_[0], $_[2]);
			&cksumfile($_[2]);
		} else {
			print "=" if ($debug);
		}
	}

	&cksumfile($_[1]);
}

sub fixtest {
	&findfile("expected", $_[0]);
	&findfile("input", $_[0]);
	&findfile("regress", $_[0]);

	if ( -f ${input} ) {
		open(I, "<${input}") || die $!;
		$_ = <I>;
		close(I);
		if ($_ =~ /^\[.*,(.*=[^]]*)\.*/) {
			$nics = $1;
		}
	} else {
		$nics = "";
	}

	if (length(${nics})) {
		@N = split(/=/, $nics);
		if ( $#N gt 0 ) {
			$name=$N[0];
			if (!defined($ENV{"${name}HEXADDR"})) {
				$addr=$N[1];
				@A = split(/\./, $addr);
				$hex = sprintf "%02x%02x %02x%02x", $A[0], $A[1], $A[2], $A[3];
				eval "\$${name}HEXADDR=\"$hex\";";
				${addr} = "${addr}______________";
				$addr =~ s/^(...............).*/$1/;
				eval "\$${name}ADDR='${addr}'";
			}
		}
	}

	if ($which eq "all" || $which eq "expected") {
		&fixfile(${expected}, ${expected_target}, ${expected_result},
			 ${expected_ipf}, ${expected_ipf_result},
			 ${expected_nat}, ${expected_nat_result});
	}
	if (($which eq "all" || $which eq "input") && ${input} ne "_") {
		&fixfile(${input}, ${input_target}, ${input_result},
			${input_ipf}, ${input_ipf_result},
			${input_nat}, ${input_nat_result});
	}
	if ($which eq "all" || $which eq "regress") {
		&fixfile(${regress}, ${regress_target}, ${regress_result},
			 ${regress_ipf}, ${regress_ipf_result},
			 ${regress_nat}, ${regress_nat_result});
	}
}

$which = $ARGV[0];
shift(@ARGV);
print "Fixing $ARGV[0]" if ($debug);
&fixtest($ARGV[0]);
print "\n" if ($debug);
exit(0);


sub dump {
	print "execpted=${expected}\n";
	print "execpted_result=${expected_result}\n";
	print "execpted_target=${expected_target}\n";
	print "execpted_ipf=${expected_ipf}\n";
	print "execpted_ipf_result=${expected_ipf_result}\n";
	print "execpted_nat=${expected_nat}\n";
	print "execpted_nat_result=${expected_nat_result}\n";
	print "input=${input}\n";
	print "input_result=${input_result}\n";
	print "input_target=${input_target}\n";
	print "input_ipf=${input_ipf}\n";
	print "input_ipf_result=${input_ipf_result}\n";
	print "input_nat=${input_nat}\n";
	print "input_nat_result=${input_nat_result}\n";
	print "regress=${regress}\n";
	print "regress_result=${regress_result}\n";
	print "regress_target=${regress_target}\n";
	print "regress_ipf=${regress_ipf}\n";
	print "regress_ipf_result=${regress_ipf_result}\n";
	print "regress_nat=${regress_nat}\n";
	print "regress_nat_result=${regress_nat_result}\n";
}
