$squares = 0;
$pktlen = 0;

#
# validate the IPv4 header checksum.
# $bytes[] is an array of 16bit values, with $cnt elements in the array.
#
sub dump {
	for ($i = 0; $i <= $#bytes; $i++) {
		if (($i * 2) + 2 > $pktlen) {
			printf "%02x ", $bytes[$i] >> 8;
		} else {
			printf "%04x ", $bytes[$i];
		}
	}
	print "\n";
	print "\n" if ($squares);
	$cnt = 0;
	$multi = 0;
	@bytes = ();
}

sub dosum {
	local($seed) = $_[0];
	local($start) = $_[1];
	local($max) = $_[2];
	local($idx) = $start;
	local($lsum) = $seed;

	for ($idx = $start, $lsum = $seed; $idx < $max; $idx++) {
		$lsum += $bytes[$idx];
	}
	$lsum = ($lsum & 0xffff) + ($lsum >> 16);
	$lsum = ~$lsum & 0xffff;
	return $lsum;
}


sub ipv4addrsum {
	local($b) = $_[0];
	local($as) = 0;

	$as += $bytes[$b + 6];	# source address
	$as += $bytes[$b + 7];
	$as += $bytes[$b + 8];	# destination address
	$as += $bytes[$b + 9];
	return ($as);
}

sub ipv6addrsum {
	local($b) = $_[0];
	local($as) = 0;

	$as += $bytes[$b + 4];	# source address
	$as += $bytes[$b + 5];
	$as += $bytes[$b + 6];
	$as += $bytes[$b + 7];
	$as += $bytes[$b + 8];
	$as += $bytes[$b + 9];
	$as += $bytes[$b + 10];
	$as += $bytes[$b + 11];
	$as += $bytes[$b + 12];	# destination address
	$as += $bytes[$b + 13];
	$as += $bytes[$b + 14];
	$as += $bytes[$b + 15];
	$as += $bytes[$b + 16];
	$as += $bytes[$b + 17];
	$as += $bytes[$b + 18];
	$as += $bytes[$b + 19];
	return ($as);
}

sub tcpcommon {
	local($base) = $_[0];
	local($hl) = $_[1];
	local($hs) = $_[2];

	local($thl) = $bytes[$base + $hl + 6];
	$thl &= 0xf0;
	$thl >>= 2;

	local($x) = $bytes[$base + 1];
	local($y) = ($cnt - $base) * 2;
	local($z) = 0;

	if ($bytes[$base + 1] > ($cnt - $base) * 2) {
		$x = $bytes[$base + 1];
		$y = ($cnt - $base) * 2;
		$z = 1;
	} elsif (($cnt - $base) * 2 < $hl + $hl) {
		$x = ($cnt - $base) * 2;
		$y = $hl + 20;
		$z = 2;
	} elsif (($cnt - $base) * 2 < $hl + $thl) {
		$x = ($cnt - $base) * 2;
		$y = $hl + $thl;
		$z = 3;
	} elsif ($len < $thl) {
		$x = ($cnt - $base) * 2;
		$y = $len;
		$z = 4;
	} elsif (($cnt - $base) * 2 < 20) {
		$x = ($cnt - $base) * 2;
		$y = $len;
		$z = 5;
	}

	if ($z) {
		return;
	}

	local($tcpat) = $base + $hl;
	$hs = &dosum($_[2], $tcpat, $cnt);
	if ($hs != 0) {
		local($osum) = $bytes[$tcpat + 8];
		$bytes[$base + $hl + 8] = 0;
		local($hs2) = &dosum($_[2], $tcpat, $cnt);
		$bytes[$tcpat + 8] = $hs2;
	}
}

sub udpcommon {
	local($base) = $_[0];
	local($hl) = $_[1];
	local($hs) = $_[2];

	if ($bytes[$base + 1] > ($cnt - $base) * 2) {
		return;
	} elsif ($bytes[$base + 1] < ($hl << 1) + 8) {
		return;
	} elsif (($cnt - $base) * 2 < ($hl << 1) + 8) {
		return;
	}

	local($udpat) = $base + $hl;
	$hs = &dosum($udpsum, $udpat, $cnt);
	local($osum) = $bytes[$udpat + 3];

	#
	# It is valid for UDP packets to have a 0 checksum field.
	# If it is 0, then display what it would otherwise be.
	#
	if ($osum == 0) {
		;
	} elsif ($hs != 0) {
		$bytes[$udpat + 3] = 0;
		local($hs2) = &dosum($udpsum, $udpat, $cnt);
		$bytes[$udpat + 3] = $hs2;
	}
}

sub ipv6check {
	local($base) = $_[0];
	$hl = $bytes[$base] / 256;
	$pktlen = $bytes[2] if ($base == 0);
	return if (($hl >> 4) != 6);	# IPv4 ?
	$hl = 40;

	if (($bytes[$base + 3] >> 8) == 6) {
		&tcpcheck6($base);
	} elsif (($bytes[$base + 3] >> 8) == 58) {
		&icmpcheck6($base);
	}
	$pktlen += 40;
}

sub tcpcheck6 {
	local($base) = $_[0];
	local($hl) = $bytes[$base] / 256;
	return if (($hl >> 4) != 6);
	$hl = 20;

	local($hs) = 6;	# TCP
	local($len) = $bytes[$base + 2];
	$hs += $len;
	$hs += &ipv6addrsum($base);

	&tcpcommon($base, $hl, $hs);
}

sub icmpcheck6 {
	local($base) = $_[0];
	local($hl) = $bytes[$base + 0] / 256;
	return if (($hl >> 4) != 6);
	$hl = 20;

	local($hs);
	local($hs2);

	local($len) = $bytes[$base + 1] - ($hl << 1);

	if ($bytes[$base + 2] > ($cnt - $base) * 2) {
		return;
	} elsif ($bytes[$base + 2] < ($hl << 1) + 8) {
		return;
	} elsif (($cnt - $base) * 2 < ($hl << 1) + 8) {
		return;
	}

	local($osum) = $bytes[$base + $hl + 1];
	$bytes[$base + $hl + 1] = 0;
	$hs2 = &dosum(0, $base + $hl, $cnt);
	$bytes[$base + $hl + 1] = $hs2;

#	if ($base == 0) {
#		$type = $bytes[$hl] >> 8;
#		if ($type == 3 || $type == 4 || $type == 5 ||
#		    $type == 11 || $type == 12) {
#			&ipv4check($hl + 4);
#		}
#	}
}

sub ipv4check {
	local($base) = $_[0];
	$hl = $bytes[$base] / 256;
	if (($hl >> 4) == 6) {
		&ipv6check($_[0]);
		return;
	}
	$pktlen = $bytes[1] if ($base == 0);
	return if (($hl >> 4) != 4);	# IPv4 ?
	$hl &= 0xf;
	$hl <<= 1;			# get the header length in 16bit words

	$hs = &dosum(0, $base, $base + $hl);
	$osum = $bytes[$base + 5];

	if ($hs != 0) {
		$bytes[$base + 5] = 0;
		$hs2 = &dosum(0, $base, $base + $hl);
		$bytes[$base + 5] = $hs2;
	}

	#
	# Recognise TCP & UDP and calculate checksums for each of these.
	#
	if (($bytes[$base + 4] & 0xff) == 4) {
		&ipv4check($hl);
	}
	if (($bytes[$base + 4] & 0xff) == 6) {
		&tcpcheck($base);
	}

	if (($bytes[$base + 4] & 0xff) == 17) {
		&udpcheck($base);
	}

	if (($bytes[$base + 4] & 0xff) == 1) {
		&icmpcheck($base);
	}
}

sub tcpcheck {
	local($base) = $_[0];
	local($hl) = $bytes[$base] / 256;
	return if (($hl >> 4) != 4);
	if ($bytes[$base + 3] & 0x3fff) {
		return;
	}
	$hl &= 0xf;
	$hl <<= 1;

	local($hs) = 6;	# TCP
	local($len) = $bytes[$base + 1] - ($hl << 1);
	$hs += $len;
	$hs += &ipv4addrsum($base);

	&tcpcommon($base, $hl, $hs);
}

sub udpcheck {
	local($base) = $_[0];
	local($hl) = $bytes[0] / 256;
	return if (($hl >> 4) != 4);
	if ($bytes[$base + 3] & 0x3fff) {
		return;
	}
	$hl &= 0xf;
	$hl <<= 1;

	local($hs) = 17;	# UDP
	local($len) = $bytes[$base + 1] - ($hl << 1);
	$hs += $len;
	$hs += &ipv4addrsum($base);
	local($udpsum) = $hs;
	&udpcommon($base, $hl, $hs);
}

sub icmpcheck {
	local($base) = $_[0];
	local($hl) = $bytes[$base + 0] / 256;
	return if (($hl >> 4) != 4);
	return if ($bytes[3] & 0x1fff);
	$hl &= 0xf;
	$hl <<= 1;

	local($hs);
	local($hs2);

	local($len) = $bytes[$base + 1] - ($hl << 1);

	if ($bytes[$base + 1] > ($cnt - $base) * 2) {
		return;
	} elsif ($bytes[$base + 1] < ($hl << 1) + 8) {
		return;
	} elsif (($cnt - $base) * 2 < ($hl << 1) + 8) {
		return;
	}

	local($osum) = $bytes[$base + $hl + 1];
	$bytes[$base + $hl + 1] = 0;
	$hs2 = &dosum(0, $base + $hl, $cnt);
	$bytes[$base + $hl + 1] = $hs2;

	if ($base == 0) {
		$type = $bytes[$hl] >> 8;
		if ($type == 3 || $type == 4 || $type == 5 ||
		    $type == 11 || $type == 12) {
			&ipv4check($hl + 4);
		}
	}
}

sub readinput {
	$save = $_;
	chop;
	s/#.*//g;

	#
	# If the first non-comment, non-empty line of input starts
	# with a '[', then allow the input to be a multi-line hex
	# string, otherwise it has to be all on one line.
	#
	if (/^\[/) {
		$squares = 1;
		$multi = 1;
		s/^\[[^]]*\]//g;
		$save =~ s/^(\[[^]]*\]).*/$1/;
		print "${save}";
		$save = "";

	}
	s/^ *//g;
	if (length == 0) {
		if ($cnt == 0) {
			print "${save}" if length($save);
			return;
		}
		&ipv4check(0);
		&dump;
		return;
	}

	if ($_ !~ /^[0-9a-f]{4}( [0-9a-f]{1,})/) {
		if ($_ !~ /^[0-9a-f]{4}\s*$/) {
			print "${save}";
			return;
		}
	}
	#
	# look for 16 bits, represented with leading 0's as required,
	# in hex.
	#
	s/NIC.HEXADDR/0000 0000/g;
	s/TCPCKSUM/0000/g;
	s/UDPCKSUM/0000/g;
	s/IPCKSUM/0000/g;
	s/\t/ /g;
	while (/^[0-9a-fA-F][0-9a-fA-F] [0-9a-fA-F][0-9a-fA-F] .*/) {
		s/^([0-9a-fA-F][0-9a-fA-F]) ([0-9a-fA-F][0-9a-fA-F]) (.*)/$1$2 $3/;
	}
	while (/.* [0-9a-fA-F][0-9a-fA-F] [0-9a-fA-F][0-9a-fA-F] .*/) {
$b=$_;
		s/(.*?) ([0-9a-fA-F][0-9a-fA-F]) ([0-9a-fA-F][0-9a-fA-F]) (.*)/$1 $2$3 $4/g;
	}
	if (/.* [0-9a-fA-F][0-9a-fA-F] [0-9a-fA-F][0-9a-fA-F]/) {
$b=$_;
		s/(.*?) ([0-9a-fA-F][0-9a-fA-F]) ([0-9a-fA-F][0-9a-fA-F])/$1 $2$3/g;
	}
	while (/^[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F].*/) {
		$x = $_;
		$x =~ s/([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]).*/$1/;
		$x =~ s/ *//g;
		$y = hex $x;
		s/[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F] *(.*)/$1/;
		$bytes[$cnt] = $y;
		$cnt++;
	}

	#
	# Pick up stragler bytes.
	#
	if (/^[0-9a-fA-F][0-9a-fA-F]/) {
		$y = hex $_;
		$bytes[$cnt++] = $y * 256;
	}
	if ($multi == 0 && $cnt > 0) {
		&ipv4check(0);
		&dump;
	}
}

if ($ARGV[0] eq "16") {
	shift(@ARGV);
}

if ($#ARGV >= 0) {
	while ($#ARGV >= 0) {
		$multi = 0;

		open(I, "$ARGV[0]") || die $!;
		while (<I>) {
			&readinput;
		}
		close(I);

		if ($cnt > 0) {
			&ipv4check(0);
			&dump;
		}
		shift(@ARGV);
	}
} else {
	while (<>) {
		&readinput;
	}
}
