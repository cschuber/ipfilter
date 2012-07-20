#!/bin/perl

use IO::Socket::IP;

$| = 1;
$died = 0;
$place = 0;
$tout = $ENV{'TCP_TIMEOUT'};
$data = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\n";

eval {
	local $SIG{ALRM} = sub { $died = 1; die "alarm\n" };
	alarm($tout);
	$socket = new IO::Socket::IP(
		PeerHost => $ARGV[0],
		PeerPort => $ARGV[1],
		LocalHost => $ARGV[2],
		ReuseAddr => true,
		Proto => 'tcp',
	) || die "ERROR creating socket to $ARGV[0],$ARGV[1]: $!";
	alarm(0);

	$place = 1;
	alarm($tout);
	print $socket $data;
	alarm(0);
	$place = 2;
	alarm($tout);
	$x = <$socket>;
	alarm(0);
	close($socket);
};
$m = length($data);
$n = length($x);
if ($died) {
	print "DIED $place\n";
} else {
	if ($m != $n) {
		print "FAILED sent $m received $n\n";
	} else {
		print "CLIENT sent $m received $n\n";
	}
}
exit(0);
