#!/usr/local/bin/perl

use IO::Socket::IP;

$|=1;
$tout = $ENV{'TCP_TIMEOUT'};
$data = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\n";

$socket = new IO::Socket::IP(
PeerAddr => $ARGV[0],
PeerPort => int($ARGV[1]),
Proto => 'udp'
) ||
die "ERROR creating UDP socket $ARGV[0],$ARGV[1]: $!";

$socket->send($data, 0, $remote);

eval {
	local $SIG{ALRM} = sub { $died = 1; die "alarm\n" };
	alarm($tout);
	$remote = $socket->recv($back, 1024);
};
$m = length($data);
$n = length($back);

if ($died) {
	print "DIED recv\n";
} else {
	if ($m != $n) {
		print "FAILED sent $m received $n\n";
	} else {
		print "CLIENT sent $m received $n\n";
	}
}

exit(0);
