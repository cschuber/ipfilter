#!/usr/local/bin/perl

use IO::Socket::IP;

$|=1;
$count = 0;
$interrupted = 0;
$pidfile = $ENV{'IPF_TMP_DIR'}."/udpserver.pid.$ARGV[2]";

if (!open(P, ">${pidfile}")) {
	die "open(>${pidfile}):$!";
}
print P "$$\n";
close(P);

$SIG{'INT'} = 'INT_handler';

$socket = new IO::Socket::IP(
LocalAddr => $ARGV[0],
LocalPort => int($ARGV[1]),
Proto => 'udp'
) ||
die "ERROR creating UDP socket $ARGV[0],$ARGV[1]: $!";

while ($interrupted == 0) {
	if ($remote = $socket->recv($data, 1024)) {
		$socket->send($data, 0, $remote);
		$count++;
	}
}

print "CLIENTCOUNT $count\n";

exit(0);

sub INT_handler {
	$interrupted = 1;
}
