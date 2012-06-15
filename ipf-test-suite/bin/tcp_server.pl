#!/bin/perl

use IO::Socket::IP;

$|=1;
$num_clients = 0;
$interrupted = 0;
$SIG{'INT'} = 'INT_handler';

$pidfile = $ENV{'IPF_TMP_DIR'}."/tcpserver.pid.$ARGV[2]";

if (!open(P, ">${pidfile}")) {
	die "open(>${pidfile}):$!";
}
print P "$$\n";
close(P);

$socket = new IO::Socket::IP(
	LocalHost => $ARGV[0],
	LocalPort => int($ARGV[1]),
	ReuseAddr => true,
	Proto => 'tcp',
	Listen => 1
) ||
die "ERROR creating TCP socket $ARGV[0],$ARGV[1]: $!";

while ($interrupted == 0) {
	if ($client = $socket->accept()) {
		$data = <$client>;
		$client->send($data);
		#
		# doing a close too quickly can cause the data just queued
		# for sending to be dropped.
		#
		sleep(1);
		close($client);
		$num_clients++;
	}
}
print "CLIENTCOUNT $num_clients\n";
exit(0);

sub INT_handler {
	$interrupted = 1;
}
