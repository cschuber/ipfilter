Introduction
============
This test suite has been developed for the use on both modern BSD systems
and Solaris systems. Any Solaris system that supports the use of dladm to
create IP tunnels is sufficient, however this will typically mean only
OpenSolaris or Solaris 11 or newer. Systems running Solaris 10 or older 
are not suported.

This document refers to three hosts and their roles are outlined thus:

SUT - System Under Test. This is the host where filtering and NAT rules
      are activated and the system through or to which traffic is sent
      in order to evaluate the functionality of IPFilter. This host is
      involved all testing. In two host testing, it acts as the server
      for client requests originating from SENDER.

SENDER - This system is used as the source of nearly all networking
      tests that involve IPFilter. There are no specific service
      requirements for this host save remote shell access without
      a password. This host does not participate in one host tests.

RECEIVER - This system is the destination for most of the tests in the
      three host set of tests. In the one host and two host tests,
      this host is not used.


Requirements
============
For the successful execution of this test suite, perl must be available
on all three systems. For shell script execution, /bin/ksh is also
expected to be available on all systems.

Network Layout
--------------

                      CTL_NET
     +-------------------+-------------------+
     |                   |                   |
     |                   |                   |
     |                   |                   |
+----+-----+        +----+-----+        +----+-----+
|          |  NET0  |          |  NET1  |          |
|  SENDER  +--------+   SUT    +--------+ RECEIVER |
|          |        |          |        |          |
+----------+        +----------+        +----------+






Root Access
-----------
Each of SUT, SENDER and RECEIVER must allow password-less access remotely
via either ssh or rsh to the host running the test. Configuration of ssh
via authorised_keys and rsh via .rhosts/hosts.equiv to allow root on those
machines to be remotely accessed from the user running the tests is a
prerequisite for the successful execution of this test. 

Services
--------
The following services are required on the all three systems:
FTP	- anonymous FTP must be configured and the file /pub/test_data.txt
	  available for download on both the SUT and SENDER hosts.
RSH	- The "shell" (remote shell) service must be enabled on both the SUT
	  and the SENDER hosts to test the rcmd proxy.
TFTP	- It must be possible to download "test_data.txt" from within the
	  root directry of the TFTP server.

Individual configuration of the test systems to support the above services
is beyond the scope of this document.

Applications
------------
ksh	- This must be available as /bin/ksh
wget	- Support for both active and passive FTP must be included
perl	- IO::Socket::IP is required. This needs IO::Socket 1.97 or later.
	  Typically, perl 5.16 or later will be required to support
	  IO::Socket::IP.
tcpdump	- Required for capturing raw traffic during test.
rsh/ssh	- Required for remote access to other hosts.
tftpd	- Required as the target for TFTP proxy testing
tftp	- Required as the client for TFTP proxy testing

Test Suite
==========

Test Scripts
------------
Each test script is required to have the following functions:

gen_ipf_conf	- output ipf test configuration to stdout
		  returns 0 if the output has been successfully generated
		  returns 1 if there are no ipf rules for the test

gen_ipnat_conf	- output ipnat test configuration to stdout
		  returns 0 if the output has been successfully generated
		  returns 1 if there are no ipnat rules for the test

gen_ippool_conf	- output ippool test configuration to stdout
		  returns 0 if the output has been successfully generated
		  returns 1 if there are is ippool configuration for the test

do_test		- perform the required test
		  returns 0 if the test succeeds
		  returns non-0 to indicate failure

do_verify	- do_test is used to see if the required behaviour can be
		  observed. do_verify is used to verify the results of the
		  test. For example, an ipnat test might attempt to NAT
		  packets going out an interface and test this by using ping.
		  In do_verify, the traffic captured using tcpdump would be
		  used to ensure that the traffic on the network was actually
		  translated.
