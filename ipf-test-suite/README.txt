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

The systems used by this test suite must be connected as per the above
diagrom using either physical or virtual networking. All addresses and
network interface names must be correctly set in the file "vars.sh".

It is advised to disable any routing daemons running on any of the above
systems that will be involved in testing. Manual routes will be configured
to support the test suite.

Root Access
-----------
Each of SUT, SENDER and RECEIVER must allow password-less access remotely
via either ssh or rsh to the host running the test. Configuration of ssh
via authorised_keys and rsh via .rhosts/hosts.equiv to allow root on those
machines to be remotely accessed from the user running the tests is a
prerequisite for the successful execution of this test. Configuring rsh
or ssh to support passwordless remote access is beyond the scope of this
document.

On systems that start the shell daemon to be used for remote passwordless
access during testing using inetd, it is necessary to check if inetd
applies rate limiting to the number of sessions. On systems where this
feature is present, inetd should be configured to support at least 120
sessions per minute.

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

*** NOTE: If you are running rsh/ssh/rcmd via inetd.conf, ensure that  ***
***       inetd is configured to support > 100 connections/second.     ***
***       Failure to do so will result in the test taking a long time. ***

Test Suite
==========
Each test is completely specified by a single file under the tests
directory. Each script should pull in required configuration information
such as IP addresses and interface names from those available through
"vars.sh".

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

Starting Up
===========
To use this test suite the first requirement is to edit the file "vars.sh"
and supply the correct information as to hostnames, interface names and
IP addresses.

The next task is to arrange password-less root access between the system
that will be used to run the tests and each of the hosts involved as either
the SUT, SENDER or RECEIVER.  Root access is required on the SENDER and
RECEIVER to support running tcpdump.

Once password-less remote access has been established, the "setup.sh"
script can be run. This will reconfigure all network interfaces that
are defined for "NET0" and "NET1" in the "vars.sh" file. It is not
necessary to manually configure those network interfaces prior to
running "setup.sh". The hostnames, IP addresses and network interfaces
that are are defined for the "CTL" network are expected to be already
available and functional before "setup.sh" is run.

As part of its work, "setup.sh" will distribute the test suite to each
of the systems involved in testing using the "distribute.sh" script to
the directory "IPF_VAR_DIR".  This ensures that each system involved
is working from the same set of environment variables and that any
irregularities in paths or command line options can be managed.

On systems based on OpenSolaris, including IllumOS and Solaris 11 and
later, it is necessary to disable NWAM prior to using the setup script.

Running Tests
=============
Tests can be executed in one of two ways:
1) using "run_tests.sh"
2) using "one_test.sh"

The script "run_tests.sh" can be used from a host other than the SUT
but the script "one_test.sh" must be run on the SUT. It is currently
required that both scripts be started from the directory in which
they are found - i.e they must be run as "./run_tests.sh" or
"./one_test.sh" from within $IPF_VAR_DIR.

Using one_test.sh
-----------------
The script "one_test.sh" can be used to run one test. Its output will
be sent to stdout. It takes one argument, the name of the test to run.
An example of how to use this script is as follows:

# ./one_test.sh 1h_ipnat_flush_005_v4

Using run_tests.sh
------------------
The script "run_tests.sh" is used to run multiple tests within the same
job. It displays the name of each test that it is running plus a relative
position in the list of tests being executed. An example line of its
output might be:

Running 1h_ipnat_flush_005_v4 4/20

meaning that "1h_ipnat_flush_005_v4" is the fourth test being run out
of a list of 20 tests. At the end of the test, "run_tests.sh" will output
a list of each test run and whether or not that test failed or passed.
All of the output from each individual test is stored in a single log
file that is provided at the start of the test result summary. The
summary can be reproduced using the script "summary.sh" in the bin
directory and supplying the test log file as its argument.

The script "run_tests.sh" is supplied with a list of one or more words
that match test names. The simplest way to use "run_tests.sh" is with
one argument, like this:

# ./run_tests.sh 1h

This will run all 1-host tests, both IPv4 and IPv6. To just run the
IPv4 1-host tests, the following can be used:

# ./run_tests.sh 1hv4

Alternatively, this can also be used:

# ./run_tests.sh 1h\*v4

If the goal is to run both 1-host and 2-host tests, then the following
would be used to excecute both IPv4 and IPv6 tests:

# ./run_tests.sh 1h 2h

To run all IPv4 tests, 1-host, 2-host and 3-host:

# ./run_tests.sh v4

To run all tests that check stateful filtering capabilities then the
following can be used:

# ./run_tests.sh state

To run all of the tests that test NAT, then the following would be used:

# ./run_tests.sh ipnat

Finally, if the goal is to run a number of specific tests then it can be
invoked with a list of individual test names like this:

# ./run_tests,sh 1h_ipf_flush_001_v4 1h_ipnat_flush_005_v4

Adding Tests
============
If you wish to add further tests to this set of tests, then please
observe the following naming convention:

* a test must fall into one of three categories:
 - 1-host (1h) test
 - 2-host (2h) test
 - 3-host (3h) test.

 The two letter abbreviation is the first component of the test name.

* the network which is the primary focus of the testing, either "net0" or
  "net1". In 2-host testing, all tests will be on "net0".

* the application or protocol used for testing. Currently the list of
  supported applications and protocols is ftp, rsh, ping, tcp and udp.
  The mechanics of each test is found in "lib/ipf_lib.sh". For both
  tcp and udp, the test is required to start a server, use a client
  to interact with the server and stop the server.

* the next section of the test name comprises a short statement about
  what is actually being tested. If an "ipf" rule is an active part of
  the test then the word "ipf" should be present. The same applies for
  both "ipnat" and "ippool". For all "ipf" tests, the name must include
  either "pass" or "block to indicate whether the test is verifying the
  ability of IPFilter to allow or deny traffic. For all ipnat tests, the
  type of the rule (map, rdr, etc) must be part of the test name. If
  there are multiple types of ipnat rules being tested then all must be
  present in the test name.

* following the abbreviation of the components under test is a number.
  This number in some cases has meaning (for example, some of the 1-host
  parsing tests have a number that can be matched to the test suite that
  is inside of IP Filter) and in others it is simply a counter.

* the final part of a test name indicates which protocol it applies to,
  either v4 (IPv4) or v6 (IPv6).
 
