gen_ipf_conf() {
	cat <<__EOF__
block in quick log level user.debug proto icmp all
block in quick log level mail.info proto icmp all
block in quick log level daemon.notice proto icmp all
block in quick log level auth.warn proto icmp all
block in quick log level syslog.err proto icmp all
block in quick log level lpr.crit proto icmp all
block in quick log level news.alert proto icmp all
block in quick log level uucp.emerg proto icmp all
block in quick log level cron.debug proto icmp all
block in quick log level ftp.info proto icmp all
block in quick log level authpriv.notice proto icmp all
block in quick log level logalert.warn proto icmp all
block in quick log level local0.err proto icmp all
block in quick log level local1.crit proto icmp all
block in quick log level local2.alert proto icmp all
block in quick log level local3.emerg proto icmp all
block in quick log level local4.debug proto icmp all
block in quick log level local5.info proto icmp all
block in quick log level local6.notice proto icmp all
block in quick log level local7.warn proto icmp all
block in quick log level kern.err proto icmp all
block in quick log level security.emerg proto icmp all
__EOF__
	return 0;
}

gen_ipnat_conf() {
	return 1;
}

gen_ippool_conf() {
	return 1;
}

do_test() {
	validate_loaded_ipf_conf
	return $?
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
