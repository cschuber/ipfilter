gen_ipf_conf() {
	cat <<__EOF__
block in quick log level user.debug inet6 proto icmp all
block in quick log level mail.info inet6 proto icmp all
block in quick log level daemon.notice inet6 proto icmp all
block in quick log level auth.warn inet6 proto icmp all
block in quick log level syslog.err inet6 proto icmp all
block in quick log level lpr.crit inet6 proto icmp all
block in quick log level news.alert inet6 proto icmp all
block in quick log level uucp.emerg inet6 proto icmp all
block in quick log level cron.debug inet6 proto icmp all
block in quick log level ftp.info inet6 proto icmp all
block in quick log level authpriv.notice inet6 proto icmp all
block in quick log level logalert.warn inet6 proto icmp all
block in quick log level local0.err inet6 proto icmp all
block in quick log level local1.crit inet6 proto icmp all
block in quick log level local2.alert inet6 proto icmp all
block in quick log level local3.emerg inet6 proto icmp all
block in quick log level local4.debug inet6 proto icmp all
block in quick log level local5.info inet6 proto icmp all
block in quick log level local6.notice inet6 proto icmp all
block in quick log level local7.warn inet6 proto icmp all
block in quick log level kern.err inet6 proto icmp all
block in quick log level security.emerg inet6 proto icmp all
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
	return $?;
}

do_tune() {
	return 0;
}

do_verify() {
	return 0;
}
