gen_ipf_conf() {
	cat <<__EOF__
a=any;
b=\"from \$a\";
c='to \$a';
d=block;
e=\"pass in\";
$d in \$b \$c
f=\" \$b \$c\";
\$e\${f}
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
