#!/usr/sbin/dtrace -Fs

fbt:ipf:ipf_check:entry/self->trace == 0 && arg3 == 10/{self->trace=1;}
fbt:ipf:ipf_check:return/self->trace/{self->trace = 0;printf("%x", arg1);}

fbt:ipf::entry/self->trace/{}
fbt:ipf::return/self->trace/{
	printf("%x", arg1);
}
sdt:ipf::/self->trace/{}
sdt:ipf::ftp_client_command/self->trace/{
	printf("cmd[%s]", stringof(arg0));
}
sdt:ipf::ftp_client_passok/self->trace/{
	printf("cmd[%s] %d %d", stringof(arg0), arg1, arg2);
}
sdt:ipf::ftp_server_passok/self->trace/{
	printf("cmd[%s] %d %d", stringof(arg0), arg1, arg2);
}
sdt:ipf::ftp_server_response/self->trace/{
	printf("cmd[%s] %d", stringof(arg0), arg1);
}
