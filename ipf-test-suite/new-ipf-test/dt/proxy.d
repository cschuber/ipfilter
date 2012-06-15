#!/usr/sbin/dtrace -Fs

fbt:ipf:ipf_proxy_check:entry/self->trace==0/{
	self->trace=1;
}
fbt:ipf:ipf_proxy_check:return/self->trace==1/{
	self->trace=0;
	printf("%d", (int)arg1);
}
fbt:ipf::entry/self->trace==1/{}
fbt:ipf::return/self->trace==1/{}

