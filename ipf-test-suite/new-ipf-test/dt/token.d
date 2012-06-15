#!/usr/sbin/dtrace -Fs

fbt:ipf:ipf_token_expire:entry{self->trace=1;}
fbt:ipf:ipf_token_expire:return/self->trace/{self->trace=0;printf(".");}
fbt:ipf::entry/self->trace/{}
fbt:ipf::return/self->trace/{}
fbt:ipf:ipf_frruleiter:entry/self->trace==0/{self->trace=1;}
fbt:ipf:ipf_frruleiter:return/self->trace/{self->trace=0;printf(".");}
fbt:ipf:ipf_token_deref:return/self->trace/{printf("%x", arg1); }
