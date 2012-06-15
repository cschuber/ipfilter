#!/usr/sbin/dtrace -Fs

ipftoken_t *tok;

fbt:ipf:ipf_lookup_iterate:entry/self->trace==0/{
self->trace=1;
}

fbt:ipf:ipf_lookup_iterate:return/self->trace==1/{
	printf("%x", arg1);
	self->trace=0;
}
fbt:ipf::entry/self->trace/{}
fbt:ipf::return/self->trace/{printf("%x", arg1);}

fbt:ipf:ipf_token_deref:entry/self->trace/{
	tok = (ipftoken_t *)arg1;
	printf("ref %d", tok->ipt_ref);
}

fbt:ipf:ipf_token_expire:entry/self->expire == 0/{ self->expire=1;}
fbt:ipf:ipf_token_expire:return/self->expire == 1/{ self->expire=0;printf(".");}
fbt:ipf::entry/self->expire/{}
fbt:ipf::return/self->expire/{printf("%x", arg1);}
