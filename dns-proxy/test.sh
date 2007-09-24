#!/bin/sh
YYDEBUG=1
export YYDEBUG
./dns-proxy -k -dddddddddd -f ./dns-proxy.conf
