#!/bin/ash

echo "Hello World!" > /dev/console
insmod /test/lkm_sm.ko
mknod /dev/security_monitor c 10 127
./test/testenclave
