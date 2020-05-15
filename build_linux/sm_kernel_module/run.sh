#!/bin/ash

echo hello > /dev/ttyS0
insmod /test/lkm_sm.ko
mknod /dev/security_monitor c 10 58
./test/testenclave
echo world > /dev/console
