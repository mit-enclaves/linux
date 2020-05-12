#!/bin/ash

echo hello > /dev/ttyS0
insmod /test/lkm_sm.ko
mknod /dev/security_monitor_dev c 10 58
./test/a.out
echo world > /dev/console
