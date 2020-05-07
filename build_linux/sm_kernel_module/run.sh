#!/bin/ash
insmod /test/lkm_sm.ko
mknod /dev/security_monitor_dev c 10 58
./test/a.out
