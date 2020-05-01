#!/bin/ash
insmod lkm_sm.ko
mknod /dev/security_monitor_dev c 10 58
./a.out
