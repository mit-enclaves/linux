#!/bin/ash

insmod /test/lkm_sm.ko
mknod /dev/security_monitor c 10 127
