#!/bin/bash

set -e

if [ $# -ne 0 ]; then
    JOBS=$1
else
    JOBS=1
fi

CURDIR=`pwd`
BUILD_DIR=$CURDIR/build/busybox

mkdir -p $BUILD_DIR

cd $BUILD_DIR
rm -rf busybox*
wget https://busybox.net/downloads/busybox-1.21.1.tar.bz2
tar -xf busybox-1.21.1.tar.bz2
cd busybox-1.21.1
cp $CURDIR/build_linux/linux_configs/busybox_config .config
make -j$JOBS

cd $CURDIR
echo "busybox compiled successfully"
