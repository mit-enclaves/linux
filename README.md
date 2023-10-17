# Linux Building Tools And Security Monitor Kernel Module

This repository contains tools and scripts to compile Linux to run on Citadel. It also contains the code for the SM Kernel Module to enable Linux to interract with the Security Monitor and allow applications to launch secure enclaves.

# Build Linux

## Global Variable:

### Mendatory

####  SM_BUILD_DIR

    The build directory of the Security Monitor that must contain :
      - sm.bin 
      - idpt.bin
      - null_boot.bin
    that can be obtained by running 'make master_test' in that repo

#### SANCTUM_QEMU

    A qemu with a Sanctum Machine

### Optionnal

####  VMLINUX

    A vmlinux elf to run on top of the SM. The default value is the vmlinux built by 'make buil_linux' in the build_linux directory

## Make Target

### build the sm kernel module first

  At the moment it requires to first build the sm kernel module.
  In order to do so, go in build_linix/sm_kernel_module
  run 'make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu-'
  then 'make test'
  
### build_linux

  To build the default vmlinux. 

### test_linux

  Take whatever VMLINUX is passed as an argument and wrap it on top of the SM and a null bootloader

### run_test_linux

  Same but run the obtained image in QEMU

### debug_test_linux

  Same but stop QEMU before the first instruction and wait for GDB to connect
