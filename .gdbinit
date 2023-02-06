set arch riscv:rv64
#set riscv use_compressed_breakpoint off
layout split
foc cmd
set trace-commands on
set logging on
target remote localhost:1234
symbol-file build_linux/riscv-linux/vmlinux
add-symbol-file build_linux/riscv-linux/vmlinux 0x82000000
add-symbol-file ../secure_shared_memory/build/sm.elf 0x80000000
add-symbol-file ../secure_shared_memory/build/sm.enclave.elf 0xf8001000
add-symbol-file /mnt/efs/fs1/micropython/ports/bare-riscv/build/firmware.elf 0x0
set directories /home/drean/Research/mit-enclaves/linux/build_linux/riscv-linux:$cdir:$cwd
