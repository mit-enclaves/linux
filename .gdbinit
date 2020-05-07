set arch riscv:rv64
#set riscv use_compressed_breakpoint off
layout split
foc cmd
set trace-commands on
set logging on
target remote localhost:1234
symbol-file build_linux/riscv-linux/vmlinux
add-symbol-file ../security_monitor/build/sm.elf 0x80003000
add-symbol-file ../security_monitor/build/sm.enclave.elf 0xf8000000
set directories /home/drean/Research/mit-enclaves/linux/build_linux/riscv-linux:$cdir:$cwd
#add-symbol-file build/master_test.elf 0x82000000
#add-symbol-file build/sm.enclave.elf  0x86000000
#add-symbol-file build/enclave.elf     0x0
