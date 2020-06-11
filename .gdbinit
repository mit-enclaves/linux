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
add-symbol-file ../enclave_test_mail/build/enclave.elf 0x0
set directories /home/drean/Research/mit-enclaves/linux/build_linux/riscv-linux:$cdir:$cwd
b sm_internal_perform_enclave_exit
b sm_internal_enclave_enter
b sm_internal_mail_accept
b sm_internal_mail_receive
b sm_internal_mail_send
