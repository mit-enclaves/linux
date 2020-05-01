obj-m += lkm_sm.o
all:
	make -C ../riscv-linux M=$(PWD)

test:
	riscv64-linux-gnu-gcc -static test.c
modulesclean:
	make -C ../riscv-linux M=$(PWD) clean

