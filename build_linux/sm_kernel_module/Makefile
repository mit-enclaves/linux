obj-m += lkm_sm.o

all: testenclave lkm_sm.ko

lkm_sm.ko: lkm_sm.c
	make -C ../riscv-linux M=$(PWD)

testenclave: test.c
	riscv64-linux-gnu-gcc -g -O -static -o $@ test.c

modulesclean:
	make -C ../riscv-linux M=$(PWD) clean

