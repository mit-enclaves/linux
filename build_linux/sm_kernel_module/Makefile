obj-m += lkm_sm.o

all: testenclave lkm_sm.ko

lkm_sm.ko:
	make -C ../riscv-linux M=$(PWD)

test: testenclave

testenclave: test.c
	riscv64-linux-gnu-gcc -g -O -static -o $@ test.c

modulesclean:
	make -C ../riscv-linux M=$(PWD) clean

