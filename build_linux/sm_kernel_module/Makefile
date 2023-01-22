obj-m += lkm_sm.o

all: testenclave lkm_sm.ko

lkm_sm.ko: lkm_sm.c
	make -C ../riscv-linux M=$(PWD)

testenclave: test.c
	$(CROSS_COMPILE)gcc -g -O -static -march=rv64g -o $@ test.c

modulesclean:
	make -C ../riscv-linux M=$(PWD) clean

clean: modulesclean
	rm -rf testenclave
