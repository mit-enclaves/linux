obj-m += lkm_sm.o

all: testenclave lkm_sm.ko

lkm_sm.ko: lkm_sm.c
	make -C ../riscv-linux M=$(PWD)

TEST_SRC := test.c inputs.c crypto_enclave_api.c msgq/msgq.c

testenclave: $(TEST_SRC) 
	$(CROSS_COMPILE)gcc -g -O -static -march=rv64g -o $@ $(TEST_SRC)

modulesclean:
	make -C ../riscv-linux M=$(PWD) clean

clean: modulesclean
	rm -rf testenclave
