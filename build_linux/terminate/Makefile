PREFIX = riscv64-unknown-elf
TERMINATE = terminate

$(TERMINATE):
	$(PREFIX)-g++ -I.. -static main.cpp -o $(TERMINATE)
	$(PREFIX)-objdump -d $(TERMINATE) > $(TERMINATE).dump
