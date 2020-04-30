# Assume TERMINATE_DIR

PREFIX = riscv64-unknown-elf
TERMINATE = $(TERMINATE_DIR)/terminate

$(TERMINATE):
	$(PREFIX)-g++ -I.. -static $(TERMINATE_DIR)/main.cpp -o $(TERMINATE)
	$(PREFIX)-objdump -d $(TERMINATE) > $(TERMINATE).dump
