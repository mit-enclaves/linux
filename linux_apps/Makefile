API_DIR:=../../security_monitor/api
# Assumes: $(API_DIR)

CC=riscv64-unknown-linux-gnu-gcc

LINUX_APPS_INCLUDES := \
	$(API_DIR) \

TEST_DIR=bin
TARGET=$(TEST_DIR)/test_ecall

all: $(TARGET)

$(TEST_DIR):
	mkdir -p $(TEST_DIR)

$(TEST_DIR)/%: src/%.c $(TEST_DIR)
	$(CC) -static $(addprefix -I , $(LINUX_APPS_INCLUDES)) $< -o $@

.PHONY: clean
clean:
	rm -rf $(TEST_DIR)
