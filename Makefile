# Assumes: $(SM_BUILD_DIR)
# Assumes: $(SANCTUM_QEMU)
# Assumes: $(VMLINUX)

# Find the Root Directory
RUN_LINUX_DIR:=$(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

# Define compiler
PYTHON=python
CC=riscv64-unknown-elf-gcc

LINUX_OBJCOPY=riscv64-unknown-linux-gnu-objcopy

# Flags
DEBUG_FLAGS := -ggdb3
CFLAGS := -march=rv64g -mcmodel=medany -mabi=lp64 -fno-common -std=gnu11 -Wall -O0 $(DEBUG_FLAGS)
LDFLAGS := -nostartfiles -nostdlib -static

# QEMU
.PHONY: check_qemu_env
check_qemu_env:
ifndef SANCTUM_QEMU
	$(error SANCTUM_QEMU is undefined)
endif

QEMU_FLAGS= -smp cpus=2 -machine sanctum -m 2G -nographic
DEBUG_QEMU_FLAGS= -S -s

# Define Directories
BUILD_DIR:=$(RUN_LINUX_DIR)/build
PLATFORM_DIR := $(RUN_LINUX_DIR)/platform

# Binaries
.PHONY: check_bin_env
check_bin_env:
ifndef SM_BUILD_DIR
	$(error SM_BUILD_DIR is undefined)
endif

NULL_BOOT_BINARY := $(SM_BUILD_DIR)/null_boot.bin
SM_BINARY := $(SM_BUILD_DIR)/sm.bin
IDPT_BINARY := $(SM_BUILD_DIR)/idpt.bin

#TODO HACK HERE
SM_PLATFORM_DIR := $(SM_BUILD_DIR)/../platform

RUN_LINUX_INCLUDES := \
	$(SM_PLATFORM_DIR)

# Linux Binary
BUILD_LINUX_DIR:=$(RUN_LINUX_DIR)/build_linux

include $(BUILD_LINUX_DIR)/Makefile

.PHONY: check_vmlinux
check_vmlinux:
ifndef VMLINUX
$(info Default value for $$VMLINUX)
VMLINUX := $(BUILD_LINUX_DIR)/riscv-linux/vmlinux
else
$(info $$VMLINUX was defined as [${VMLINUX}])
endif
LINUX_BIN := $(BUILD_DIR)/vmlinux.bin

$(LINUX_BIN): check_vmlinux $(VMLINUX) 
	$(LINUX_OBJCOPY) -O binary --set-section-flags .bss=alloc,load,contents $(VMLINUX) $@

# Targets
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Preprocessor fills out linker script constants
RUN_LINUX_LDS := $(BUILD_DIR)/test-linux.lds

$(BUILD_DIR)/%.lds : %.lds.in
	$(CC) -E -x c $(addprefix -I , $(RUN_LINUX_INCLUDES)) $^ | grep -v '^#' > $@

# Platform Sources
ALL_TESTS_SRC := \
	$(PLATFORM_DIR)/htif.c \
	$(PLATFORM_DIR)/sm_keys.c \
	$(PLATFORM_DIR)/sm.S \
	$(PLATFORM_DIR)/idpt.S \

$(BUILD_DIR)/test_linux.elf: check_bin_env $(SM_TEST_LD) $(BUILD_DIR) $(SM_BINARY) $(IDPT_BINARY) $(LINUX_BIN) $(RUN_LINUX_LDS)
	$(CC) $(CFLAGS) $(addprefix -I , \
	$(RUN_LINUX_INCLUDES)) \
	$(LDFLAGS) \
	-T $(RUN_LINUX_LDS) \
	$(ALL_TESTS_SRC) \
	$(RUN_LINUX_DIR)/linux.S \
	-D IDPT_FILE=\"$(IDPT_BINARY)\" \
	-D SM_BINARY_FILE=\"$(SM_BINARY)\" \
	-D LINUX_FILE=\"$(LINUX_BIN)\" \
	-o $@

all: test_linux 

.PHONY: test_linux
test_linux: $(BUILD_DIR)/test_linux.elf

.PHONY: run_test_linux
run_test_linux: check_qemu_env $(BUILD_DIR)/test_linux.elf $(NULL_BOOT_BINARY)
	$(SANCTUM_QEMU) $(QEMU_FLAGS) --kernel $(BUILD_DIR)/test_linux.elf --bios $(NULL_BOOT_BINARY)

.PHONY: debug_test_linux
debug_test_linux: check_qemu_env $(BUILD_DIR)/test_linux.elf $(NULL_BOOT_BINARY)
	$(SANCTUM_QEMU) $(QEMU_FLAGS) $(DEBUG_QEMU_FLAGS) --kernel $(BUILD_DIR)/test_linux.elf --bios $(NULL_BOOT_BINARY)

.PHONY: clean
clean:
	-rm -rf $(BUILD_DIR)
