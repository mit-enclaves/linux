# Assume python
# Assume BUILD_LINUX_DIR

JOBS ?= 8

# Busybox
BUSYBOX=$(BUILD_DIR)/busybox/busybox-1.21.1/busybox

$(BUILD_DIR)/busybox:
	mkdir -p $@

$(BUILD_DIR)/busybox/busybox-1.21.1:
	mkdir -p $@

$(BUILD_DIR)/busybox/busybox-1.21.1.tar.bz2: $(BUILD_DIR)/busybox
	curl -o $@ https://busybox.net/downloads/busybox-1.21.1.tar.bz2

$(BUILD_DIR)/busybox/busybox-1.21.1: $(BUILD_DIR)/busybox/busybox-1.21.1.tar.bz2
	cd `dirname $@`; tar -xf busybox-1.21.1.tar.bz2

$(BUILD_DIR)/busybox/busybox-1.21.1/.config: $(RUN_LINUX_DIR)/build_linux/linux_configs/busybox_config $(BUILD_DIR)/busybox/busybox-1.21.1
	cp -v $< $@

$(BUSYBOX): $(BUILD_DIR)/busybox/busybox-1.21.1 $(BUILD_DIR)/busybox/busybox-1.21.1/.config
	cd `dirname $@`; make -j$(JOBS)

# Terminate
TERMINATE_DIR:=$(BUILD_LINUX_DIR)/terminate
include $(TERMINATE_DIR)/Makefile

# Build Linux
.PHONY: build_linux
build_linux: $(BUSYBOX) $(TERMINATE)
	python $(BUILD_LINUX_DIR)/build-linux.py --jobs $(JOBS)
