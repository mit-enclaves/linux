# Assume python
# Assume BUILD_LINUX_DIR

# Busybox
BUSYBOX=$(BUILD_DIR)/busybox/busybox-1.21.1/busybox
$(BUSYBOX):
	$(BUILD_LINUX_DIR)/build-busybox.sh

# Terminate
TERMINATE_DIR:=$(BUILD_LINUX_DIR)/terminate
include $(TERMINATE_DIR)/Makefile

# Build Linux
.PHONY: build_linux
build_linux: $(BUSYBOX) $(TERMINATE)
	python $(BUILD_LINUX_DIR)/build-linux.py --jobs 16
