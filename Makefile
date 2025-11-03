KERNEL_SRC := ~/linux-5.15.165
BUILD_DIR := $(PWD)/build
INCLUDE_DIR := $(PWD)/include
SRC_DIR := $(PWD)/src

obj-m := vhost_console.o
vhost_console-objs := src/vhost_console.o
ccflags-y := -Wall -I$(INCLUDE_DIR)

.PHONY: clean

all:
	@ mkdir -p build
	@ echo "=== Building Guest Code ==="
	@ $(TARGET)-gcc -ffreestanding -m32 -o2 -nostdlib -T $(PWD)/linker.ld -I$(INCLUDE_DIR) $(SRC_DIR)/guest.c -o $(BUILD_DIR)/guest.elf
	@ $(TARGET)-objcopy -O binary $(BUILD_DIR)/guest.elf $(BUILD_DIR)/guest.bin
	@ echo "Guest code size: $$(stat -c%s $(BUILD_DIR)/guest.bin) bytes"

	@ echo "=== Building VMM ==="
	@ gcc -Wall -g -I$(KERNEL_SRC)/include -I$(KERNEL_SRC)/arch/x86/include -I$(INCLUDE_DIR) $(SRC_DIR)/main.c $(SRC_DIR)/virtio_console.c -o $(BUILD_DIR)/main
	
	@ echo "=== Building Vhost Kernel Module ==="
	make -C $(KERNEL_SRC) M=$(PWD) modules

	# 	Reorganize build output
	mv -f *.o *.mod *.mod.c *.ko *.symvers *.order *.cmd $(BUILD_DIR)/ 2>/dev/null || true
	mv -f .*.cmd $(BUILD_DIR)/ 2>/dev/null || true
	mv -f $(SRC_DIR)/*.o $(SRC_DIR)/*.cmd $(SRC_DIR)/.*.cmd $(BUILD_DIR)/ 2>/dev/null || true

	@ echo "=== Build Complete! ==="
	@ echo "Run with build/main"

clean:
	make -C $(KERNEL_SRC) M=$(PWD) clean
	rm -rf $(BUILD_DIR)