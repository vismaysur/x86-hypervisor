KERNEL_SRC := ~/linux-5.15.165
BUILD_DIR := $(PWD)/build
INCLUDE_DIR := $(PWD)/include

.PHONY: clean

all:
	@ mkdir -p build
	@ echo "=== Building Guest Code ==="
	@ $(TARGET)-gcc -ffreestanding -m32 -o2 -nostdlib -T $(PWD)/linker.ld guest/main.c -o build/guest.elf
	@ $(TARGET)-objcopy -O binary build/guest.elf build/guest.bin
	@ echo "Guest code size: $$(stat -c%s build/guest.bin) bytes"
	@ echo "=== Building VMM ==="
	@ gcc -Wall -g -I$(KERNEL_SRC)/include -I$(KERNEL_SRC)/arch/x86/include -I$(INCLUDE_DIR) src/main.c src/virtio_console.c -o $(BUILD_DIR)/main
	@ echo "=== Build Complete! ==="
	@ echo "Run with build/main"

clean:
	rm -rf $(BUILD_DIR)