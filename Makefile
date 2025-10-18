KERNEL_SRC := /home/vismay3003/linux-5.15.165
BUILD_DIR := $(PWD)/build

.PHONY: clean

all:
	mkdir -p build
	gcc -Wall -I$(KERNEL_SRC)/include -I$(KERNEL_SRC)/arch/x86/include src/main.c -o $(BUILD_DIR)/main

clean:
	rm -rf $(BUILD_DIR)