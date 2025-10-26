#include "virtio_console.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// Host offered features
// BIT(0) = VIRTIO_CONSOLE_F_SIZE, BIT(32) = VIRTIO_F_VERSION_1
uint64_t device_features = (1ULL << 0) | (1ULL << 32);

// Guest accepted features; initialized to 0
uint64_t driver_features = 0;

// Device status register
uint8_t device_status = 0;

// Interrupt status register
uint8_t interrupt_status = 0;

// Currently selected queue index
uint16_t queue_sel = 0;

// Maximum queue size offerred by host
uint16_t queue_num_max = 4;

// Virtqueues used for device-guest communication
struct virtqueue queues[2] = {0}; // 0: rx, 1: tx

// Device config space
struct console_config_space console_config = {
    .cols = 80,
    .rows = 24
};

void handle_mmio_read(uint64_t address, unsigned char* data, int len) {
    switch (address - VIRTIO_MMIO_BASE) {
        case 0x000: {
            uint32_t magicnum = MAGIC_NUMBER;
            memcpy(data, &magicnum, len);
            break;
        }
        case 0x004: {
            uint32_t device_version = DEVICE_VERSION_NUMBER;
            memcpy(data, &device_version, len);
            break;
        }
        case 0x008: {
            uint32_t device_id = DEVICE_ID;
            memcpy(data, &device_id, len);
            break;
        }
        default:
            printf("Should handle MMIO read @ 0x%lx, of size %d\n", address, len);
    }
}

void handle_mmio_write(uint64_t address, unsigned char* data, int len) {
   printf("Should handle MMIO write @ 0x%lx, of size %d\n", address, len); 
}