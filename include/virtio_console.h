#ifndef VIRTIO_CONSOLE_H
#define VIRTIO_CONSOLE_H

#include <stdint.h>
#include "virtio_control_regs.h"

#define VIRTIO_MMIO_BASE        0x10000000ULL
#define VIRTIO_MMIO_SIZE        0x1000

#define MAGIC_NUMBER            0x74726976
#define DEVICE_VERSION_NUMBER   0x2
#define DEVICE_ID               0x3

// Host offered features
// BIT(0) = VIRTIO_CONSOLE_F_SIZE
// BIT(32) = VIRTIO_F_VERSION_1
// BIT(35) = VIRTIO_F_IN_ORDER
extern uint64_t device_features;

// Guest accepted features; initialized to 0
extern uint64_t driver_features;

// Device status register
extern uint8_t device_status;

// Interrupt status register
extern uint8_t interrupt_status;

// Currently selected queue index
extern uint16_t queue_sel;

// Maximum queue size offerred by host
extern uint16_t queue_num_max;

// Virtqueue used for guest-device communication
struct virtqueue {
    uint64_t desc_addr;
    uint64_t avail_addr;
    uint64_t used_addr;
    uint16_t num;
    uint8_t queue_ready;
};

// Virtqueues used for device-guest communication
extern struct virtqueue queues[2];

// Device config space
struct console_config_space {
    uint16_t cols;
    uint16_t rows;
};

extern struct console_config_space console_config;

// Base address of guest "physical memory".
extern void* guest_physical_mem_base;

// Handler for KVM_EXIT_MMIO: driver read from memory mapped control registers belonging 
// to VirtIO console device).
void handle_mmio_read(uint64_t address, unsigned char* data, int len);

// Handler for KVM_EXIT_MMIO: driver wrote to memory mapped control registers belonging 
// to VirtIO console device).
void handle_mmio_write(uint64_t address, unsigned char* data, int len);

#endif