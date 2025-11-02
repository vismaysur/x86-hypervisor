#ifndef VIRTIO_CONSOLE_H
#define VIRTIO_CONSOLE_H

#include "vhost_console.h"
#include <stdint.h>

#define VIRTIO_MMIO_BASE        0x10000000ULL
#define VIRTIO_MMIO_SIZE        0x1000

#define MAGIC_NUMBER            0x74726976
#define DEVICE_VERSION_NUMBER   0x2
#define DEVICE_ID               0x3

// Used for VHOST_SET_VRING_NUM ioctl
struct vhost_vring_state {
    uint16_t queue_sel;
    uint16_t num;
};

// Used for VHOST_SET_VRING_ADDR ioctl
struct vhost_vring_addr {
    uint16_t queue_sel;
    uint64_t desc_addr;
    uint64_t avail_addr;
    uint64_t used_addr;
};

// Used for VHOST_SET_VRING_KICK ioctl
struct vhost_vring_fd {
    uint16_t queue_sel;
    int      fd;
};

// Virtqueue used for guest-device communication
struct virtqueue {
    uint64_t desc_addr;
    uint64_t avail_addr;
    uint64_t used_addr;
    uint16_t num;
    uint8_t queue_ready;
};

// Device config space
struct console_config_space {
    uint16_t cols;
    uint16_t rows;
};

struct console_device {
    // Host offered features
    // BIT(0) = VIRTIO_CONSOLE_F_SIZE
    // BIT(32) = VIRTIO_F_VERSION_1
    // BIT(35) = VIRTIO_F_IN_ORDER
    uint64_t device_features;
    // Select lower (0) or upper (1) bits of features for subsequent ops
    uint8_t device_features_sel;
    // Guest accepted features; initialized to 0
    uint64_t driver_features;
    // Select lower (0) or upper (1) bits of features for subsequent ops
    uint8_t driver_features_sel;
    // Device status register
    uint8_t device_status;
    // Interrupt status register
    uint8_t interrupt_status;
    // Currently selected queue index
    uint16_t queue_sel;
    // Maximum queue size offerred by host
    uint16_t queue_num_max;
    // Virtqueues used for device-guest communication
    struct virtqueue queues[2];
    // Device config space
    struct console_config_space console_config;
};

extern struct console_device device;

// Base address of guest "physical memory".
extern void* guest_physical_mem_base;

// Handler for KVM_EXIT_MMIO: driver read from memory mapped control registers belonging 
// to VirtIO console device).
void handle_mmio_read(uint64_t address, unsigned char* data, int len, int vcpufd, struct vhost_state* state);

// Handler for KVM_EXIT_MMIO: driver wrote to memory mapped control registers belonging 
// to VirtIO console device).
int handle_mmio_write(uint64_t address, unsigned char* data, int len, int vcpufd, struct vhost_state* state, int output_fd);

#endif