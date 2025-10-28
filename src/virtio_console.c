#include "virtio_console.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// Host offered features
// BIT(0) = VIRTIO_CONSOLE_F_SIZE, BIT(32) = VIRTIO_F_VERSION_1
uint64_t device_features = (1ULL << 0) | (1ULL << 32);
// Select lower (0) or upper (1) bits of features for subsequent ops
uint8_t  device_features_sel = 0;

// Guest accepted features; initialized to 0
uint64_t driver_features = 0;
// Select lower (0) or upper (1) bits of features for subsequent ops
uint8_t  driver_features_sel = 0;

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

// Handler for KVM_EXIT_MMIO: driver read from memory mapped control registers belonging 
// to VirtIO console device).
void handle_mmio_read(uint64_t address, unsigned char* data, int len) {
    switch (address - VIRTIO_MMIO_BASE) {
        case REG_MAGIC: {
            uint32_t magicnum = MAGIC_NUMBER;
            memcpy(data, &magicnum, len);
            break;
        }
        case REG_DEVICE_VERSION: {
            uint32_t device_version = DEVICE_VERSION_NUMBER;
            memcpy(data, &device_version, len);
            break;
        }
        case REG_DEVICE_ID: {
            uint32_t device_id = DEVICE_ID;
            memcpy(data, &device_id, len);
            break;
        }
        case REG_STATUS: {
            memcpy(data, &device_status, len);
            break;
        }
        case REG_DEVICE_FEATURES: {
            memcpy(data, (char*) &device_features + 4 * device_features_sel, len);
            break;
        }
        default:
            fprintf(stderr, "[Error: doesn't handle MMIO read @ 0x%lx, of size %d]\n", address, len);
    }
}

// Handler for KVM_EXIT_MMIO: driver wrote to memory mapped control registers belonging 
// to VirtIO console device).
void handle_mmio_write(uint64_t address, unsigned char* data, int len) {
   switch (address - VIRTIO_MMIO_BASE) {
        case REG_STATUS: {
            uint8_t value_written;
            memcpy(&value_written, data, len);

            if (value_written == 0) { // Entire status register is zeroed
                printf("=== Resetting VirtIO console device ===\n");
                driver_features = 0;
                device_status = 0;
                interrupt_status = 0;
                queue_sel = 0;
            } else {
                uint8_t prev_status = device_status;
                device_status = value_written;
                
                uint8_t bit_changed = device_status ^ prev_status;

                switch (bit_changed) {
                    case 1: // ACKNOWLEDGE (1 ~= BIT 0)
                        printf("=== Guest OS has noticed device ===\n");
                        break;
                    case 2: // DRIVER (2 ~= BIT 1)
                        printf("=== Guest OS knows how to drive device ===\n");
                        break;
                    case 4: // DRIVER_OK (4 ~= BIT 2)
                        printf("=== Driver is set up; console device is live ===\n");
                        break;
                    // Driver has read device_features, and set its own bits in driver_features
                    // to request features; device must now enforce feature request correctness.
                    case 8: { // FEATURES_OK (8 ~= BIT 3)
                        if (driver_features & (~device_features)) {
                            printf("=== Feature negotation failed (driver requested unsupported features) ===\n");
                            device_status &= ~8;
                        }
                        else if (device_features != driver_features) {
                            printf("=== Feature negotiation failed (driver doesn't recognize mandatory features) ===\n");
                            device_status &= ~8;
                        } else {
                            printf("=== Driver has acknowledged recognizable features; feature negotiation complete ===\n");
                        }
                        break;
                    }
                    default:
                        fprintf(stderr, "[Error: guest driver wrote to undefined device status bit (%d)]\n", bit_changed);
                }
            }
            break;
        }
        case REG_DEVICE_FEATURES_SEL: {
            memcpy(&device_features_sel, data, len);
            break;
        }
        case REG_DRIVER_FEATURES: {
            memcpy((char*) &driver_features + 4 * driver_features_sel, data, len);
            break;
        }
        case REG_DRIVER_FEATURES_SEL: {
            memcpy(&driver_features_sel, data, len);
            break;
        }
        default:
            fprintf(stderr, "[Error: doesn't handle MMIO read @ 0x%lx, of size %d]\n", address, len);
    }
}