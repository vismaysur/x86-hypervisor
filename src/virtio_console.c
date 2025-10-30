#include "virtio_console.h"
#include "helpers.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// Host offered features
// BIT(0) = VIRTIO_CONSOLE_F_SIZE
// BIT(32) = VIRTIO_F_VERSION_1
// BIT(35) = VIRTIO_F_IN_ORDER
uint64_t device_features = (1ULL << 0) | (1ULL << 32) | (1ULL << 35); 
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

// Maximum queue size offerred by host (tuned to fit one page)
uint16_t queue_num_max = 38;

// Virtqueues used for device-guest communication
struct virtqueue queues[2] = {0}; // 0: rx, 1: tx

// Device config space
struct console_config_space console_config = {
    .cols = 80,
    .rows = 24
};

// Convert guest "physical" address to host virtual address
static inline void* guest_to_host_va(uint32_t ptr) {
    return (char *) guest_physical_mem_base + (ptr - 0x1000); 
}

static inline void initialize_used_ring(void* ring_addr) {
    // used->flags
    *((char*) ring_addr) = 0;           
    // used->idx
    *((char*) ring_addr + 16) = 0;
}

static inline void walk_used_vring() {    
    char* avail_base = (char *) guest_to_host_va(queues[queue_sel].avail_addr);
    uint16_t avail_idx = *(uint16_t*)(avail_base + 2);

    char* used_base = (char *) guest_to_host_va(queues[queue_sel].used_addr);
    uint16_t used_idx = *(uint16_t*)(used_base + 2);

    char* desc_base = (char *) guest_to_host_va(queues[queue_sel].desc_addr);
    
    while (used_idx != avail_idx) {
        uint16_t* avail_ring_entry = (uint16_t *) (avail_base + 4 + 2 * used_idx);
        uint16_t desc_idx = *(avail_ring_entry);

        char* desc_ring_entry = (desc_base + desc_idx * 16);
        uint64_t addr = *(uint64_t*)(desc_ring_entry);
        uint32_t len = *(uint32_t*)(desc_ring_entry + 8);
        // uint16_t flags = *(uint16_t*)(desc_ring_entry + 12);
        // uint16_t next = *(uint16_t*)(desc_ring_entry + 14); 

        char* buffer_addr = guest_to_host_va(addr);

        // EMULATE CONSOLE!!
        printf("%.*s", len, buffer_addr);         

        used_idx = (used_idx + 1) % queues[queue_sel].num;
    }

    // update used_idx to reflect walked used vring entries
    *(uint16_t*)(used_base + 2) = used_idx;
}

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
        case REG_QUEUE_NUM_MAX: {
            memcpy(data, &queue_num_max, len);
            break;
        }
        default:
            fprintf(stderr, ERROR_COLOR "[Error: doesn't handle MMIO read @ 0x%lx, of size %d]\n" RESET_COLOR, address, len);
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
                printf(DEBUG_COLOR "=== Resetting VirtIO console device ===\n" RESET_COLOR);
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
                        printf(DEBUG_COLOR "=== Guest OS has noticed device ===\n" RESET_COLOR);
                        break;
                    case 2: // DRIVER (2 ~= BIT 1)
                        printf(DEBUG_COLOR "=== Guest OS knows how to drive device ===\n" RESET_COLOR);
                        break;
                    case 4: // DRIVER_OK (4 ~= BIT 2)
                        printf(DEBUG_COLOR "=== Driver is set up; console device is live ===\n" RESET_COLOR);
                        break;
                    // Driver has read device_features, and set its own bits in driver_features
                    // to request features; device must now enforce feature request correctness.
                    case 8: { // FEATURES_OK (8 ~= BIT 3)
                        if (driver_features & (~device_features)) {
                            printf(DEBUG_COLOR "=== Feature negotation failed (driver requested unsupported features) ===\n" RESET_COLOR);
                            device_status &= ~8;
                        }
                        else if (device_features != driver_features) {
                            printf(DEBUG_COLOR "=== Feature negotiation failed (driver doesn't recognize mandatory features) ===\n" RESET_COLOR);
                            device_status &= ~8;
                        } else {
                            printf(DEBUG_COLOR "=== Driver has acknowledged recognizable features; feature negotiation complete ===\n" RESET_COLOR);
                        }
                        break;
                    }
                    default:
                        fprintf(stderr, ERROR_COLOR "[Error: guest driver wrote to undefined device status bit (%d)]\n" RESET_COLOR, bit_changed);
                }
            }
            break;
        }
        case REG_QUEUE_NOTIFY: {
            walk_used_vring();
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
        case REG_QUEUE_SEL: {
            memcpy(&queue_sel, data, len);
            break;
        }
        case REG_QUEUE_NUM: {
            memcpy(&queues[queue_sel].num, data, len);
            break;
        }
        case REG_QUEUE_DESC_LOW: {
            memcpy(&queues[queue_sel].desc_addr, data, len);
            break;
        }
        case REG_QUEUE_DRIVER_LOW: {
            memcpy(&queues[queue_sel].avail_addr, data, len);
            break;
        }
        case REG_QUEUE_DEVICE_LOW: {
            memcpy(&queues[queue_sel].used_addr, data, len);
            // host is responsible for properly setting up the virtqueue used rings.
            void* used_ring = guest_to_host_va(queues[queue_sel].used_addr);
            initialize_used_ring(used_ring);
            break;
        }
        // we ignore upper 32 bits of addrs in this implementation
        case REG_QUEUE_DESC_HIGH:
        case REG_QUEUE_DRIVER_HIGH:
        case REG_QUEUE_DEVICE_HIGH:
            break;
        default:
            fprintf(stderr, ERROR_COLOR "[Error: doesn't handle MMIO read @ 0x%lx, of size %d]\n" RESET_COLOR, address, len);
    }
}