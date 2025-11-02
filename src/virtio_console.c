#include "virtio_console.h"
#include "helpers.h"
#include "virtio_control_regs.h"
#include <errno.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include "vhost_console.h"

struct console_device device = {
    // Host offered features
    // BIT(0) = VIRTIO_CONSOLE_F_SIZE
    // BIT(32) = VIRTIO_F_VERSION_1
    // BIT(35) = VIRTIO_F_IN_ORDER
    .device_features = (1ULL << 0) | (1ULL << 32) | (1ULL << 35),
    // Select lower (0) or upper (1) bits of features for subsequent ops
    .device_features_sel = 0,
    // Guest accepted features; initialized to 0
    .driver_features = 0,
    // Select lower (0) or upper (1) bits of features for subsequent ops
    .driver_features_sel = 0,
    // Device status register
    .device_status = 0,
    // Interrupt status register
    .interrupt_status = 0,
    // Currently selected queue index
    .queue_sel = 0,
    // Maximum queue size offerred by host (tuned to fit one page)
    .queue_num_max = 38,
    // Virtqueues used for device-guest communication
    .queues = {{0}},
    // Device config space
    .console_config = {
        .cols = 80,
        .rows = 24,
    }
};

// // Manually injects interrupt into VM
// static inline int inject_interrupt_manual(int vcpufd, uint32_t irq_number) {
//     struct kvm_interrupt irq = {
//         .irq = irq_number
//     };

//     int ret = ioctl(vcpufd, KVM_INTERRUPT, &irq);
//     if (ret == -1) {
//         fprintf(stderr, ERROR_COLOR "ioctl(): %s\n" RESET_COLOR, strerror(errno));
//         return 1;
//     }

//     return 0;
// }

// Convert guest "physical" address to host virtual address
static inline void* guest_to_host_va(uint32_t ptr) {
    return (char *) guest_physical_mem_base + (ptr - 0x1000); 
}

// Initialization is done in kernel-space (Vhost)
// Userspace func kept here for benchmarking.
static inline void initialize_used_ring(void* ring_addr) {
    // used->flags
    *((char*) ring_addr) = 0;           
    // used->idx
    *((char*) ring_addr + 16) = 0;
}

// Virtqueue is done in kernel-space (Vhost)
// Userspace func kept here for benchmarking.
static inline void walk_used_vring(uint8_t selected_queue, int vcpufd, int outputfd) {    
    char* avail_base = (char *) guest_to_host_va(device.queues[selected_queue].avail_addr);
    uint16_t avail_idx = *(uint16_t*)(avail_base + 2);

    char* used_base = (char *) guest_to_host_va(device.queues[selected_queue].used_addr);
    uint16_t used_idx = *(uint16_t*)(used_base + 2);

    char* desc_base = (char *) guest_to_host_va(device.queues[selected_queue].desc_addr);
    
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
        dprintf(outputfd, "%.*s", len, buffer_addr);         

        used_idx = (used_idx + 1) % device.queues[selected_queue].num;
    }

    // update used_idx to reflect walked used vring entries
    *(uint16_t*)(used_base + 2) = used_idx;

    device.interrupt_status |= 1;
    // inject_interrupt_manual(vcpufd, 33);
}

// Handler for KVM_EXIT_MMIO: driver read from memory mapped control registers belonging 
// to VirtIO console device).
void handle_mmio_read(uint64_t address, unsigned char* data, int len, int vcpufd, struct vhost_state* state) {
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
            memcpy(data, &device.device_status, len);
            break;
        }
        case REG_DEVICE_FEATURES: {
            memcpy(data, (char*) &device.device_features + 4 * device.device_features_sel, len);
            break;
        }
        case REG_QUEUE_NUM_MAX: {
            memcpy(data, &device.queue_num_max, len);
            break;
        }
        case REG_QUEUE_READY: {
            memcpy(data, &device.queues[device.queue_sel].queue_ready, len);
            break;
        }
        default:
            fprintf(stderr, ERROR_COLOR "[Error: doesn't handle MMIO read @ 0x%lx, of size %d]\n" RESET_COLOR, address, len);
    }
}

// Handler for KVM_EXIT_MMIO: driver wrote to memory mapped control registers belonging 
// to VirtIO console device).
int handle_mmio_write(uint64_t address, unsigned char* data, int len, int vcpufd, struct vhost_state* state, int output_fd) {
   switch (address - VIRTIO_MMIO_BASE) {
        case REG_STATUS: {
            uint8_t value_written;
            memcpy(&value_written, data, len);

            if (value_written == 0) { // Entire status register is zeroed
                printf(DEBUG_COLOR "=== Resetting VirtIO console device ===\n" RESET_COLOR);
                device.driver_features = 0;
                device.device_status = 0;
                device.interrupt_status = 0;
                device.queue_sel = 0;
            } else {
                uint8_t prev_status = device.device_status;
                device.device_status = value_written;
                
                uint8_t bit_changed = device.device_status ^ prev_status;

                switch (bit_changed) {
                    case 1: // ACKNOWLEDGE (1 ~= BIT 0)
                        printf(DEBUG_COLOR "=== Guest OS has noticed device ===\n" RESET_COLOR);
                        break;
                    case 2: // DRIVER (2 ~= BIT 1)
                        printf(DEBUG_COLOR "=== Guest OS knows how to drive device ===\n" RESET_COLOR);
                        break;
                    case 4: { // DRIVER_OK (4 ~= BIT 2)
                        printf(DEBUG_COLOR "=== Driver is set up; console device is live ===\n" RESET_COLOR);
                        // If DRIVER_OK is set, after it sets DEVICE_NEEDS_RESET, the device MUST send a device configuration change notification to the driver.
                        if (device.device_status & (1 << 6)) {
                            device.interrupt_status |= (1 << 1);
                            // inject_interrupt_manual(vcpufd, 33);
                        }
                        break;
                    }
                    // Driver has read device_features, and set its own bits in driver_features
                    // to request features; device must now enforce feature request correctness.
                    case 8: { // FEATURES_OK (8 ~= BIT 3)
                        if (device.driver_features & (~device.device_features)) {
                            printf(DEBUG_COLOR "=== Feature negotation failed (driver requested unsupported features) ===\n" RESET_COLOR);
                            device.device_status &= ~8;
                        }
                        else if (device.device_features != device.driver_features) {
                            printf(DEBUG_COLOR "=== Feature negotiation failed (driver doesn't recognize a mandatory feature) ===\n" RESET_COLOR);
                            device.device_status &= ~8;
                        } else {
                            printf(DEBUG_COLOR "=== Driver has acknowledged recognizable features; feature negotiation complete ===\n" RESET_COLOR);
                        }
                        break;
                    }
                    case 128: { // FAILED (128 ~= BIT 7)
                        printf(DEBUG_COLOR "=== Device initialization failed ===\n" RESET_COLOR);
                        break;
                    }
                    default:
                        fprintf(stderr, ERROR_COLOR "[Error: guest driver wrote to undefined device status bit (%d)]\n" RESET_COLOR, bit_changed);
                }
            }
            break;
        }
        case REG_QUEUE_NOTIFY: {
            // Virtqueue processing should be done in kernel-space (Vhost)
            // Userspace logic kept here for benchmarking

            // The device MUST NOT consume buffers or send any used buffer notifications 
            // to the driver before DRIVER_OK.
            if (!(device.device_status & 4)) return 0;

            uint8_t queue_sel;
            memcpy(&queue_sel, data, len);

            // Devices for which QueueReady is set to 0 must not be active.
            if (!device.queues[queue_sel].queue_ready) return 0;

            walk_used_vring(queue_sel, vcpufd, output_fd);
            break;
        }
        case REG_DEVICE_FEATURES_SEL: {
            memcpy(&device.device_features_sel, data, len);
            break;
        }
        case REG_DRIVER_FEATURES: {
            memcpy((char*) &device.driver_features + 4 * device.driver_features_sel, data, len);
            break;
        }
        case REG_DRIVER_FEATURES_SEL: {
            memcpy(&device.driver_features_sel, data, len);
            break;
        }
        case REG_QUEUE_SEL: {
            memcpy(&device.queue_sel, data, len);
            break;
        }
        case REG_QUEUE_NUM: {
            memcpy(&device.queues[device.queue_sel].num, data, len);
            break;
        }
        case REG_QUEUE_DESC_LOW: {
            memcpy(&device.queues[device.queue_sel].desc_addr, data, len);
            break;
        }
        case REG_QUEUE_DRIVER_LOW: {
            memcpy(&device.queues[device.queue_sel].avail_addr, data, len);
            break;
        }
        case REG_QUEUE_DEVICE_LOW: {
            memcpy(&device.queues[device.queue_sel].used_addr, data, len);
            // host is responsible for properly setting up the virtqueue used rings.
            void* used_ring = guest_to_host_va(device.queues[device.queue_sel].used_addr);
            initialize_used_ring(used_ring);
            break;
        }
        // we ignore upper 32 bits of addrs in this implementation
        case REG_QUEUE_DESC_HIGH:
        case REG_QUEUE_DRIVER_HIGH:
        case REG_QUEUE_DEVICE_HIGH:
            break;
        case REG_QUEUE_READY: {
            memcpy(&device.queues[device.queue_sel].queue_ready, data, len);
            
            // Activate queue in kernel space if vhost acceleration is enabled
            if (device.queues[device.queue_sel].queue_ready && state->vhostfd != -1) {
                int ret;

                struct vhost_vring_state vring_state = {
                    .queue_sel = device.queue_sel,
                    .num = device.queues[device.queue_sel].num
                };

                ret = ioctl(state->vhostfd, VHOST_SET_VRING_NUM, &vring_state);
                if (ret == -1) {
                    fprintf(
                        stderr, 
                        "VHOST_SET_VRING_NUM ioctl() failed: %s\n", 
                        strerror(errno)
                    );
                    return 1;
                }

                struct vhost_vring_addr addr = {
                    .queue_sel = device.queue_sel,
                    .desc_addr = device.queues[device.queue_sel].desc_addr,
                    .avail_addr = device.queues[device.queue_sel].avail_addr,
                    .used_addr = device.queues[device.queue_sel].used_addr
                };

                ret = ioctl(state->vhostfd, VHOST_SET_VRING_ADDR, &addr);
                if (ret == -1) {
                    fprintf(
                        stderr,
                        "VHOST_SET_VRING_ADDR ioctl() failed: %s\n",
                        strerror(errno)
                    );
                    return 1;
                }

                struct vhost_vring_fd file = {
                    .queue_sel = device.queue_sel,
                    .fd = output_fd,
                };

                ret = ioctl(state->vhostfd, VHOST_SET_OUTPUT_FD, &file);
                if (ret == -1) {
                    fprintf(
                        stderr,
                        "VHOST_SET_OUTPUT_FD ioctl() failed: %s\n",
                        strerror(errno)
                    );
                    return 1;
                }

                file.queue_sel = device.queue_sel;
                file.fd = state->kick_efd;

                ret = ioctl(state->vhostfd, VHOST_SET_VRING_KICK, &file);
                if (ret == -1) {
                    fprintf(
                        stderr,
                        "VHOST_SET_VRING_KICK ioctl() failed: %s\n",
                        strerror(errno)
                    );
                    return 1;
                }
            }
            break;
        }
        case REG_INTERRUPT_ACK: {
            uint8_t interrupt_acked;
            memcpy(&interrupt_acked, data, len);
            device.interrupt_status ^= interrupt_acked;
            break;
        }
        default:
            fprintf(stderr, ERROR_COLOR "[Error: doesn't handle MMIO read @ 0x%lx, of size %d]\n" RESET_COLOR, address, len);
    }

    return 0;
}