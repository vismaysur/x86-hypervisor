// bare-metal code with no stdlib, compiled to 32-bit protected mode x86 assembly

#include <stdint.h>
#include "virtio_control_regs.h"

#define SERIAL_COM1_PORT        0x3F8  
#define VIRTIO_MMIO_BASE        0x10000000
#define CONSOLE_QUEUE_DESC      0x5000
#define CONSOLE_QUEUE_DRIVER    0x5100
#define CONSOLE_QUEUE_DEVICE    0x5200
#define CONSOLE_VIRTQUEUE_SIZE  0x10

uint16_t next_free_desc = 0;
uint8_t interrupt_received = 0;

struct idt_entry {
   uint16_t offset_low;         // offset bits 0..15
   uint16_t selector;           // a code segment selector in GDT or LDT
   uint8_t  zero;               // unused, set to 0
   uint8_t  type_attributes;    // gate type, dpl, and p fields
   uint16_t offset_high;        // offset bits 16..31
} __attribute__((packed));

struct idt_entry idt[256] __attribute__((aligned(8)));

struct {
    uint32_t offset;    // base
    uint16_t size;      // bounds
} __attribute__((packed)) idtr;

__attribute__((always_inline))
static inline void outb(uint16_t port, uint8_t val) {
    asm volatile (
        "outb %[v], %[p]"
        :
        : [v] "a" (val), [p] "d" (port)
    );
}

__attribute__((always_inline))
static inline uint32_t mmio_read32(volatile void* base, uint32_t offset /* in bytes */) {
    asm volatile("mfence" ::: "memory");
    uint32_t* val = (uint32_t *)((char *) base + offset);
    asm volatile("mfence" ::: "memory");
    return *val;
}

__attribute__((always_inline))
static inline uint16_t mmio_read16(volatile void* base, uint32_t offset /* in bytes */) {
    asm volatile("mfence" ::: "memory");
    uint16_t* val = (uint16_t *)((char *) base + offset);
    asm volatile("mfence" ::: "memory");
    return *val;
}

__attribute__((always_inline))
static inline uint8_t mmio_read8(volatile void* base, uint32_t offset /* in bytes */) {
    asm volatile("mfence" ::: "memory");
    uint8_t* val = (uint8_t *)((char *) base + offset);
    asm volatile("mfence" ::: "memory");
    return *val;
}

__attribute__((always_inline))
static inline void mmio_write32(volatile void* base, uint32_t offset /* in bytes */, uint32_t val) {
    asm volatile("mfence" ::: "memory");
    *(uint32_t *)((char *) base + offset) = val;
    asm volatile("mfence" ::: "memory");
}

__attribute__((always_inline))
static inline void mmio_write16(volatile void* base, uint32_t offset /* in bytes */, uint16_t val) {
    asm volatile("mfence" ::: "memory");
    *(uint16_t *)((char *) base + offset) = val;
    asm volatile("mfence" ::: "memory");
}

__attribute__((always_inline))
static inline void mmio_write8(volatile void* base, uint32_t offset /* in bytes */, uint8_t val) {
    asm volatile("mfence" ::: "memory");
    *(uint8_t *)((char *) base + offset) = val;
    asm volatile("mfence" ::: "memory");
}

__attribute__((always_inline))
static inline void print_error_to_serial(char* error_message) {
    for (int i = 0; ; i++) {
        if (error_message[i] == '\0') break;
        outb(SERIAL_COM1_PORT, error_message[i]);
    }
}

__attribute__((always_inline))
static inline void exit_with_error(char* error_message) {
    print_error_to_serial(error_message);
    while (1) asm("hlt");
}

__attribute__((always_inline))
static inline void init_virtio_console() {
    volatile void* device_mmio_base = (void *) VIRTIO_MMIO_BASE;

    // verify magic number
    
    if (mmio_read32(device_mmio_base, REG_MAGIC) != 0x74726976) 
        exit_with_error("=== Driver error: invalid magic number ===\n");

    // verify device version number
    if (mmio_read32(device_mmio_base, REG_DEVICE_VERSION) != 0x2)
        exit_with_error("=== Driver error: invalid device version ===\n");

    // verify device id of console
    if (mmio_read32(device_mmio_base, REG_DEVICE_ID) != 0x3)
        exit_with_error("=== Driver error: invalid device id ===\n");

    uint8_t device_status = 0x00;

    // reset device by writing to REG_STATUS
    mmio_write8(device_mmio_base, REG_STATUS, device_status);

    // set ACKNOWLEDGE status bit (notice this device)
    device_status |= 0x01;
    mmio_write8(device_mmio_base, REG_STATUS, device_status);

    // set DRIVER status bit (indicate driver knows how to drive device)
    device_status |= 0x02;
    mmio_write8(device_mmio_base, REG_STATUS, device_status);

    /*
     * read device feature bits and check support for features required by driver
     */

    // BIT(0) = VIRTIO_CONSOLE_F_SIZE
    // BIT(32) = VIRTIO_F_VERSION_1
    // BIT(35) = VIRTIO_F_IN_ORDER
    uint64_t required_features = (1ULL << 0) | (1ULL << 32) | (1ULL << 35); 

    // set REG_DEVICE_FEATURES_SEL to 0
    mmio_write8(device_mmio_base, REG_DEVICE_FEATURES_SEL, 0);
    // get lower 32 bits of REG_DEVICE_FEATURES
    uint32_t device_features = mmio_read32(device_mmio_base, REG_DEVICE_FEATURES);       

    // If device does not offer a required feature, set FAILED bit and cease initialization.
    // This driver DOES NOT HAVE BACKWARD COMPATIBILITY.
    if (required_features & ~(device_features)) {
        device_status |= 128;
        mmio_write8(device_mmio_base, REG_STATUS, device_status);
        exit_with_error("=== Driver error: feature negotiation failed ===\n");
    }

    // set REG_DRIVER_FEATURES_SEL to 0
    mmio_write8(device_mmio_base, REG_DRIVER_FEATURES_SEL, 0);
    // set lower 32 bits of REG_DRIVER_FEATURES
    mmio_write32(device_mmio_base, REG_DRIVER_FEATURES, device_features);

     // set REG_DEVICE_FEATURES_SEL to 1
    mmio_write8(device_mmio_base, REG_DEVICE_FEATURES_SEL, 1);
    // get upper 32 bits of REG_DEVICE_FEATURES 
    device_features = mmio_read32(device_mmio_base, REG_DEVICE_FEATURES);         
    // set REG_DRIVER_FEATURES_SEL to 1
    mmio_write8(device_mmio_base, REG_DRIVER_FEATURES_SEL, 1);
    // set upper 32 bits of REG_DRIVER_FEATURES
    mmio_write32(device_mmio_base, REG_DRIVER_FEATURES, device_features);

    // set and re-check FEATURES_OK to verify feature negotation
    device_status |= 0x08;
    mmio_write8(device_mmio_base, REG_STATUS, device_status);
    uint8_t resulting_device_status = mmio_read8(device_mmio_base, REG_STATUS);
    resulting_device_status &= 0x08;
    if (!resulting_device_status) {
        // set FAILED bit
        device_status |= 128;
        mmio_write8(device_mmio_base, REG_STATUS, device_status);
        exit_with_error("=== Driver error: feature negotiation failed ===\n");
    }

    /* 
     * device specific setup
     */

    // if QueueReady is already 1, skip device-specific set-up
    uint8_t queue_ready = mmio_read8(device_mmio_base, REG_QUEUE_READY);

    if (!queue_ready) {
        mmio_write32(device_mmio_base, REG_QUEUE_SEL, 1);                    // QueueSel

        // verify that host supports required queue size
        
        uint32_t queue_num_max = mmio_read32(device_mmio_base, REG_QUEUE_NUM_MAX);   // QueueNumMax
        if (queue_num_max < CONSOLE_VIRTQUEUE_SIZE) {
            // set FAILED bit
            device_status |= 128;
            mmio_write8(device_mmio_base, REG_STATUS, device_status);
            exit_with_error("=== Driver error: host does not support required queue size ===\n");
        }

        // TODO: zero queue memory

        // configure virtqueue
        mmio_write32(device_mmio_base, REG_QUEUE_NUM, CONSOLE_VIRTQUEUE_SIZE);      // QueueNum
        mmio_write32(device_mmio_base, REG_QUEUE_DESC_LOW, CONSOLE_QUEUE_DESC);     // QueueDescLow
        mmio_write32(device_mmio_base, REG_QUEUE_DESC_HIGH, 0x0);                   // QueueDescHigh
        mmio_write32(device_mmio_base, REG_QUEUE_DRIVER_LOW, CONSOLE_QUEUE_DRIVER); // QueueDriverLow
        mmio_write32(device_mmio_base, REG_QUEUE_DRIVER_HIGH, 0x0);                 // QueueDriverHigh
        mmio_write32(device_mmio_base, REG_QUEUE_DEVICE_LOW, CONSOLE_QUEUE_DEVICE); // QueueDeviceLow
        mmio_write32(device_mmio_base, REG_QUEUE_DEVICE_HIGH, 0);                   // QueueDeviceHigh
        
        // we can reuse mmio funcs for memory ops within addr space too.
        mmio_write16(0, CONSOLE_QUEUE_DRIVER, 0);    // initialize avail->flags to 0 (driver area)
        mmio_write16(0, CONSOLE_QUEUE_DRIVER+2, 0);  // initialize avail->idx to 0   (driver area)            

        // set QueueReady to 1
        mmio_write8(device_mmio_base, REG_QUEUE_READY, 1);
    }

    // indicate device initialization completion
    device_status |= 0x04;
    mmio_write8(device_mmio_base, REG_STATUS, device_status);

    return;
}

__attribute__((always_inline))
static inline void close_virtio_console() {
    volatile void* device_mmio_base = (void *) VIRTIO_MMIO_BASE;

    // set QueueReady to 0 and read for synchronization
    mmio_write8(device_mmio_base, REG_QUEUE_READY, 0);
    while (mmio_read8(device_mmio_base, REG_QUEUE_READY) != 0);
}

void handle_interrupt() {
//     volatile void* device_mmio_base = (void *) VIRTIO_MMIO_BASE;

//     int interrupt_status = mmio_read8(device_mmio_base, REG_INTERRUPT_STATUS);

//     if (interrupt_status & 1) {
//         // Used buffer notification
//         interrupt_received = 1;
//     }

//     if (interrupt_status & 2) {
//         // Config change notification
//         uint8_t device_status = mmio_read8(device_mmio_base, REG_STATUS);
        
//         // Device needs reset
//         if (device_status & 0x40) {
//             print_error_to_serial("=== Driver: device needs reset ===\n");
//             init_virtio_console();
//             return;
//         }
//     }

//     mmio_write8(device_mmio_base, REG_INTERRUPT_ACK, interrupt_status);
}

__attribute__((naked))
static void handle_interrupt_asm() {
    asm volatile (
        "pusha\n"   // Save all registers
        "call handle_interrupt\n"   // Call C handler
        "movb $0x20, %al\n"    // Send end-of-interupt to programmable interrupt controller
        "outb %al, $0x20\n"
        "popa\n" // Restore registers
        "iret\n" // Return from interrupt
        );
}

__attribute__((always_inline))
static inline void virtq_add_desc(
    uint16_t desc_idx, uint32_t addr, uint32_t len, uint16_t flags, uint16_t next
) {
    // each descriptor table entry is 16 bytes
    uint32_t desc_entry_addr = (CONSOLE_QUEUE_DESC + desc_idx * 16);

    mmio_write32(0, desc_entry_addr, addr); // addr
    mmio_write32(0, desc_entry_addr+4, 0);

    mmio_write32(0, desc_entry_addr+8, len);
    mmio_write16(0, desc_entry_addr+12, flags);
    mmio_write16(0, desc_entry_addr+14, next);
}

__attribute__((always_inline)) 
static inline void init_interrupts() {
    // uint32_t handler_addr = (uint32_t) handle_interrupt_asm;

    // idt[33].offset_low = handler_addr & 0xFFFF;
    // idt[33].offset_high = (handler_addr >> 16) & 0xFFFF;
    // idt[33].selector = 0x08;            // Code segment selector
    // idt[33].type_attributes = 0x8E;     // // Present, DPL=0, 32-bit interrupt gate
    // idt[33].zero = 0;

    // idtr.offset = (uint32_t) idt;
    // idtr.size = sizeof(idt) - 1;

    // asm volatile ("lidt %0" : : "m"(idtr));

    // asm volatile ("sti");
}

__attribute__((always_inline))
static inline void virtq_push_avail(uint16_t desc_idx) {
    // add new ring entry to point to correct descriptor table entry
    uint32_t avail_entry_addr = (CONSOLE_QUEUE_DRIVER + 4 + desc_idx * 2);
    mmio_write16(0, avail_entry_addr, desc_idx);

    // increment avail->idx
    uint32_t avail_idx_addr = (CONSOLE_QUEUE_DRIVER + 2);
    uint16_t avail_idx = mmio_read16(0, avail_idx_addr);
    mmio_write16(0, avail_idx_addr, avail_idx+1);
}

__attribute__((always_inline))
static inline void print_to_console(char* str) {
    volatile void* device_mmio_base = (void *) VIRTIO_MMIO_BASE;

    uint32_t strlen = 0;
    
    for (int i = 0; ; i++) {
        if (str[i] == '\0') break;
        strlen++;
    }

    uint32_t str_addr = (uint32_t) str;

    virtq_add_desc(next_free_desc, str_addr, strlen, 0, 0);
    virtq_push_avail(next_free_desc);

    mmio_write16(device_mmio_base, REG_QUEUE_NOTIFY, 1);   // QueueNotify (Virtqueue Index = 1)

    next_free_desc = (next_free_desc + 1) % CONSOLE_VIRTQUEUE_SIZE;
}

__attribute__((always_inline))
static inline void print_sync(char* str) {
    print_to_console(str);
}

__attribute__((always_inline))
static inline void print_async(char* str) {
    print_to_console(str);
}

int main() {
    // init_interrupts();

    // init_virtio_console();

    // print_sync("Hello World!\n");

    // close_virtio_console();

    while (1) asm("hlt");
}