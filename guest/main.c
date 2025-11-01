// bare-metal code with no stdlib, compiled to 32-bit protected mode x86 assembly

#include <stdint.h>

#define SERIAL_COM1_PORT        0x3F8  
#define VIRTIO_MMIO_BASE        0x10000000
#define CONSOLE_QUEUE_DESC      0x4000
#define CONSOLE_QUEUE_DRIVER    0x4100
#define CONSOLE_QUEUE_DEVICE    0x4200
#define CONSOLE_VIRTQUEUE_SIZE  0x10

uint16_t next_free_desc = 0;

__attribute__((always_inline))
static inline void outb(uint16_t port, uint8_t val) {
    asm volatile (
        "outb %[v], %[p]"
        :
        : [v] "a" (val), [p] "d" (port)
    );
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
    uint32_t* device_mmio_base = (uint32_t *) VIRTIO_MMIO_BASE;

    // verify magic number
    if (*(device_mmio_base) != 0x74726976) 
        exit_with_error("=== Driver error: invalid magic number ===\n");

    // verify device version number
    if (*(device_mmio_base + 1) != 0x2)
        exit_with_error("=== Driver error: invalid device version ===\n");

    // verify device id of console
    if (*(device_mmio_base + 2) != 0x3)
        exit_with_error("=== Driver error: invalid device id ===\n");

    uint8_t device_status = 0x00;

    // reset device by writing to REG_STATUS
    *(uint8_t*)(device_mmio_base + 0x070/4) = device_status;

    // set ACKNOWLEDGE status bit (notice this device)
    device_status |= 0x01;
    *(uint8_t*)(device_mmio_base + 0x070/4) = device_status;

    // set DRIVER status bit (indicate driver knows how to drive device)
    device_status |= 0x02;
    *(uint8_t*)(device_mmio_base + 0x070/4) = device_status;

    /*
     * read device feature bits and check support for features required by driver
     */

    // BIT(0) = VIRTIO_CONSOLE_F_SIZE
    // BIT(32) = VIRTIO_F_VERSION_1
    // BIT(35) = VIRTIO_F_IN_ORDER
    uint64_t required_features = (1ULL << 0) | (1ULL << 32) | (1ULL << 35); 

    // set REG_DEVICE_FEATURES_SEL to 0
    *(uint8_t*)(device_mmio_base + 0x014/4) = 0; 
    // get lower 32 bits of REG_DEVICE_FEATURES_SEL             
    uint32_t device_features = *(device_mmio_base + 0x010/4); 

    // If device does not offer a required feature, set FAILED bit and cease initialization.
    // This driver DOES NOT HAVE BACKWARD COMPATIBILITY.
    if (required_features & ~(device_features)) {
        device_status |= 128;
        *(uint8_t*)(device_mmio_base + 0x070/4) = device_status;
        exit_with_error("=== Driver error: feature negotiation failed ===\n");
    }

    // set REG_DRIVER_FEATURES_SEL to 0
    *(uint8_t*)(device_mmio_base + 0x024/4) = 0;
    // set lower 32 bits of REG_DRIVER_FEATURES_SEL
    *(device_mmio_base + 0x020/4) = device_features;

     // set REG_DEVICE_FEATURES_SEL to 1
    *(uint8_t*)(device_mmio_base + 0x014/4) = 1; 
    // get upper 32 bits of REG_DEVICE_FEATURES_SEL             
    device_features = *(device_mmio_base + 0x010/4); 
    // set REG_DRIVER_FEATURES_SEL to 1
    *(uint8_t*)(device_mmio_base + 0x024/4) = 1;
    // set upper 32 bits of REG_DRIVER_FEATURES_SEL
    *(device_mmio_base + 0x020/4) = device_features;

    // set and re-check FEATURES_OK to verify feature negotation
    device_status |= 0x08;
    *(uint8_t*)(device_mmio_base + 0x070/4) = device_status;
    uint8_t resulting_device_status = *(uint8_t*)(device_mmio_base + 0x070/4);
    resulting_device_status &= 0x08;
    if (!resulting_device_status) {
        // set FAILED bit
        device_status |= 128;
        *(uint8_t*)(device_mmio_base + 0x070/4) = device_status;
        exit_with_error("=== Driver error: feature negotiation failed ===\n");
    }

    /* 
     * device specific setup
     */

    // if QueueReady is already 1, skip device-specific set-up
    uint8_t queue_ready = *(uint8_t*)(device_mmio_base + 0x044/4);

    if (!queue_ready) {
        *(device_mmio_base + 0x030/4) = 1;                          // QueueSel

        // verify that host supports required queue size
        uint32_t queue_num_max = *(device_mmio_base + 0x034/4);     // QueueNumMax
        if (queue_num_max < CONSOLE_VIRTQUEUE_SIZE) {
            // set FAILED bit
            device_status |= 128;
            *(uint8_t*)(device_mmio_base + 0x070/4) = device_status;
            exit_with_error("=== Driver error: host does not support required queue size ===\n");
        }

        // TODO: zero queue memory

        // configure virtqueue
        *(device_mmio_base + 0x038/4) = CONSOLE_VIRTQUEUE_SIZE;     // QueueNum
        *(device_mmio_base + 0x080/4) = CONSOLE_QUEUE_DESC;         // QueueDescLow
        *(device_mmio_base + 0x084/4) = 0x0;                        // QueueDescHigh
        *(device_mmio_base + 0x090/4) = CONSOLE_QUEUE_DRIVER;       // QueueDriverLow
        *(device_mmio_base + 0x094/4) = 0x0;                        // QueueDriverHigh
        *(device_mmio_base + 0x0a0/4) = CONSOLE_QUEUE_DEVICE;       // QueueDeviceLow
        *(device_mmio_base + 0x0a4/4) = 0x0;                        // QueueDeviceHigh

        *(uint16_t*)(CONSOLE_QUEUE_DRIVER) = 0;                     // initialize avail->flags to 0 (driver area)
        *(uint16_t*)(CONSOLE_QUEUE_DRIVER + 2) = 0;                 // initialize avail->idx to 0   (driver area)

        // set QueueReady to 1
        *(uint8_t *)(device_mmio_base + 0x044/4) = 1;
    }

    // indicate device initialization completion
    device_status |= 0x04;
    *(uint8_t*)(device_mmio_base + 0x070/4) = device_status;

    return;
}

__attribute__((always_inline))
static inline void close_virtio_console() {
    uint32_t* device_mmio_base = (uint32_t *) VIRTIO_MMIO_BASE;

    // set QueueReady to 0 and read for synchronization
    *(uint8_t*)(device_mmio_base + 0x044/4) = 0;
    while (*(uint8_t*)(device_mmio_base + 0x044/4) != 0);
}

__attribute__((always_inline))
static inline void virtq_add_desc(
    uint16_t desc_idx, uint32_t addr, uint32_t len, uint16_t flags, uint16_t next
) {
    // each descriptor table entry is 16 bytes
    char* desc_entry = (char*) (CONSOLE_QUEUE_DESC + desc_idx * 16);

    *(uint32_t*) desc_entry = addr;       // addr
    *(uint32_t*) (desc_entry + 4) = 0;

    *(uint32_t*)(desc_entry + 8) = len;    // len 
    *(uint16_t*)(desc_entry + 12) = flags;  // flags
    *(uint16_t*)(desc_entry + 14) = next;   // next
}

__attribute__((always_inline))
static inline void virtq_push_avail(uint16_t desc_idx) {
    // add new ring entry to point to correct descriptor table entry
    uint8_t* avail_entry = (uint8_t*) (CONSOLE_QUEUE_DRIVER + 4 + desc_idx * 2);
    *avail_entry = desc_idx;

    // increment avail->idx
    uint8_t* avail_idx = (uint8_t*) (CONSOLE_QUEUE_DRIVER + 2);
    *avail_idx = *avail_idx + 1;
}

// since we negotiated device feature VIRTIO_F_IN_ORDER,
// we simply need to check that used->idx == avail->idx to indicate
// all pending used entries have been walked by the device.
__attribute__((always_inline))
static inline void virtq_poll_used() {
    // read device status 
    uint8_t device_status = *((char*) VIRTIO_MMIO_BASE + 0x070);

    // if DEVICE_NEEDS_RESET bit is set, abort poll, reset and reinitialize device
    if (device_status & (1 << 6)) {
        print_error_to_serial("Driver: device needs reset\n");
        init_virtio_console();
        return;
    }

    uint16_t used_idx = *(uint16_t*)(CONSOLE_QUEUE_DEVICE + 2);
    uint16_t avail_idx = *(uint16_t*)(CONSOLE_QUEUE_DRIVER + 2);

    // busy spin until device has walked device area table
    // and processed buffer descriptors.
    while (used_idx != avail_idx);
}

__attribute__((always_inline))
static inline void print_to_console(char* str) {
    // read device status 
    uint8_t device_status = *((char*) VIRTIO_MMIO_BASE + 0x070);

    // if DEVICE_NEEDS_RESET bit is set, abort poll, reset and reinitialize device
    if (device_status & (1 << 6)) {
        print_error_to_serial("Driver: device needs reset\n");
        init_virtio_console();
        return;
    }

    uint32_t strlen = 1;
    
    for (int i = 0; ; i++) {
        if (str[i] == '\0') break;
        strlen++;
    }

    uint32_t str_addr = (uint32_t) str;

    virtq_add_desc(next_free_desc, str_addr, strlen, 0, 0);
    virtq_push_avail(next_free_desc);

    *(uint16_t*)(VIRTIO_MMIO_BASE + 0x050) = 1;   // QueueNotify (Virtqueue Index = 1)

    next_free_desc = (next_free_desc + 1) % CONSOLE_VIRTQUEUE_SIZE;
}

__attribute__((always_inline))
static inline void print_sync(char* str) {
    print_to_console(str);
    virtq_poll_used();           // Additionaly, poll to ensure device has processed all buffers
}

__attribute__((always_inline))
static inline void print_async(char* str) {
    print_to_console(str);
}

int main() {
    init_virtio_console();

    print_sync("Hello World!\n");

    close_virtio_console();

    while (1) asm("hlt");
}