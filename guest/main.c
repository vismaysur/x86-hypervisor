// bare-metal code with no stdlib, compiled to 32-bit protected mode x86 assembly

#include <stdint.h>

#define SERIAL_COM1_PORT        0x3F8  
#define VIRTIO_MMIO_BASE        0x10000000
#define CONSOLE_QUEUE_DESC      0x4000
#define CONSOLE_QUEUE_DRIVER    0x4100
#define CONSOLE_QUEUE_DEVICE    0x4200
#define CONSOLE_VIRTQUEUE_SIZE  0x10

uint16_t next_free_desc = 0;

char serial_msg_magic_error[] = "Driver error: invalid magic number\n";
char serial_msg_device_version_error[] = "Driver error: invalid device version\n";
char serial_msg_device_id_error[] = "Driver error: invalid device id\n";
char serial_msg_queue_num_max_error[] = "Driver error: host does not support required queue size\n";
char serial_msg_feature_negotiation_error[] = "Driver error: feature negotiation failed\n";

char console_msg_example[] = "Hello World!\n";

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
        exit_with_error(serial_msg_magic_error);

    // verify device version number
    if (*(device_mmio_base + 1) != 0x2)
        exit_with_error(serial_msg_device_version_error);

    // verify device id of console
    if (*(device_mmio_base + 2) != 0x3)
        exit_with_error(serial_msg_device_id_error);

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
     * read and accept all device feature bits
     */

    // set REG_DEVICE_FEATURES_SEL to 0
    *(uint8_t*)(device_mmio_base + 0x014/4) = 0; 
    // get lower 32 bits of REG_DEVICE_FEATURES_SEL             
    uint32_t device_features = *(device_mmio_base + 0x010/4); 
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
    if (!resulting_device_status) 
        exit_with_error(serial_msg_feature_negotiation_error);

    /* 
     * device specific setup
     */

    *(device_mmio_base + 0x030/4) = 1;                          // QueueSel

    // verify that host supports required queue size
    uint32_t queue_num_max = *(device_mmio_base + 0x034/4);     // QueueNumMax
    if (queue_num_max < CONSOLE_VIRTQUEUE_SIZE)
        exit_with_error(serial_msg_queue_num_max_error);

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

    // indicate device initialization completion
    device_status |= 0x04;
    *(uint8_t*)(device_mmio_base + 0x070/4) = device_status;

    return;
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

// since we check for device feature VIRTIO_F_IN_ORDER,
// we simply need to check that used->idx == avail->idx to indicate
// all pending used entries have been walked by the device.
__attribute__((always_inline))
static inline void virtq_poll_used() {
    uint16_t used_idx = *(uint16_t*)(CONSOLE_QUEUE_DEVICE + 2);
    uint16_t avail_idx = *(uint16_t*)(CONSOLE_QUEUE_DRIVER + 2);

    // busy spin until device has walked device area table
    // and processed buffer descriptors.
    while (used_idx != avail_idx);
}

__attribute__((always_inline))
static inline void print_to_console(uint32_t str_addr) {
    char* str = (char*) str_addr;
    uint32_t strlen = 1;
    
    for (int i = 0; ; i++) {
        if (str[i] == '\0') break;
        strlen++;
    }

    virtq_add_desc(next_free_desc, str_addr, strlen, 0, 0);
    virtq_push_avail(next_free_desc);

    *(uint16_t*)(VIRTIO_MMIO_BASE + 0x050) = 1;   // QueueNotify (Virtqueue Index = 1)

    next_free_desc = (next_free_desc + 1) % CONSOLE_VIRTQUEUE_SIZE;
}

__attribute__((always_inline))
static inline void print_sync(uint32_t str_addr) {
    print_to_console(str_addr);
    virtq_poll_used();           // Additionaly, poll to ensure device has processed all buffers
}

__attribute__((always_inline))
static inline void print_async(uint32_t str_addr) {
    print_to_console(str_addr);
}

int main() {
    init_virtio_console();

    print_async((uint32_t) console_msg_example);

    while (1) asm("hlt");
}