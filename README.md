## VirtIO-based x86-64 Hypervisor

A minimal x86-64 hypervisor implementing a VirtIO console device with optional vhost acceleration for low-latency I/O processing in kernel space.

### Overview

This project demonstrates the core concepts of hardware virtualization on x86-64 systems using KVM (Kernel Virtual Machine). It implements a complete VirtIO console device following the VirtIO 1.0 specification, allowing a bare-metal guest OS to perform I/O operations through a paravirtualized console interface.

The hypervisor supports two modes of operation:
- Userspace I/O handling: Traditional approach where guest I/O notifications trigger VM exits to userspace
- Vhost acceleration: Kernel-space I/O processing that bypasses userspace entirely, significantly reducing context switch overhead

### Key Features

- **Full VirtIO 1.0 Console Implementation**: Complete device initialization, feature negotiation, and virtqueue processing
- **Vhost Acceleration**: Optional kernel-space I/O handling via `/dev/vhost-console` device driver 
- **MMIO-based Device Interface**: Memory-mapped control registers for device configuration
- **Bare-metal Guest Support**: Runs custom x86 protected mode guest code without OS dependencies

### Architecture

```
        ┌─────────────────────────────────────────────────────────────┐
        │                        Guest VM                             │
        │  ┌────────────────────────────────────────────────────────┐ │
        │  │  Guest Code (guest.c)                                  │ │
        │  │  • VirtIO console driver                               │ │
        │  │  • Virtqueue management (descriptor/available rings)   │ │
        │  │  • MMIO register access                                │ │
        │  └─────────────────────┬──────────────────────────────────┘ │
        │                        │ MMIO Write to QueueNotify          │
        └────────────────────────┼────────────────────────────────────┘
                                 │
                                 ▼
                ┌────────────────────────────────────┐
                │           KVM (Kernel)             │
                │  • VM Exit Handling                │
                │  • MMIO Emulation                  │
                │  • Eventfd Notification (vhost)    │
                └────────┬───────────────────────────┘
                         │
            ┌────────────┴─────────────┐
            │                          │
            ▼ (Userspace)              ▼ (Kernel - Vhost Mode)
        ┌─────────────────────────┐  ┌──────────────────────────────┐
        │  Hypervisor (main.c)    │  │  /dev/vhost-console          │
        │  • VM Setup & Memory    │  │  • Worker thread             │
        │  • VirtIO Device State  │  │  • Direct memory access      │
        │  • MMIO Handlers        │  │  • Virtqueue processing      │
        │  • Virtqueue Processing │  │  • Zero VM exits for I/O     │
        └───────────┬─────────────┘  └─────────────┬────────────────┘
                    │                              │
                    ▼                              ▼
            ┌─────────────────────────────────────────┐
            │      /dev/vmm-console (output)          │
            │  • Emulates console device              │
            │  • Receives guest output                │
            └─────────────────────────────────────────┘
```

## Project Structure
```
virtio-console-hypervisor/
├── src/
│   ├── main.c                    # Hypervisor entry point & KVM setup
│   ├── virtio_console.c          # VirtIO console device implementation
│   ├── vhost_console.c           # Kernel-space vhost driver
│   └── guest.c                   # Bare-metal guest code / VirtIO console driver
├── include/
│   ├── virtio_control_regs.h     # MMIO register definitions
│   ├── virtio_console.h          # VirtIO device structures
│   └── vhost_console.h           # Vhost IOCTL definitions
├── build/                        # Compiled binaries
│   ├── main                      # Hypervisor executable
│   ├── guest.bin                 # Guest binary
│   └── vhost_console.ko          # Vhost kernel module
├── Makefile
├── linker.ld         # Linker script defining memory layout for bare-metal x86 guest binary
└── README.md
```

### Dependencies & Environment Setup

#### Requirements

- Operating System: Linux with KVM support (x86-64)
- Kernel: Linux 4.0+ with KVM modules enabled
- Hardware: Intel VT-x or AMD-V enabled CPU
- Cross-compiler: GCC with support for 32-bit cross-compilation
- Kernel Headers: Required for building kernel modules

#### Installation

1. **Verify KVM Support**:
```bash
# Check if CPU supports virtualization
egrep -c '(vmx|svm)' /proc/cpuinfo  # Should return non-zero

# Check if KVM modules are loaded
lsmod | grep kvm
```

Note: I used a Google Cloud n1-standard-1 instance (1 vCPU, 3.75 GB RAM, Debian 12) in us-central1-f with KVM explicitly enabled via nested virt support. Follow [Google Cloud's guide to enable nested virtualization](https://docs.cloud.google.com/compute/docs/instances/nested-virtualization/overview) to set the required license flag and reboot.


2. **Install Dependencies**:
```bash
# Debian/Ubuntu
sudo apt-get install build-essential linux-headers-$(uname -r) \
    bison flex libgmp3-dev libmpc-dev libmpfr-dev texinfo

# Fedora/RHEL
sudo dnf install gcc kernel-devel bison flex gmp-devel \
    libmpc-devel mpfr-devel texinfo
```

3. **Build i686-elf Cross-Compiler** (required for guest code):

The guest code must be compiled with an i686-elf cross-compiler to produce proper freestanding binaries. Follow the [OSDev GCC Cross-Compiler tutorial](https://wiki.osdev.org/GCC_Cross-Compiler).

4. **Configure KVM Permissions**:

```bash
# Add user to kvm group
sudo usermod -aG kvm $USER

# Verify permissions on /dev/kvm
ls -l /dev/kvm
```

5. **Build the project**:

```bash
make clean
make
```

6. **Load Vhost Linux Module (required for vhost acceleration)**

```bash
insmod build/vhost_console.ko
```

Note: you made need to boot a custom Linux kernel in QEMU with module loading enabled for development purposes. Loading custom kernel modules isn't always straightforward on modern systems with security features enabled (definitely do not find a way to load this module into your kernel, it is not production ready).

### Usage

#### Basic Usage

```bash
./build/main
```

Output will be written to  `/dev/vmm-console`:

```bash
cat /dev/vmm-console
```

#### Vhost Accelerated Mode (Kernel I/O)

```bash
./build/main -v
```

#### CLI Flags

```
| Flag | Description |
|------|-------------|
| `-v` | Enable vhost acceleration (kernel-space I/O processing) |
| `-h` | Display help message |
```

#### Example Output

```
=== Vhost acceleration enabled ===
=== Guest OS has noticed device ===
=== Guest OS knows how to drive device ===
=== Driver has acknowledged recognizable features; feature negotiation complete ===
=== Driver is set up; console device is live ===
[KVM_EXIT_HLT: program halted normally]

Time taken to run VM: 1234 microseconds
```

Guest output in `/dev/vmm-console`:

```
Hello World!
```

### Technical Deep Dive

#### VirtIO Device Lifecycle

1. **Device Discovery**: Guest probes MMIO region, verifies magic number and device ID
2. **Feature Negotiation**: Guest and host agree on supported features (VIRTIO_F_VERSION_1, VIRTIO_F_IN_ORDER)
3. **Virtqueue Setup**: Guest allocates and configures descriptor, available, and used rings
4. **I/O Operations**: Guest populates descriptors, updates available ring, writes to QueueNotify
5. **Device Processing**: Host/kernel processes buffers and updates used ring

#### Memory layout

```
Guest Physical Memory:
0x0000 - 0x0FFF: (Reserved)
0x1000 - 0x3FFF: Guest code (3 pages)
0x4000 - 0x4FFF: Stack (1 page)
0x5000 - 0x5FFF: Virtqueue rings (1 page)
  ├── 0x5000: Descriptor table
  ├── 0x5100: Available ring
  └── 0x5200: Used ring

MMIO Region:
0x10000000 - 0x100000FF: VirtIO console control registers
```

### TODOs:

- **Performance Optimization**: Investigate and resolve performance bottleneck in the vhost-console device's worker thread (overhead created by spurious wake ups / event notification storms associated with eventfd registered with KVM).
- **Interrupt Injection**: Implement VM interrupt injection mechanism to enable host to guest `device-configuration-change` and `used-buffer` notifications.
- **VirtIO Block Device**: Extend to support block I/O.
- **Testing & Validation**: Extensive testing required.
- **Enhanced Guest Support**: Support for larger memory regions, better multiqueue support, and multi-vCPU round-robin scheduling.

### References

- [VirtIO 1.0 Specification](https://docs.oasis-open.org/virtio/virtio/v1.0/virtio-v1.0.html)
- [KVM API Documentation](https://docs.kernel.org/virt/kvm/index.html)
- [Using the KVM API - Excellent tutorial by LWN](https://lwn.net/Articles/658511/)
- [Vhost Architecture](https://www.redhat.com/en/blog/deep-dive-virtio-networking-and-vhost-net)
- [Intel VT-x Documentation / Intel Developer Guide](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)

### License

GPL v2 (consistent with Linux kernel module licensing)

### Author

Vismay Suramwar - vismaysuramwar@gmail.com

_____

Note: This is an educational project demonstrating hypervisor concepts. It is not intended for production use.