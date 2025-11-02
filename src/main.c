#include <asm/kvm.h>
#include <linux/kvm.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <stdbool.h>

#include "vhost_console.h"
#include "virtio_console.h"
#include "helpers.h"
#include "virtio_control_regs.h"

#define PAGE_SIZE           getpagesize()
#define GUEST_MEM_SIZE      0x10000000ULL

#define CR0_PE              1u

void* guest_physical_mem_base;

// Set initial state of VCPU special registers (Intel x86-64)
static inline int setup_sregisters(int vcpufd) {
    int ret;
    struct kvm_sregs sregs;

    // get data structure to configure initial state of special registers of the VCPU
    ret = ioctl(vcpufd, KVM_GET_SREGS, &sregs);
    if (ret == -1) {
        fprintf(stderr, ERROR_COLOR "ioctl(): %s\n" RESET_COLOR, strerror(errno));
        return 1;
    } 

    // set fields for default segment config
    struct kvm_segment segment = {
        .base = 0x0,
        .limit = 0xffffffff,
        .g = 1,
        .present = 1,
        .type = 11,
        .s = 1,
        .dpl = 0,
        .db = 1,
        .selector = 1 << 3
    };

    sregs.cs = segment;
    sregs.cr0 |= 1;

    // code segment and other segments must have different segment selectors
    segment.selector = 2 << 3;
    segment.type = 3;
    sregs.ds = sregs.es = sregs.gs = sregs.fs = sregs.ss = segment;

    ret = ioctl(vcpufd, KVM_SET_SREGS, &sregs);
    if (ret == -1) {
        fprintf(stderr, ERROR_COLOR "ioctl(): %s\n" RESET_COLOR, strerror(errno));
        return 1;
    } 

    return 0;
}

// Set initial state of VCPU registers (Intel x86-64)
static inline int setup_registers(int vcpufd) {
    struct kvm_regs regs = {0};
    int ret;

     // init most of general purpose regs to 0, set some fields
    regs.rip = PAGE_SIZE;
    regs.rflags = 0x2;
    // memory allocated for stack has physical addr range 0x4000-0x4FFF
    regs.rsp = 0x5000;     
    ret = ioctl(vcpufd, KVM_SET_REGS, &regs);
    if (ret == -1) {
        fprintf(stderr, ERROR_COLOR "ioctl(): %s\n" RESET_COLOR, strerror(errno));
        return 1;
    } 

    return 0;
}

// Set up guest VM's "physical memory" region.
//
// Note 1: Physical addr starts at 0x1000 with a simple 5 page layout to
// hold guest code in pages 0-2 (0x1000-0x3FFF), stack in page 3 (0x4000-0x4FFF) and
// virtrings in page 4 (0x5000-0x5FFF).
// Note 2: Actual memory resource doesn't belong to any specific process, it is mapped to 
// shared and anonymous zero-initialized memory that can be read from and written to by 
// both, the hypervisor and the guest VM.
//
// Arg 0: guest_codefd = file descriptor of binary containing guest code, to be loaded to page 0.
// Arg 1: VM file descriptor used for KVM ioctls
// Arg 2: guest_mem = void pointer to guest memory starting address in hypervisor address space
//
// Critical: must write the (pointer to mmapped guest memory address) to `guest_mem` (arg 2) 
// for further use and unmapping in caller.
static inline int setup_memory_region(int guestcode_fd, int vmfd, void** guest_mem) {
    off_t guestcode_size;
    int ret;
    uint8_t* code;
    void* guest_physical_mem;
    struct kvm_userspace_memory_region memregion = {0};

    // get size of guest binary
    guestcode_size = lseek(guestcode_fd, 0, SEEK_END);
    if (guestcode_size == -1) {
        fprintf(stderr, ERROR_COLOR "lseek(): %s\n" RESET_COLOR, strerror(errno));
        return 1; 
    }

    // reset file pointer back to beginning of file
    ret = lseek(guestcode_fd, 0, SEEK_SET);
    if (ret == -1) {
        fprintf(stderr, ERROR_COLOR "lseek(): %s\n" RESET_COLOR, strerror(errno));
        return 1;
    }

    // allocate memory to hold guest binary, read into allocated memory.
    code = malloc(guestcode_size);
    if (code == NULL) {
        fprintf(stderr, ERROR_COLOR "malloc(): %s\n" RESET_COLOR, strerror(errno));
        return 1; 
    }

    ret = read(guestcode_fd, code, guestcode_size);
    if (ret == -1) {
        fprintf(stderr, ERROR_COLOR "read(): %s\n" RESET_COLOR, strerror(errno));
        return 1; 
    }

    // allocate 4 pages of page aligned, zero-initialized shared memory to hold guest code and other segments.
    guest_physical_mem = mmap(NULL, PAGE_SIZE * 5, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0); 
    if (guest_physical_mem == (void*) -1) {
        fprintf(stderr, ERROR_COLOR "mmap(): %s\n" RESET_COLOR, strerror(errno));
        return 1;
    }

    // copy machine code into mapped memory
    memcpy(guest_physical_mem, code, guestcode_size);

    // free memory used to hold guest binary, read into allocated memory.
    free(code);

    // inform VM of allocated and mapped memory
    memregion.slot = 0;
    memregion.guest_phys_addr = PAGE_SIZE;
    // second page of VM's "physical" address space
    // avoids conflict with with non-existent real-mode interrupt descriptor table
    // at address 0
    memregion.memory_size = 5 * PAGE_SIZE;
    memregion.userspace_addr = (uint64_t) guest_physical_mem;

    ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &memregion);
    if (ret == -1) {
        fprintf(stderr, ERROR_COLOR "ioctl(): %s\n" RESET_COLOR, strerror(errno));
        return 1;
    }

    // assign (pointer to newly mapped guest memory address) to guest_mem
    *guest_mem = guest_physical_mem;

    return 0;
}

static inline int setup_vhost(int vmfd, int vcpufd, struct vhost_state* state, int output_fd) {
    int vhostfd, kick_efd, ret;

    vhostfd = open("/dev/vhost-console", O_RDWR);
    if (vhostfd == -1) {
        fprintf(stderr, ERROR_COLOR "open(): %s\n" RESET_COLOR, strerror(errno));
        return 1;
    }

    kick_efd = eventfd(1, EFD_NONBLOCK | EFD_CLOEXEC);
    if (kick_efd == -1) {
        fprintf(stderr, ERROR_COLOR "eventfd(): %s\n" RESET_COLOR, strerror(errno));
        return 1;
    }

    struct kvm_ioeventfd fd = {
        .datamatch = 1,
        .len = 2,
        .fd = kick_efd,
        .addr = VIRTIO_MMIO_BASE + REG_QUEUE_NOTIFY,
        .flags = KVM_IOEVENTFD_FLAG_DATAMATCH,
    };

    ret = ioctl(vmfd, KVM_IOEVENTFD, &fd);
    if (ret == -1) {
        fprintf(stderr, ERROR_COLOR "ioctl(): %s\n" RESET_COLOR, strerror(errno));
        return 1;
    }

    state->vhostfd = vhostfd;
    state->kick_efd = kick_efd;

    ret = ioctl(vhostfd, VHOST_SET_OWNER, NULL);
    if (ret == -1) {
        fprintf(stderr, ERROR_COLOR "ioctl(): %s\n" RESET_COLOR, strerror(errno));
        return 1;
    }

    return 0;
}

static inline int close_vhost(struct vhost_state* state) {
    if (state->vhostfd == -1) return 0;

    int ret = close(state->vhostfd);
    if (ret == -1) {
        fprintf(stderr, ERROR_COLOR "close(): %s\n" RESET_COLOR, strerror(errno));
        return 1;
    }

    return 0;
}

int main() {
    int kvm, ret, vmfd, vcpufd, guestcode_fd;
    void *guest_mem;
    struct kvm_run* run;
    size_t kvm_run_mmap_size;
    int output_fd;
    bool halted;

    struct vhost_state state = {
        .vhostfd = -1,
        .kick_efd = -1
    };

    // emulate console device using console_output.txt file
    output_fd = open("/dev/vmm-console", O_WRONLY | O_CREAT | O_TRUNC);
    if (output_fd == -1) {
        fprintf(stderr, ERROR_COLOR "open(): %s\n" RESET_COLOR, strerror(errno));
        return 1;
    } 

    // user logged in at console must be part of kvm group to access /dev/kvm
    kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm == -1) {
        fprintf(stderr, ERROR_COLOR "open(): %s\n" RESET_COLOR, strerror(errno));
        return 1;
    }

    // ensure usage of stable version of the KVM API: Version 12
    ret = ioctl(kvm, KVM_GET_API_VERSION, NULL);
    if (ret == -1) {
        fprintf(stderr, ERROR_COLOR "ioctl(): %s\n" RESET_COLOR, strerror(errno));
        return 1;
    }

    if (ret != 12) {
        fprintf(stderr, ERROR_COLOR "KVM_GET_API_VERSION: %d, expected 12" RESET_COLOR, ret);
        return 1;
    }

    // create VM with machine type 0
    // VM has no memory or virtual CPUs
    vmfd = ioctl(kvm, KVM_CREATE_VM, 0);
    if (vmfd == -1) {
        fprintf(stderr, ERROR_COLOR "ioctl(): %s\n" RESET_COLOR, strerror(errno));
        return 1;
    }

     // read guest.bin from disk
    guestcode_fd = open("build/guest.bin", O_RDONLY);
    if (guestcode_fd == -1) {
        fprintf(stderr, ERROR_COLOR "open(): %s\n" RESET_COLOR, strerror(errno));
        return 1; 
    }

    // set up VM memory region and copy guest code to it
    if ((ret = setup_memory_region(guestcode_fd, vmfd, &guest_mem))) return ret;
    guest_physical_mem_base = guest_mem;

    // create virtual CPU to run code in guest physical memory.
    vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, 0);
    if (vcpufd == -1) {
        fprintf(stderr, ERROR_COLOR "ioctl(): %s\n" RESET_COLOR, strerror(errno));
        return 1;
    } 

    // determine size of memory to map to hold kvm_run structure
    kvm_run_mmap_size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (kvm_run_mmap_size == -1) {
        fprintf(stderr, ERROR_COLOR "ioctl(): %s\n" RESET_COLOR, strerror(errno));
        return 1;
    } 

    // allocate kvm_run mmap_size sized memory for kvm_run data structure.
    run = mmap(NULL, kvm_run_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);
    if (run == (void*) -1) {
        fprintf(stderr, ERROR_COLOR "mmap(): %s\n" RESET_COLOR, strerror(errno));
        return 1;
    }
    
    // set up VCPU special regs initial state 
    if ((ret = setup_sregisters(vcpufd))) return ret;

    // set up VCPU regs initial state
    if ((ret = setup_registers(vcpufd))) return ret;

    // set up vhost-console device
    if ((ret = setup_vhost(vmfd, vcpufd, &state, output_fd))) return ret;

    halted = false;

    while (1) {
        // run VM with Intel VT
        ret = ioctl(vcpufd, KVM_RUN, NULL);
        if (ret == -1) {
            fprintf(stderr, ERROR_COLOR "ioctl(): %s\n" RESET_COLOR, strerror(errno));
            return 1;
        } 

        switch (run->exit_reason) {
            // VM called `hlt` instruction
            case KVM_EXIT_HLT: {
                printf(DEBUG_COLOR "[KVM_EXIT_HLT: program halted normally] \n" RESET_COLOR);
                halted = true;
                break;
            }
            // VM wrote to i/o port
            case KVM_EXIT_IO: {
                if (run->io.direction == KVM_EXIT_IO_OUT && 
                    run->io.size == 1 &&
                    run->io.port == 0x3f8 &&
                    run->io.count == 1) {
                    char* serial_msg = ((char *) run + run->io.data_offset);
                    fprintf(stderr, ERROR_COLOR "%s" RESET_COLOR, serial_msg);
                } else
                    fprintf(stderr, ERROR_COLOR "[unhandled KVM_EXIT_IO]\n" RESET_COLOR);
                break;
            }
            // VM read/wrote to memory outside its physical addr range
            // Used for VirtIO MMIO
            case KVM_EXIT_MMIO: {
                if (run->mmio.phys_addr < VIRTIO_MMIO_BASE || run->mmio.phys_addr >= VIRTIO_MMIO_BASE + VIRTIO_MMIO_SIZE) {
                    fprintf(stderr, ERROR_COLOR "[unhandled MMIO @ 0x%llx] \n" RESET_COLOR, run->mmio.phys_addr);
                    halted = true;
                    break;
                }

                // Ignore writes to QueueNotify if vhost enabled
                if (
                    state.vhostfd != -1 && 
                    run->mmio.phys_addr == VIRTIO_MMIO_BASE + REG_QUEUE_NOTIFY && 
                    *run->mmio.data == 1 && 
                    run->mmio.len == 2
                ) {
                    break;
                }

                if (run->mmio.is_write) 
                    handle_mmio_write(run->mmio.phys_addr, run->mmio.data, run->mmio.len, vcpufd, &state, output_fd);
                else 
                    handle_mmio_read(run->mmio.phys_addr, run->mmio.data, run->mmio.len, vcpufd, &state);
                
                break;
            }
            // Likely set up VCPU incorrectly and doesn't align with Intel VT pre-reqs
            case KVM_EXIT_FAIL_ENTRY: {
                fprintf(
                    stderr, 
                    ERROR_COLOR "[KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = %llx] \n" RESET_COLOR,
                    (unsigned long long) run->fail_entry.hardware_entry_failure_reason
                );
                halted = true;
                break;
            }
            // Error internal to KVM
            case KVM_INTERNAL_ERROR_EMULATION: {
                fprintf(
                    stderr,
                    ERROR_COLOR "[KVM_INTERNAL_ERROR_EMULATION: suberror = 0x%x] \n" RESET_COLOR,
                    run->emulation_failure.suberror
                );
                halted = true;
                break;
            }
            default: {
                fprintf(stderr, ERROR_COLOR "[Unhandled KVM exit reason: %d]\n" RESET_COLOR, run->exit_reason);
                halted = true;
                break;
            }
        }

        if (halted) break;
    }

    // close vhost-console device
    if ((ret = close_vhost(&state))) return ret;

    // release memory page allocated for guest VM's memory
    ret = munmap(guest_mem, PAGE_SIZE * 5);
    if (ret == -1) {
        fprintf(stderr, ERROR_COLOR "munmap(): %s\n", strerror(errno));
        return 1;
    } 

    // release memory allocated for kvm_run structure to track VM VCPU state
    ret = munmap(run, kvm_run_mmap_size);
    if (ret == -1) {
        fprintf(stderr, ERROR_COLOR "munmap(): %s\n", strerror(errno));
        return 1;
    } 

    // close /dev/kvm device file
    ret = close(kvm);
    if (ret == -1) {
        fprintf(stderr, ERROR_COLOR "close(): %s\n", strerror(errno));
        return 1;
    }

    return 0;
}