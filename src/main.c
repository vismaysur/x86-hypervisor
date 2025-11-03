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
#include <time.h>
#include <unistd.h>
#include <stdbool.h>
#include <getopt.h>

#include "vhost_console.h"
#include "virtio_console.h"
#include "virtio_control_regs.h"

#define PAGE_SIZE           getpagesize()
#define GUEST_MEM_SIZE      0x10000000ULL

#define CR0_PE              1u

/*
 * Tracks starting address of guest VM's memory in the hypervisor's address space.
 */
void* guest_physical_mem_base;

/*
 * Sets initial state of VCPU special registers (Intel x86-64)
 */
static inline int setup_sregisters(int vcpufd) {
    int ret;
    struct kvm_sregs sregs;

    /* Gets configurable initial state of special registers of the VCPU */
    ret = ioctl(vcpufd, KVM_GET_SREGS, &sregs);
    if (ret == -1) {
        fprintf(stderr,  "ioctl(): %s\n" , strerror(errno));
        return 1;
    } 

    /* Sets fields for default segment config */
    struct kvm_segment segment = {
        .base = 0x0,
        .limit = 0xffffffff,
        .g = 1,
        .present = 1,
        .type = 11,        // Read + Execute
        .s = 1,
        .dpl = 0,
        .db = 1,
        .selector = 1 << 3
    };

    sregs.cs = segment;
    sregs.cr0 |= 1;

    /* Other segments must have different segment selectors from the code segment */
    segment.selector = 2 << 3;

    /* Other segments must be readable and writable */
    segment.type = 3; 
    sregs.ds = sregs.es = sregs.gs = sregs.fs = sregs.ss = segment;

    /* Configure/set special registers of the VCPU */
    ret = ioctl(vcpufd, KVM_SET_SREGS, &sregs);
    if (ret == -1) {
        fprintf(stderr,  "ioctl(KVM_SET_SREGS): %s\n" , strerror(errno));
        return 1;
    } 

    return 0;
}

/*
 * Set initial state of VCPU registers (Intel x86-64)
 */
static inline int setup_registers(int vcpufd) {
    struct kvm_regs regs = {0};
    int ret;

    /* Code segment starts at 0x1000.
     * Instruction pointer must have initial value 0x1000.
     */
    regs.rip = PAGE_SIZE;
    regs.rflags = 0x2;          // Required for x86

    /* Memory allocated for stack has physical addr range 0x4000-0x4FFF
     * Stack pointer must begin at one past first usable byte address
     */
    regs.rsp = 0x5000;     

    /* Configure/set registers of the VCPU. */
    ret = ioctl(vcpufd, KVM_SET_REGS, &regs);
    if (ret == -1) {
        fprintf(stderr,  "ioctl(): %s\n" , strerror(errno));
        return 1;
    } 

    return 0;
}

/*
 * Set up guest VM's "physical memory" region.
 *
 * Note 1: Physical addr starts at 0x1000 with a simple 5 page layout to
 * hold guest code in pages 0-2 (0x1000-0x3FFF), stack in page 3 (0x4000-0x4FFF) and
 * virtrings in page 4 (0x5000-0x5FFF).
 * Note 2: Actual memory resource doesn't belong to any specific process, it is mapped to 
 * shared and anonymous zero-initialized memory that can be read from and written to by 
 * both, the hypervisor and the guest VM.
 *
 * Arg 0: guest_codefd = file descriptor of binary containing guest code, to be loaded to page 0.
 * Arg 1: VM file descriptor used for KVM ioctls
 * Arg 2: guest_mem = void pointer to guest memory starting address in hypervisor address space
 *
 * Critical: must write the (pointer to mmapped guest memory address) to `guest_mem` (arg 2) 
 * for further use and unmapping in caller.
 */
static inline int setup_memory_region(int guestcode_fd, int vmfd, void** guest_mem) {
    off_t guestcode_size;
    int ret;
    uint8_t* code;
    void* guest_physical_mem;
    struct kvm_userspace_memory_region memregion = {0};

    /* Gets size of guest binary */
    guestcode_size = lseek(guestcode_fd, 0, SEEK_END);
    if (guestcode_size == -1) {
        fprintf(stderr,  "lseek(): %s\n" , strerror(errno));
        return 1; 
    }

    /* Resets guest binary file pointer back to beginning of file */
    ret = lseek(guestcode_fd, 0, SEEK_SET);
    if (ret == -1) {
        fprintf(stderr,  "lseek(): %s\n" , strerror(errno));
        return 1;
    }

    /* Allocates memory to hold guest binary, read into allocated memory. */
    code = malloc(guestcode_size);
    if (code == NULL) {
        fprintf(stderr,  "malloc(): %s\n" , strerror(errno));
        return 1; 
    }

    /* Reads guest code from file into allocated memory */
    ret = read(guestcode_fd, code, guestcode_size);
    if (ret == -1) {
        fprintf(stderr,  "read(): %s\n" , strerror(errno));
        free(code);
        return 1; 
    }

    /* Allocates 5 pages of page aligned, zero-initialized shared memory to hold guest code and other segments. */
    guest_physical_mem = mmap(NULL, PAGE_SIZE * 5, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0); 
    if (guest_physical_mem == (void*) -1) {
        fprintf(stderr,  "mmap(): %s\n" , strerror(errno));
        free(code);
        return 1;
    }

    /* Copies machine code into mapped memory */
    memcpy(guest_physical_mem, code, guestcode_size);

    /* Frees memory used to hold guest binary, read into allocated memory. */
    free(code);

    /* Informs VM of allocated and mapped memory */
    memregion.slot = 0;
    memregion.guest_phys_addr = PAGE_SIZE;

    /*
     * Second page of VM's "physical" address space
     * Avoids conflict with with real-mode interrupt descriptor table
     * at address 0.
     */
    memregion.memory_size = 5 * PAGE_SIZE;
    memregion.userspace_addr = (uint64_t) guest_physical_mem;

    ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &memregion);
    if (ret == -1) {
        fprintf(stderr,  "ioctl(): %s\n" , strerror(errno));
        munmap(guest_physical_mem, PAGE_SIZE * 5);
        return 1;
    }

    /* Assigns (pointer to newly mapped guest memory address) to guest_mem */
    *guest_mem = guest_physical_mem;

    return 0;
}

/*
 * Sets up /dev/vhost-console to enable low-latency I/O handling in kernel space.
 * When enabled, writes to QueueNotify register aren't relayed to hypervisor to KVM; KVM instead
 * signals eventfd (kick_efd) registered with it to trigger kernel space worker thread to process 
 * console virtqueues.
 */
static inline int setup_vhost(int vmfd, int vcpufd, struct vhost_state* state, int output_fd) {
    int vhostfd, kick_efd, ret;

    // Opens `/dev/vhost-console` special device file.
    vhostfd = open("/dev/vhost-console", O_RDWR);
    if (vhostfd == -1) {
        fprintf(stderr,  "open(): %s\n" , strerror(errno));
        return 1;
    }
    
    /*
     * This event fd is signalled by KVM on writes to QueueNotify reg when vhost is enabled.
     *
     * When vhost is enabled, this avoids expensive context switches on I/O triggered by
     * guest -> host notifications. Virtqueue processing is done in kernel space by /dev/vhost-console.
     */
    kick_efd = eventfd(1, EFD_CLOEXEC);
    if (kick_efd == -1) {
        fprintf(stderr,  "eventfd(): %s\n" , strerror(errno));
        close(vhostfd);
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
        fprintf(stderr,  "ioctl(KVM_IOEVENTFD): %s\n" , strerror(errno));
        close(vhostfd);
        close(kick_efd);
        return 1;
    }

    /* /dev/vmm-console file descriptor */
    state->vhostfd = vhostfd;
    /* Eventfd file descriptor for signalling by KVM on QueueNotify writes by guest VM */
    state->kick_efd = kick_efd;

    /*
     * Creates idle kernel-space worker thread (kthread) to handle expensive I/O operations
     * without kernel switches. 
     */
    ret = ioctl(vhostfd, VHOST_SET_OWNER, NULL);
    if (ret == -1) {
        fprintf(stderr,  "ioctl(VHOST_SET_OWNER): %s\n" , strerror(errno));
        close(vhostfd);
        close(kick_efd);
        return 1;
    }

    /* Informs /dev/vhost-console of file descriptor used to emulate console. */
    struct vhost_vring_fd output_fd_data = {
        .queue_sel = 1,  // TX queue
        .fd = output_fd
    };
    
    ret = ioctl(vhostfd, VHOST_SET_OUTPUT_FD, &output_fd_data);
    if (ret == -1) {
        fprintf(stderr, "ioctl(VHOST_SET_OUTPUT_FD): %s\n", strerror(errno));
        close(vhostfd);
        close(kick_efd);
        return 1;
    }

    /*
     * Informs /dev/vhost-console of location of guest physical memory within hypervisor
     * address space; /dev/vhost-console uses this information to pin and map the correct 
     * pages for fast virtqueue processing.
     */
    struct memtable mt = {
        .gpa_base = 0x1000,
        .mem_size = 0x5000,
        .userspace_guest_addr = (uint64_t) guest_physical_mem_base,
    };

    ret = ioctl(vhostfd, VHOST_SET_MEMTABLE, &mt);
    if (ret == -1) {
        fprintf(stderr, "ioctl(VHOST_SET_MEMTABLE): %s\n", strerror(errno));
        close(vhostfd);
        close(kick_efd);
        return 1;
    }

    return 0;
}

/*
 * Releases all resources acquired to track /dev/vhost-console state.
 */
static inline int close_vhost(struct vhost_state* state) {
    int ret;

    if (state->vhostfd == -1) return 0;

    if (state->kick_efd != -1) {
        ret = close(state->kick_efd);
        if (ret == -1) {
            fprintf(stderr,  "close(): %s\n" , strerror(errno));
            return 1;
        }
    }

    ret = close(state->vhostfd);
    if (ret == -1) {
        fprintf(stderr,  "close(): %s\n" , strerror(errno));
        return 1;
    }

    return 0;
}

/*
 * Used as a crude mechanism for quick and easy benchmarking execution time.
 */
static uint64_t get_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;
}

int main(int argc, char* argv[]) {
    int kvm, ret, vmfd, vcpufd, guestcode_fd;
    void *guest_mem;
    struct kvm_run* run;
    size_t kvm_run_mmap_size;
    int output_fd;
    bool halted;
    bool use_vhost = false;
    uint64_t start_us, end_us;
    int opt;

    struct vhost_state state = {
        .vhostfd = -1,
        .kick_efd = -1
    };

    /* Iterates over CLI args and handle valid flags */
    while ((opt = getopt(argc, argv, "vh")) != -1) {
        switch (opt) {
            /* Enables vhost acceleration */
            case 'v':
                use_vhost = true;
                printf("=== Vhost acceleration enabled ===\n");
                break;
            /* Prints help/usage message to stdout */
            case 'h':
                printf("Usage: %s [-v] [-h]\n", argv[0]);
                printf("  -v    Enable vhost acceleration\n");
                printf("  -h    Show this help message\n");
                return 0;
                break;
            default:
                return 1;
        }
    }

    /* Emulates console device using /dev/vmm-console file */
    output_fd = open("/dev/vmm-console", O_WRONLY | O_CREAT | O_TRUNC);
    if (output_fd == -1) {
        fprintf(stderr,  "open(): %s\n" , strerror(errno));
        return 1;
    } 

    /* User logged in at console must be part of kvm group to access /dev/kvm */
    kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm == -1) {
        fprintf(stderr,  "open(): %s\n" , strerror(errno));
        close(output_fd);
        return 1;
    }

    /* Ensures usage of stable version of the KVM API: Version 12 */
    ret = ioctl(kvm, KVM_GET_API_VERSION, NULL);
    if (ret == -1) {
        fprintf(stderr,  "ioctl(): %s\n" , strerror(errno));
        close(output_fd);
        close(kvm);
        return 1;
    }

    if (ret != 12) {
        fprintf(stderr,  "KVM_GET_API_VERSION: %d, expected 12" , ret);
        close(output_fd);
        close(kvm);
        return 1;
    }

    /*
     * Creates VM with machine type 0;
     * VM has no memory or virtual CPUs yet
     */
    vmfd = ioctl(kvm, KVM_CREATE_VM, 0);
    if (vmfd == -1) {
        fprintf(stderr,  "ioctl(): %s\n" , strerror(errno));
        close(output_fd);
        close(kvm);
        return 1;
    }

    /* Reads guest.bin from disk */
    guestcode_fd = open("build/guest.bin", O_RDONLY);
    if (guestcode_fd == -1) {
        fprintf(stderr,  "open(): %s\n" , strerror(errno));
        close(output_fd);
        close(kvm);
        return 1; 
    }

    /* Sets up VM memory region and copy guest code to it */
    if ((ret = setup_memory_region(guestcode_fd, vmfd, &guest_mem))) {
        close(output_fd);
        close(kvm);
        close(guestcode_fd);
        return ret;
    }

    guest_physical_mem_base = guest_mem;

    /* Creates virtual CPU to run code in guest physical memory. */
    vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, 0);
    if (vcpufd == -1) {
        fprintf(stderr,  "ioctl(): %s\n" , strerror(errno));
        close(output_fd);
        close(kvm);
        close(guestcode_fd);
        return 1;
    }

    /* Determines size of memory to map to hold kvm_run structure */
    kvm_run_mmap_size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (kvm_run_mmap_size == -1) {
        fprintf(stderr,  "ioctl(): %s\n" , strerror(errno));
        close(output_fd);
        close(kvm);
        close(guestcode_fd);
        return 1;
    } 

    /* 
     * Allocates kvm_run mmap_size sized memory for kvm_run data structure 
     * that tracks information from VM exits 
     */
    run = mmap(NULL, kvm_run_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);
    if (run == (void*) -1) {
        fprintf(stderr,  "mmap(): %s\n" , strerror(errno));
        close(output_fd);
        close(kvm);
        close(guestcode_fd);
        return 1;
    }
    
    /* Sets up VCPU special regs initial state */
    if ((ret = setup_sregisters(vcpufd))) {
        close(output_fd);
        close(kvm);
        close(guestcode_fd);
        return ret;
    }

    /* Sets up VCPU regs initial state */
    if ((ret = setup_registers(vcpufd))) {
        close(output_fd);
        close(kvm);
        close(guestcode_fd);
        return ret;
    }

    /* Sets up vhost-console device if vhost is enabled in CLI */
    if (use_vhost && (ret = setup_vhost(vmfd, vcpufd, &state, output_fd)))  {
        close(output_fd);
        close(kvm);
        close(guestcode_fd);
        return ret;
    }

    halted = false;

    /* Exec time benchmarking */
    start_us = get_us();

    while (1) {
        /* Runs VM with VT-x support in KVM! */
        ret = ioctl(vcpufd, KVM_RUN, NULL);
        if (ret == -1) {
            fprintf(stderr,  "ioctl(): %s\n" , strerror(errno));
            close(output_fd);
            close(kvm);
            close(guestcode_fd);
            return 1;
        } 

        switch (run->exit_reason) {
            /* VM called `hlt` instruction */
            case KVM_EXIT_HLT: {
                printf("[KVM_EXIT_HLT: program halted normally] \n" );
                halted = true;
                break;
            }
            /* VM wrote to i/o port */
            case KVM_EXIT_IO: {
                if (run->io.direction == KVM_EXIT_IO_OUT && 
                    run->io.size == 1 &&
                    run->io.port == 0x3f8 &&
                    run->io.count == 1) {
                    char* serial_msg = ((char *) run + run->io.data_offset);
                    fprintf(stderr,  "%s" , serial_msg);
                } else
                    fprintf(stderr,  "[unhandled KVM_EXIT_IO]\n" );
                break;
            }
            /*
             * VM read/wrote to memory outside its physical addr range
             * Used for VirtIO MMIO
             */
            case KVM_EXIT_MMIO: {
                if (run->mmio.phys_addr < VIRTIO_MMIO_BASE || run->mmio.phys_addr >= VIRTIO_MMIO_BASE + VIRTIO_MMIO_SIZE) {
                    fprintf(stderr,  "[unhandled MMIO @ 0x%llx] \n" , run->mmio.phys_addr);
                    halted = true;
                    break;
                }

                /* Ignore writes to QueueNotify if vhost enabled */
                if (
                    use_vhost && 
                    run->mmio.phys_addr == VIRTIO_MMIO_BASE + REG_QUEUE_NOTIFY 
                ) {
                    /* this line should be unreachable */
                    break;
                }

                if (run->mmio.is_write) 
                    handle_mmio_write(run->mmio.phys_addr, run->mmio.data, run->mmio.len, vcpufd, &state, output_fd);
                else 
                    handle_mmio_read(run->mmio.phys_addr, run->mmio.data, run->mmio.len, vcpufd, &state);
                
                break;
            }
            /* Likely set up VCPU incorrectly and doesn't align with Intel VT pre-reqs */
            case KVM_EXIT_FAIL_ENTRY: {
                fprintf(
                    stderr, 
                     "[KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = %llx] \n" ,
                    (unsigned long long) run->fail_entry.hardware_entry_failure_reason
                );
                halted = true;
                break;
            }
            /* Error internal to KVM */
            case KVM_INTERNAL_ERROR_EMULATION: {
                fprintf(
                    stderr,
                     "[KVM_INTERNAL_ERROR_EMULATION: suberror = 0x%x] \n" ,
                    run->emulation_failure.suberror
                );
                halted = true;
                break;
            }
            default: {
                fprintf(stderr,  "[Unhandled KVM exit reason: %d]\n" , run->exit_reason);
                halted = true;
                break;
            }
        }

        if (halted) break;
    }

    /* Exec time benchmarking */
    end_us = get_us();

    printf("\nTime taken to run VM: %lu microseconds\n", end_us - start_us);

    /*
     * Best effort resource clean-up
     */

    /* Releases resources that track /dev/vhost-console device */
    if ((ret = close_vhost(&state))) {
        close(output_fd);
        close(kvm);
        close(guestcode_fd);
        return ret;
    }

    /* Releases memory page allocated for guest VM's memory */
    ret = munmap(guest_mem, PAGE_SIZE * 5);
    if (ret == -1) {
        fprintf(stderr,  "munmap(): %s\n", strerror(errno));
        return 1;
    } 

    /* Releases memory allocated for kvm_run structure to track VM VCPU state */
    ret = munmap(run, kvm_run_mmap_size);
    if (ret == -1) {
        fprintf(stderr,  "munmap(): %s\n", strerror(errno));
        return 1;
    } 

    /* Closes /dev/vmm-console file */
    ret = close(output_fd);
    if (ret == -1) {
        fprintf(stderr,  "close(): %s\n", strerror(errno));
        return 1;
    }

    /* Closes guest.bin file*/
    ret = close(guestcode_fd);
    if (ret == -1) {
        fprintf(stderr,  "close(): %s\n", strerror(errno));
        return 1;
    }

    /* Closes /dev/kvm device file */
    ret = close(kvm);
    if (ret == -1) {
        fprintf(stderr,  "close(): %s\n", strerror(errno));
        return 1;
    }

    return 0;
}