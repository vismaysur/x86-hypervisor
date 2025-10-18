#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdbool.h>

#define PAGE_SIZE getpagesize()

int main() {
    int kvm, ret, vmfd, vcpufd;
    void *guest_mem;
    struct kvm_run* run;
    size_t kvm_run_mmap_size;
    struct kvm_userspace_memory_region memregion;
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    bool halted;

    // 16-bit x86 code written in scripts/serial_test.asm
    // obj dump:
    // 0:   ba f8 03 b0 34          mov    $0x34b003f8,%edx
    // 5:   ee                      out    %al,(%dx)
    // 6:   b0 0a                   mov    $0xa,%al
    // 8:   ee                      out    %al,(%dx)
    // 9:   f4                      hlt
    //      ...
    // 1fe: 55                      push   %ebp
    // 1ff: aa                      stos   %al,%es:(%edi)
    const uint8_t code[] = {
        0xba, 0xf8, 0x03, 0xb0, 0x34,
        0xee, 
        0xb0, 0x0a,
        0xee,
        0xf4
    };

    // user logged in at console must be part of kvm group to access /dev/kvm
    kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm == -1) {
        fprintf(stderr, "open(): %s\n", strerror(errno));
        return 1;
    }

    ret = ioctl(kvm, KVM_GET_API_VERSION, NULL);
    if (ret == -1) {
        fprintf(stderr, "ioctl(): %s\n", strerror(errno));
        return 1;
    }

    // ensure usage of stable version of the KVM API: Version 12
    if (ret != 12) {
        fprintf(stderr, "KVM_GET_API_VERSION: %d, expected 12", ret);
        return 1;
    }

    // create VM with machine type 0
    // VM has no memory or virtual CPUs
    vmfd = ioctl(kvm, KVM_CREATE_VM, 0);
    if (vmfd == -1) {
        fprintf(stderr, "ioctl(): %s\n", strerror(errno));
        return 1;
    }

    // allocate single page of page aligned, zero-initialized shared memory to hold guest code
    guest_mem = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0); 
    if (guest_mem == (void*) -1) {
        fprintf(stderr, "mmap(): %s\n", strerror(errno));
        return 1;
    }

    // copy machine code into mapped memory
    memcpy(guest_mem, code, sizeof(code));

    // inform VM of allocated and mapped memory
    memregion.slot = 0;
    memregion.guest_phys_addr = PAGE_SIZE;
    // second page of VM's "physical" address space
    // avoids conflict with with non-existent real-mode interrupt descriptor table
    // at address 0
    memregion.memory_size = PAGE_SIZE;
    memregion.userspace_addr = (uint64_t) guest_mem;

    ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &memregion);
    if (ret == -1) {
        fprintf(stderr, "ioctl(): %s\n", strerror(errno));
        return 1;
    } 

    // create virtual CPU to run code in guest physical memory.
    vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, 0);
    if (vcpufd == -1) {
        fprintf(stderr, "ioctl(): %s\n", strerror(errno));
        return 1;
    } 

    // determine size of memory to map to hold kvm_run structure
    kvm_run_mmap_size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (kvm_run_mmap_size == -1) {
        fprintf(stderr, "ioctl(): %s\n", strerror(errno));
        return 1;
    } 


    // allocate kvm_run mmap_size sized memory for kvm_run data structure.
    run = mmap(NULL, kvm_run_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);
    if (run == (void*) -1) {
        fprintf(stderr, "mmap(): %s\n", strerror(errno));
        return 1;
    }

    // set initial state of registers of the VCPU
    // change only two fields of special regs
    ret = ioctl(vcpufd, KVM_GET_SREGS, &sregs);
    if (ret == -1) {
        fprintf(stderr, "ioctl(): %s\n", strerror(errno));
        return 1;
    } 

    sregs.cs.base = 0;
    sregs.cs.selector = 0;

    ret = ioctl(vcpufd, KVM_SET_SREGS, &sregs);
    if (ret == -1) {
        fprintf(stderr, "ioctl(): %s\n", strerror(errno));
        return 1;
    } 

    // init most of general purpose regs to 0, set some fields
    regs.rip = PAGE_SIZE;
    regs.rflags = 0x2;
    ret = ioctl(vcpufd, KVM_SET_REGS, &regs);
    if (ret == -1) {
        fprintf(stderr, "ioctl(): %s\n", strerror(errno));
        return 1;
    } 

    halted = false;

    while (1) {
        ret = ioctl(vcpufd, KVM_RUN, NULL);
        if (ret == -1) {
            fprintf(stderr, "ioctl(): %s\n", strerror(errno));
            return 1;
        } 

        switch (run->exit_reason) {
            case KVM_EXIT_HLT:
                printf("KVM_EXIT_HLT\n");
                halted = true;
                break;
            case KVM_EXIT_IO:
                if (run->io.direction == KVM_EXIT_IO_OUT && 
                    run->io.size == 1 &&
                    run->io.port == 0x3f8 &&
                    run->io.count == 1)
                    putchar(*((char *) run + run->io.data_offset));
                else
                    fprintf(stderr, "unhandled KVM_EXIT_IO\n");
                break;
            case KVM_EXIT_FAIL_ENTRY:
                fprintf(
                    stderr, 
                    "KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reaon = %llx\n",
                    (unsigned long long) run->fail_entry.hardware_entry_failure_reason
                );
                halted = true;
                break;
            case KVM_INTERNAL_ERROR_EMULATION:
                fprintf(
                    stderr,
                    "KVM_INTERNAL_ERROR_EMULATION: suberror = 0x%x\n",
                    run->emulation_failure.suberror
                );
                halted = true;
                break;
        }

        if (halted) break;
    }

    // release memory page allocated for guest VM's memory
    ret = munmap(guest_mem, PAGE_SIZE);
     if (ret == -1) {
        fprintf(stderr, "munmap(): %s\n", strerror(errno));
        return 1;
    } 

    // release memory allocated for kvm_run structure to track VM VCPU state
    ret = munmap(run, kvm_run_mmap_size);
    if (ret == -1) {
        fprintf(stderr, "munmap(): %s\n", strerror(errno));
        return 1;
    } 

    // close /dev/kvm device file
    ret = close(kvm);
    if (ret == -1) {
        fprintf(stderr, "close(): %s\n", strerror(errno));
        return 1;
    } 

    return 0;
}