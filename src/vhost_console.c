/*
 * Kernel-space I/O request handling for VirtIO console device.
 *
 * Configured by userspace VMM / hypervisor.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "asm/page_types.h"
#include "linux/gfp.h"
#include <linux/poll.h>
#include "linux/mm_types.h"
#include "linux/sched.h"
#include "linux/wait.h"
#include "linux/uaccess.h"
#include "linux/types.h"
#include "asm/current.h"
#include "linux/printk.h"
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/eventfd.h>
#include <linux/kthread.h>
#include "vhost_console.h"
#include <linux/io.h>
#include <linux/mm.h>

// #define DEBUG

MODULE_AUTHOR("Vismay Suramwar <vismaysuramwar@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Vhost I/O acceleration for x86-hypervisor console device");

/* 
 * Used for VHOST_SET_VRING_NUM ioctl 
 * Allows hypervisor to configure number of descriptors in a virtqueue 
 */
struct vhost_vring_state {
    uint16_t queue_sel;     // Virtqueue index (0 = RX, 1 = TX)
    uint16_t num;           // Number of descriptors
};

/* 
 * Used for VHOST_SET_VRING_ADDR ioctl 
 * Sets physical addresses of descriptor, available, and used rings
 */
struct vhost_vring_addr {
    uint16_t queue_sel;     // Virtqueue index
    uint64_t desc_addr;     // Descriptor table base
    uint64_t avail_addr;    // Available ring base
    uint64_t used_addr;     // Used ring base
};

/* 
 * Used for VHOST_SET_VRING_KICK ioctl 
 * Associates an eventfd for virtqueue notifications
 */
struct vhost_vring_fd {
    uint16_t queue_sel;     // Virtqueue index
    int fd;                 // Eventfd file descriptor
};

/* Virtqueue used for guest <-> device communication */
struct virtqueue {
    uint64_t            desc_addr;      // Descriptor vring address
    uint64_t            avail_addr;     // Available vring address
    uint64_t            used_addr;      // Used vring address

    uint16_t            num;            // Queue size
    uint8_t             queue_ready;    // Queue usability state
    struct eventfd_ctx* kick_efd;       /* Event fd signalled by KVM on 
                                           guest mmio write to QueueNotify register */
    struct file*        output_fd;      // File descriptor of file used to emulate console device
    loff_t              output_off;     // Offset of data written to file
};

/* 
 * Set via VHOST_SET_MEMTABLE ioctl 
 * Maps guest physical memory to hypervisor's address space.
 */
struct memtable {
    uint64_t gpa_base;              // guest physical address base
    uint64_t mem_size;              // size of mapped guest memory
    uint64_t userspace_guest_addr;  // address of guest memory in VMM address space
};

/*
 * VirtIO console device state tracked by /dev/vhost-console
 * Tracks virtqueues, memory, and worker thread
 */
struct console_device {
    /* Virtqueues used for device-guest communication (0 = rx, 1 = tx) */
    struct virtqueue queues[2]; 

    /* Mem table to translate guest physical addresses to VMM virtual addresses */
    struct memtable mt;

    /* Worker thread (inherits hypervisor's memory mappings) */
    struct task_struct *work_thread;
    char*               guest_memory;

    /* Mmapped pages from guest memory */
    unsigned long       num_guest_pages;
    struct page**       guest_pages;
    struct mm_struct*   mm;
};

/* 
 * Converts guest physical address to hypervisor virtual address
 * Returns pointer into mapped guest memory
 */
static inline void* guest_to_host_va(uint32_t ptr, struct console_device *device) {
    return (char *) device->guest_memory + (ptr - device->mt.gpa_base); 
}

/* 
 * Processes virtqueue entries in kernel thread context
 * Walks available ring -> fetches descriptor -> writes to console
 */
static int process_virtqueue(uint8_t queue_num, struct console_device *device) {
    uint16_t avail_idx, used_idx;
    char *avail, *used, *desc;

    /* virtqueue selected for processing */
    struct virtqueue* vq = &device->queues[queue_num];

    /* base address of available table/vring */
    avail = guest_to_host_va(vq->avail_addr, device);
    
    /* index into next free available table/vring entry to use */
    avail_idx = *(uint16_t*)(avail + 2);;

    /* base address of used table/vring */
    used = guest_to_host_va(vq->used_addr, device);

    /* index into next free used table/vring entry to use */
    used_idx = *(uint16_t*)(used + 2);

    /* base address of descriptor table/vring */
    desc = guest_to_host_va(vq->desc_addr, device);

    /* nothing to process */
    if (avail_idx == used_idx) return 0;

    while (used_idx != avail_idx) {
        /*
         * Gets first 2-byte entry in available vring that hasn't yet been read by device
         * Entry is read to get next descriptor vring entry index that must be read.
         */
        uint16_t* avail_ring_entry = (uint16_t *) (avail + 4 + 2 * (used_idx % vq->num));
        uint16_t desc_idx = *(avail_ring_entry);

        /*
         * Use index obtained from available table / vring entry to get descriptor vring entry
         * Read indexed descriptor vring entry to find memory buffer that must be processed.
         */
        char* desc_ring_entry = (desc + desc_idx * 16);
        uint64_t addr = *(uint64_t*)(desc_ring_entry);
        uint32_t len = *(uint32_t*)(desc_ring_entry + 8);

        /* EMULATE CONSOLE!! */
        if (!vq->output_fd) {
            pr_warn("Output file descriptor to emulate console was never correctly set\n");
        } else {
            kernel_write(vq->output_fd, guest_to_host_va(addr, device), len, &vq->output_off); 
        }

        used_idx++;
    }

    /* Update used_idx to reflect 'walked' used vring entries */
    *(uint16_t*)(used + 2) = used_idx;

    /* TODO: figure out how to inject interrupts/notifications into guest VM */
    // device.interrupt_status |= 1;
    // -> some procedure call to inject interrupt into VM

    return 0;
}

/* 
 * Worker thread function 
 * Waits for virtqueue kick event and processes TX queue
 */
static int worker_thread(void* data) {
    struct console_device *device = data;
    int ret;

    while (!kthread_should_stop()) {
        uint64_t count;

        /* Wait for kick notification */
        eventfd_ctx_do_read(device->queues[1].kick_efd, &count);

        /* Virtqueue processing */
        if ((ret = process_virtqueue(1, device))) return ret;
    }

    return 0;
}

/* 
 * Pins guest pages and maps them into kernel address space
 * Returns number of pages mapped or negative error code
 */
static int pin_and_mmap_pages(
    size_t memregion_size, 
    struct page*** pages, 
    uint64_t userspace_addr, 
    char** mmap_addr,
    struct mm_struct* mm
) {
    unsigned long num_pages;
    int ret, i;

    /*
     * Allocate array of page structures to pin guest pages
     */
    num_pages = (memregion_size) >> PAGE_SHIFT;
    *pages = kmalloc_array(num_pages, sizeof(struct page*), GFP_KERNEL);
    if (!*pages) {
        pr_err("kmalloc_array() returned nullptr\n");
        return -ENOMEM;
    }

    /*
     * Pins guest pages using allocated array of page structures by 
     * increasing ref count of each page.
     */
    down_read(&mm->mmap_lock);
    ret = get_user_pages_remote(
        mm, 
        userspace_addr, 
        num_pages, 
        FOLL_WRITE | FOLL_FORCE, 
        *pages, 
        NULL, 
        NULL
    );
    up_read(&mm->mmap_lock);
    if (ret != num_pages) {
        pr_err("get_user_pages_remote(): failed to pin pages\n");
        return -EFAULT;
    }

    /*
     * Maps pinned guest pages into kernel address space
     */
    *mmap_addr = vmap(*pages, num_pages, VM_MAP, PAGE_KERNEL);
    if (!*mmap_addr) {
        for (i = 0; i < num_pages; i++)
            put_page((*pages)[i]);
        kfree(*pages);
        return -ENOMEM;
    }

    /*
     * Address returned by vmap is aligned by PAGE_SIZE
     *
     * Increment mapped memory by offset into first page to get 
     * actual start address of guest memory.
     */
    *mmap_addr += (userspace_addr & ~PAGE_MASK);

    return num_pages;
}

/* 
 * Wrapper to map guest memory region into kernel space
 */
static int mmap_guest(struct console_device *device, struct mm_struct* mm) {
    size_t memregion_size;
    unsigned long num_pages;
    struct page** pages;
    char* mapped_addr;

    /* 
     * device->mt.mem_size tracks the size of the guest VM's physical memory; 
     * we must align this size by PAGE_SIZE to get the correct number of guest pages to pin
     * and map into the kernel's address space
     */
    memregion_size = ALIGN(device->mt.mem_size, PAGE_SIZE);
    num_pages = pin_and_mmap_pages(
        memregion_size, 
        &pages,             // pages is set by pin_and_mmap_pages
        (uint64_t) device->mt.userspace_guest_addr, 
        &mapped_addr,   // mapped_addr is set by pin_and_mmap_pages
        mm
    );
    if (num_pages < 0) {
        pr_err("pin_and_mmap_pages() failed\n");
        return num_pages;
    }

    device->guest_memory = mapped_addr;
    device->guest_pages = pages;
    device->num_guest_pages = num_pages;

    return 0;
}

/* 
 * IOCTL handler for vhost-console
 * Implements all VHOST_* commands used by hypervisor/VMM
 */
long vhost_console_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct console_device* device = file->private_data;
    struct vhost_vring_state    state_data;
    struct vhost_vring_addr     addr_data;
    struct vhost_vring_fd       fd_data;
    struct memtable             mt;
    struct file*                output_fd;
    struct virtqueue*           vq;
    int ret;

    switch (cmd) {
        /* Hypervisor configures number of descriptors in a virtqueue */
        case VHOST_SET_VRING_NUM:
            if (copy_from_user(&state_data, (int __user *) arg, sizeof(struct vhost_vring_state))) {
                pr_err("copy_from_user() failed to copy some bytes");
                return -EFAULT;
            }
            device->queues[state_data.queue_sel].num = state_data.num;
            break;
        /* Hypervisor sets physical addresses of descriptor, available, and used rings */
        case VHOST_SET_VRING_ADDR:
            if (copy_from_user(&addr_data, (int __user *) arg, sizeof(struct vhost_vring_addr))) {
                pr_err("copy_from_user() failed to copy some bytes");
                return -EFAULT;
            }

            vq = &device->queues[addr_data.queue_sel];
            if (vq->queue_ready) return -EBUSY;

            vq->avail_addr = addr_data.avail_addr;
            vq->used_addr = addr_data.used_addr;
            vq->desc_addr = addr_data.desc_addr;

            break;
        /* 
         * Hypervisor provides an associated eventfd for virtqueue notifications
         *
         * Virtqueue is marked as ready; device may begin processing I/O requests now
         */
        case VHOST_SET_VRING_KICK:
            if (copy_from_user(&fd_data, (int __user *) arg, sizeof(struct vhost_vring_fd))) {
                pr_err("copy_from_user() failed to copy some bytes");
                return -EFAULT;
            }
            device->queues[fd_data.queue_sel].kick_efd = eventfd_ctx_fdget(fd_data.fd);
            if (IS_ERR(device->queues[fd_data.queue_sel].kick_efd)) {
                pr_err("eventfd_ctx_fdget()\n");
                return PTR_ERR(device->queues[fd_data.queue_sel].kick_efd);
            }
            device->queues[fd_data.queue_sel].queue_ready = 1;
            if (fd_data.queue_sel == 1 && device->work_thread) {
                wake_up_process(device->work_thread);
            }
            break;
        /* Hypervisor takes "ownership" of /dev/vhost-console; creates worker thread, but doesn't yet run it */
        case VHOST_SET_OWNER:
            device->work_thread = kthread_create(worker_thread, device, "vhost-console-worker");
            if (IS_ERR(device->work_thread)) {
                pr_err("kthread_create()\n");
                return PTR_ERR(device->work_thread);
            }
            device->mm = current->mm;
            break;
        /* 
         * Hypervisor provides a file descriptor for /dev/vmm-console, 
         * a special device file used to emulate console device.
         */
        case VHOST_SET_OUTPUT_FD:
            if (copy_from_user(&fd_data, (int __user *) arg, sizeof(struct vhost_vring_fd))) {
                pr_err("copy_from_user() failed to copy some bytes");
                return -EFAULT;
            }
            output_fd = fget(fd_data.fd);
            output_fd->f_flags = O_NONBLOCK;
            if (!output_fd) {
                pr_err("fdget(): received invalid file via VHOST_SET_OUTPUT_FD\n");
                return -EBADF;
            }
            device->queues[fd_data.queue_sel].output_fd = output_fd;
            device->queues[fd_data.queue_sel].output_off = 0;
            break;
        /* 
         * Hypervisor provides /dev/vhost-console information to map guest physical memory to 
         * hypervisor's address space; /dev/vhost-console uses this info to map these pages into its 
         * own address space for fast virtqueue processing.
         */
        case VHOST_SET_MEMTABLE:
            if (copy_from_user(&mt, (int __user *) arg, sizeof(struct memtable))) {
                pr_err("copy_from_user() failed to copy some bytes");
                return -EFAULT;
            }
            device->mt = mt;

            if (!device->mm) {
                pr_err("VHOST_SET_OWNER must be called before VHOST_SET_MEMTABLE\n");
                return -EINVAL;
            }

            ret = mmap_guest(device, device->mm);
            if (ret < 0) {
                pr_err("mmap_guest() failed\n");
                return ret;
            }
            break;
        default:
            pr_err("Unknown IOCTL cmd\n");
            return -EINVAL;
    }

    return 0;
}

/* 
 * Open function for vhost-console device 
 * Allocates and initializes console_device structure
 */
int vhost_console_open(struct inode *inode, struct file *file) {
    struct console_device* device;

    device = kzalloc(sizeof(struct console_device), GFP_KERNEL);
    if (device == NULL) {
        pr_err("kzalloc() returned nullptr\n");
        return -ENOMEM;
    }

    file->private_data = device;

    #ifdef DEBUG
    pr_info("Successfully opened vhost-console device!\n");
    #endif 

    return 0;
}

/* 
 * Release function for vhost-console device 
 * Cleans up memory, pinned pages, and worker thread
 */
int vhost_console_release(struct inode *inode, struct file *file) {
    struct console_device* device = file->private_data;
    int queue_sel, i;

    /*
     * Stop running worker thread to avoid further virtqueue processing
     */
    if (device->work_thread) {
        int ret = kthread_stop(device->work_thread);
        if (ret < 0) {
            pr_err("kthread_stop()\n");
            return ret;
        }
    }

    /*
     * Release resources with each virtqueue.
     */
    for (queue_sel = 0; queue_sel < 2; queue_sel++) {
        struct virtqueue* vq = &device->queues[queue_sel];

        if (vq->kick_efd)
            eventfd_ctx_put(vq->kick_efd);

        if (vq->output_fd)
            fput(vq->output_fd);
    }

    if (device->guest_memory) {
        /*
        * In `pin_and_mmap_pages`, the guest starting address returned 
        * by vmap is aligned by PAGE_SIZE. Hence, we incremented mapped memory 
        * by offset into first page to get actual start address of guest memory.
        *
        * We must undo this in order to get address provided by vmap function call.
        */
        device->guest_memory -= (device->mt.userspace_guest_addr & ~PAGE_MASK);
        vunmap(device->guest_memory);
        for (i = 0; i < device->num_guest_pages; i++) {
            /* 
             * Reduce ref count of pages within hypervisor address space that contain
             * guest physical memory.
             */
            put_page(device->guest_pages[i]);
        }
        kfree(device->guest_pages);
    }

    kfree(device);

    #ifdef DEBUG
    pr_info("Successfully closed vhost-console device!\n");
    #endif

    return 0;
}

/* File operations structure */
struct file_operations fops = {
    .unlocked_ioctl = vhost_console_ioctl,
    .open = vhost_console_open,
    .release = vhost_console_release,
};

/* Misc device registration structure */
struct miscdevice device = {
    .name = "vhost-console",
    .minor = MISC_DYNAMIC_MINOR,
    .fops = &fops,
};

/* Module initialization */
static int __init vhost_module_init(void) {
    int ret;
    
    if ((ret = misc_register(&device))) {
        pr_err("mis_register() failed");
        return ret;
    }

    #ifdef DEBUG
    pr_info("vhost-console: Device registered\n");
    #endif

    return 0;
}

/* Module exit */
static void __exit vhost_module_exit(void) {
    misc_deregister(&device);

    #ifdef DEBUG
    pr_info("vhost-console: Device deregistered\n");
    #endif
}

module_init(vhost_module_init);
module_exit(vhost_module_exit);