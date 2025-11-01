#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "asm/current.h"
#include "linux/printk.h"
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/file.h>

MODULE_AUTHOR("Vismay Suramwar <vismaysuramwar@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Vhost acceleration for hypervisor console device");

// Virtqueue used for guest-device communication
struct virtqueue {
    uint64_t desc_addr;
    uint64_t avail_addr;
    uint64_t used_addr;
    uint16_t num;
    uint8_t queue_ready;
};

struct console_device {
    // Virtqueues used for device-guest communication (0 = rx, 1 = tx)
    struct virtqueue queues[2]; 
    // Selected virtqueue
    unsigned int queue_sel;
    // Userspace hypervisor's stdout (emulated as console device)
    struct file* fs;
    // Worker thread
    struct task_struct *work_thread;
    atomic_t stop_thread;
};

long vhost_console_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    return 0;
}

int vhost_console_open(struct inode *inode, struct file *file) {
    struct console_device* device;

    device = kzalloc(sizeof(struct console_device), GFP_KERNEL);
    if (device == NULL) {
        pr_err("kzalloc() returned nullptr\n");
        return -ENOMEM;
    }

    device->fs = fget(1);

    kernel_write(device->fs, "test output\n", 12, 0);

    return 0;
}

struct file_operations fops = {
    .open = vhost_console_open,
    .unlocked_ioctl = vhost_console_ioctl,
};

struct miscdevice device = {
    .name = "vhost-console",
    .minor = MISC_DYNAMIC_MINOR,
    .fops = &fops,
};

static int __init vhost_module_init(void) {
    int ret;
    
    if ((ret = misc_register(&device))) {
        pr_err("mis_register() failed");
        return ret;
    }

    pr_info("vhost-console: Device registered\n");

    return 0;
}

static void __exit vhost_module_exit(void) {
    misc_deregister(&device);
    pr_info("vhost-console: Device deregistered\n");
}

module_init(vhost_module_init);
module_exit(vhost_module_exit);