#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

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
#include "helpers.h"

MODULE_AUTHOR("Vismay Suramwar <vismaysuramwar@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Vhost acceleration for hypervisor console device");

#define DEBUG

struct vhost_vring_state {
    uint16_t queue_sel;
    uint16_t num;
};

struct vhost_vring_addr {
    uint16_t queue_sel;
    uint64_t desc_addr;
    uint64_t avail_addr;
    uint64_t used_addr;
};

struct vhost_vring_fd {
    uint16_t queue_sel;
    int fd;
};

// Virtqueue used for guest-device communication
struct virtqueue {
    uint64_t            desc_addr;
    uint64_t            avail_addr;
    uint64_t            used_addr;
    uint16_t            num;
    uint8_t             queue_ready;
    struct eventfd_ctx* kick_efd;
    struct file*        output_fd;
};

struct console_device {
    // Virtqueues used for device-guest communication (0 = rx, 1 = tx)
    struct virtqueue queues[2]; 
    // Userspace hypervisor's stdout (emulated as console device)
    struct file* fs;
    // Worker thread
    struct task_struct *work_thread;
};

static int worker_thread(void* data) {
    struct console_device *dev = data;

    while (!kthread_should_stop()) {
        uint64_t count;

        eventfd_ctx_do_read(dev->queues[1].kick_efd, &count);

        kernel_write(dev->queues[1].output_fd, "you\n", 4, 0);
    }

    return 0;
}

long vhost_console_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct console_device* device = file->private_data;
    struct vhost_vring_state    state_data;
    struct vhost_vring_addr     addr_data;
    struct vhost_vring_fd       fd_data;
    struct file*                output_fd;

    switch (cmd) {
        case VHOST_SET_VRING_NUM:
            if (copy_from_user(&state_data, (int __user *) arg, sizeof(struct vhost_vring_state))) {
                pr_err("copy_from_user() failed to copy some bytes");
                return -EFAULT;
            }
            device->queues[state_data.queue_sel].num = state_data.num;
            break;
        case VHOST_SET_VRING_ADDR:
            if (copy_from_user(&addr_data, (int __user *) arg, sizeof(struct vhost_vring_addr))) {
                pr_err("copy_from_user() failed to copy some bytes");
                return -EFAULT;
            }
            device->queues[addr_data.queue_sel].avail_addr = addr_data.avail_addr;
            device->queues[addr_data.queue_sel].desc_addr = addr_data.desc_addr;
            device->queues[addr_data.queue_sel].used_addr = addr_data.used_addr;
            break;
        case VHOST_SET_VRING_KICK:
            if (copy_from_user(&fd_data, (int __user *) arg, sizeof(struct vhost_vring_fd))) {
                pr_err("copy_from_user() failed to copy some bytes");
                return -EFAULT;
            }
            device->queues[fd_data.queue_sel].kick_efd = eventfd_ctx_fdget(fd_data.fd);
            if (fd_data.queue_sel == 1 && device->work_thread) {
                wake_up_process(device->work_thread);
            }
            break;
        case VHOST_SET_OWNER:
            device->work_thread = kthread_create(worker_thread, device, "vhost-console-worker");
            if (IS_ERR(device->work_thread)) {
                pr_err("kthread_create()\n");
                return -EFAULT;
            }
            break;
        case VHOST_SET_OUTPUT_FD:
            if (copy_from_user(&fd_data, (int __user *) arg, sizeof(struct vhost_vring_fd))) {
                pr_err("copy_from_user() failed to copy some bytes");
                return -EFAULT;
            }
            output_fd = fget(fd_data.fd);
            if (!output_fd) {
                pr_err("fdget(): received invalid file via VHOST_SET_OUTPUT_FD\n");
                return -EBADF;
            }
            device->queues[fd_data.queue_sel].output_fd = output_fd;
            break;
        default:
            pr_err("Unknown IOCTL cmd\n");
            return -EINVAL;
    }

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
    file->private_data = device;

    #ifdef DEBUG
    pr_info(KERN_COLOR "Successfully opened vhost-console device!\n" RESET_COLOR);
    #endif 

    return 0;
}

int vhost_console_release(struct inode *inode, struct file *file) {
    struct console_device* device = file->private_data;

    int ret = kthread_stop(device->work_thread);
    if (ret < 0) {
        pr_err("kthread_stop()\n");
        return ret;
    }

    kfree(device);

    #ifdef DEBUG
    pr_info(KERN_COLOR "Successfully closed vhost-console device!\n" RESET_COLOR);
    #endif

    return 0;
}

struct file_operations fops = {
    .unlocked_ioctl = vhost_console_ioctl,
    .open = vhost_console_open,
    .release = vhost_console_release,
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

    #ifdef DEBUG
    pr_info(KERN_COLOR "vhost-console: Device registered\n" RESET_COLOR);
    #endif

    return 0;
}

static void __exit vhost_module_exit(void) {
    misc_deregister(&device);

    #ifdef DEBUG
    pr_info(KERN_COLOR "vhost-console: Device deregistered\n" RESET_COLOR);
    #endif
}

module_init(vhost_module_init);
module_exit(vhost_module_exit);