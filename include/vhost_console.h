#ifndef VHOST_CONSOLE_H
#define VHOST_CONSOLE_H

#define MYCHARDEV_MAGIC         'M'
#define VHOST_SET_VRING_NUM     _IOW(MYCHARDEV_MAGIC, 0, struct vhost_vring_state)
#define VHOST_SET_VRING_ADDR    _IOW(MYCHARDEV_MAGIC, 1, struct vhost_vring_addr)
#define VHOST_SET_VRING_KICK    _IOW(MYCHARDEV_MAGIC, 2, struct vhost_vring_fd)
#define VHOST_SET_OWNER         _IO(MYCHARDEV_MAGIC, 3)
#define VHOST_SET_OUTPUT_FD     _IOW(MYCHARDEV_MAGIC, 4, struct vhost_vring_fd)

struct vhost_state {
    int vhostfd;    // /dev/vhost-console
    int kick_efd;   // Guest -> vhost notify event
};

#endif