#ifndef VIRTIO_CONTROL_REGS_H
#define VIRTIO_CONTROL_REGS_H

/* Memory mapped control registers */
#define REG_MAGIC               0x000
#define REG_DEVICE_VERSION      0x004
#define REG_DEVICE_ID           0x008
#define REG_DEVICE_FEATURES     0x010
#define REG_DEVICE_FEATURES_SEL 0x014
#define REG_DRIVER_FEATURES     0x020
#define REG_DRIVER_FEATURES_SEL 0x024
#define REG_QUEUE_SEL           0x030
#define REG_QUEUE_NUM_MAX       0x034
#define REG_QUEUE_NUM           0x038
#define REG_QUEUE_READY         0x044
#define REG_QUEUE_NOTIFY        0x050
#define REG_INTERRUPT_STATUS    0x060
#define REG_INTERRUPT_ACK       0x064   
#define REG_STATUS              0X070
#define REG_QUEUE_DESC_LOW      0x080
#define REG_QUEUE_DESC_HIGH     0X084
#define REG_QUEUE_DRIVER_LOW    0X090
#define REG_QUEUE_DRIVER_HIGH   0X094
#define REG_QUEUE_DEVICE_LOW    0X0a0
#define REG_QUEUE_DEVICE_HIGH   0X0a4

#endif