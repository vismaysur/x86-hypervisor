; serial_test.asm - sends '4' and newline over serial_test

BITS 32
ORG 0x1000

VIRTIO_MMIO_BASE equ 0x10000000

start:
    mov dx, 0x03F8              ; COM1 serial port

    call init_virtio_console       ; invoke init_virtio_mmio

    ; just halt
    hlt

init_virtio_console:
    ; verify magic number
    mov eax, dword [ fs : VIRTIO_MMIO_BASE ]
    cmp eax, 0x74726976
    jne error

    ; verify device version number
    mov eax, dword [ fs : VIRTIO_MMIO_BASE + 0x004 ]
    cmp eax, 0x2
    jne error

    ; verify device id for console
    mov eax, dword [ fs : VIRTIO_MMIO_BASE + 0x008 ]
    cmp eax, 0x3
    jne error

    ret

error:
    hlt