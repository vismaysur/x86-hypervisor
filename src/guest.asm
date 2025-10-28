; serial_test.asm - sends '4' and newline over serial_test

BITS 32
ORG 0x1000

VIRTIO_MMIO_BASE equ 0x10000000

start:
    ; invoke init_virtio_mmio
    call init_virtio_console 

    ; just halt
    hlt

init_virtio_console:
    ; verify magic number
    mov eax, dword [ VIRTIO_MMIO_BASE ]
    cmp eax, 0x74726976
    jne magic_error

    ; verify device version number
    mov eax, dword [ VIRTIO_MMIO_BASE + 0x004 ]
    cmp eax, 0x2
    jne device_version_error

    ; verify device id for console
    mov eax, dword [ VIRTIO_MMIO_BASE + 0x008 ]
    cmp eax, 0x3
    jne device_id_error

    ; track device status
    mov al, 0x0

    ; reset device by writing to REG_STATUS
    mov byte [ VIRTIO_MMIO_BASE + 0x070 ], al

    ; set ACKNOWLEDGE status bit (notice this device)
    or al, 0x01
    mov byte [ VIRTIO_MMIO_BASE + 0x070 ], al 

    ; set DRIVER status bit (indicate driver knows how to drive device)
    or al, 0x02
    mov byte [ VIRTIO_MMIO_BASE + 0x070 ], al

    ; read and accept all device feature bits
    mov byte [ VIRTIO_MMIO_BASE + 0x014 ], 0
    mov ebx, dword [ VIRTIO_MMIO_BASE + 0x010 ]
    mov byte [ VIRTIO_MMIO_BASE + 0x024 ], 0
    mov dword [ VIRTIO_MMIO_BASE + 0x020 ], ebx

    mov byte [ VIRTIO_MMIO_BASE + 0x014 ], 1
    mov ebx, dword [ VIRTIO_MMIO_BASE + 0x010 ]
    mov byte [ VIRTIO_MMIO_BASE + 0x024 ], 1
    mov dword [ VIRTIO_MMIO_BASE + 0x020 ], ebx

    ; set and re-check FEATURES_OK to verify feature negotation
    or al, 0x08
    mov byte [ VIRTIO_MMIO_BASE + 0x070 ], al
    mov bl, byte [ VIRTIO_MMIO_BASE + 0x070 ]
    and bl, 0x08
    jz feature_negotiation_error

    ; indicate device initialization completion
    or al, 0x04
    mov byte [ VIRTIO_MMIO_BASE + 0x070 ], al

    ret

magic_error:
    mov si, msg_magic_error
    call print_string
    hlt

device_version_error:
    mov si, msg_device_version_error
    call print_string
    hlt

device_id_error:
    mov si, msg_device_id_error
    call print_string
    hlt

feature_negotiation_error:
    mov si, msg_feature_negotiation_error
    call print_string
    hlt

print_string:
    mov dx, 0x3F8 ; COM1 port
.loop:
    lodsb
    test al, al
    jz .done
    out dx, al
    jmp .loop
.done:
    ret

msg_magic_error: db "Driver error: invalid magic number", 0x0A, 0
msg_device_version_error: db "Driver error: invalid device version", 0x0A, 0
msg_device_id_error: db "Driver error: invalid device id", 0x0A, 0
msg_feature_negotiation_error: db "Driver error: feature negotiation failed", 0x0A, 0