; serial_test.asm - sends '4' and newline over serial_test

BITS 16
ORG 0x7C00

mov dx, 0x3F8   ; COM1 serial port

mov al, '4'     ; ASCII '4'
out dx, al      ; send AL to serial

mov al, 10      ; newline
out dx, al      ; send AL to serial

; just halt
hlt

times 510-($-$$) db 0
dw 0xAA55