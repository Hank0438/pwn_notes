section    .text
global    _start

_start:

    push _write
    mov rdi,0
    mov rsi,rsp
    sub rsi,8
    mov rdx,300
    mov rax,0
    syscall
    ret

_write:
    push _exit
    mov rsi,rsp
    sub rsi,8
    mov rdx,8
    mov rax,1
    mov rdi,1
    syscall
    ret

_exit:

    mov rax,0x3c
    syscall
