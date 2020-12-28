from pwn import *
import time

#r = process("./netatalk/afpd")
r = process('./netatalk/afpd', env={"LD_PRELOAD":"./netatalk/libatalk.so.18"})
#libc = ELF("./libc.so")
r.interactive()