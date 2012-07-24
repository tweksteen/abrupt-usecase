# Python PoC Server Name Indication
# (c) Securus Global 2012
# Patch your Python first!

import sys
import ssl
import socket
import struct

def examine(packet):
  if packet[0] == 1:
    print("Hello Client")
    i = packet[1+3+2+32+1:41]
    if i:
      # jump over the Cipher Suites
      k = struct.unpack(">h", i)[0] + 41
      i = packet[k:k+1]
      if i:
        # jump over the Compression Methods
        k += struct.unpack(">b", i)[0]
        i = packet[k+1:k+3]
        if i:
          # parse the Extensions list
          ext_len = struct.unpack(">h", i)[0] 
          k += 3 
          i = packet[k:k+2] 
          found = False
          k += 2 
          while not found:
            if i == b'\x00\x00':
              print("Name Extension found")
              found = True
              k += 5
              i = packet[k:k+2]
              name_len = struct.unpack(">h",i)[0]
              name = packet[k+2:k+2+name_len]
              print(name)
            else:
              print("Extension:", i)
              i = packet[k:k+2]
              if i:
                k += struct.unpack(">h", i)[0] + 2
                i = packet[k:k+2]
              else:   
                break
  sys.exit(0)
  return

sc = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
sc.set_msg_callback(examine)
print("Creating new socket...")
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', 4433))
s.listen(1)
print("Listening on port 4433")
conn, addr = s.accept()
ss = sc.wrap_socket(conn,server_side=True)


