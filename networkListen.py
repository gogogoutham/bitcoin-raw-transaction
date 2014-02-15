import messageUtil
import networkUtil
import socket
import struct

sock, header = networkUtil.findPeer("main", 70001, 24)
sock.settimeout(30)

want = 0
buf = ''

step = 0
while 1:
    if len(header) == 0: break
    magic, cmd, payload_len, checksum = struct.unpack('L12sL4s', header)
    buf = ''
    while payload_len > 0:
        chunk = sock.recv(payload_len)
        if len(chunk) == 0: break
        buf += chunk
        payload_len -= len(chunk)
        print 'got chunk of', len(chunk)
    messageUtil.parse(header, buf)
    header = sock.recv(24)
    

    #if step == 0:
    #   sock.send(msg_getblocks)
    # step += 1

    # if step == 5:
    #     msg = msgUtils.getAddrMsg()
    #     sock.send(msg)
    #     print 'SENT', msg.encode('hex')