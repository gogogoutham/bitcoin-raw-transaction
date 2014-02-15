import unittest
import struct
import hashlib
import time
import random
import translationUtil
import transactionUtil
import networkUtil


def makeCore(network, command, payload):
    """ Adds the common message structure around a payload """
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]
    return struct.pack('L12sL4s', 
        networkUtil.magics[network], 
        command, 
        len(payload), 
        checksum) + payload

def makeVersion(network, version, services, timestamp, addressReceived, portReceived, addressFrom, portFrom, nonce, userAgent, startHeight, relay):
    """ Makes a version message message given the provided arguments """
    payloadFields = []
    payloadFields.append(struct.pack("lQq26s26s",
        version, 
        services, 
        timestamp,
        translationUtil.formatNetAddress(timestamp, services, addressReceived, portReceived),
        translationUtil.formatNetAddress(timestamp, services, addressFrom, portFrom)))
    payloadFields.append(struct.pack("Q",nonce))
    payloadFields.append(translationUtil.formatVarStr(userAgent))
    payloadFields.append(struct.pack("l?",  
        startHeight,
        relay))
    return makeCore(network, "version", "".join(payloadFields))

def makeVersionStandard(network, version):
    """ Makes a more standardized version packet, filling in many of the details that do not need to be varied across version messages"""
    services = 1
    timestamp = int(time.time())
    addressReceived = "127.0.0.1" # My address
    portReceived = networkUtil.ports[network] # My port
    addressFrom = "127.0.0.1" # Your address
    portFrom = networkUtil.ports[network] # Your port
    nonce = random.getrandbits(64) # Random seed to detect self-sends
    userAgent = '' # Also subversion
    startHeight = 0 # Supposed to be the 
    relay = True # This is the default value; if False there are some more limited relaying conditions (see BIP 0037)
    return makeVersion(network, version, services, timestamp, addressReceived, portReceived, addressFrom, portFrom, nonce, userAgent, startHeight, relay)

def makeInv(network, inventory):
    invHashes = []
    for item in inventory:
        invHashes.append(struct.pack("<L", item[0]) + 
            hashlib.sha256(hashlib.sha256(item[1]).digest()).digest()[::-1])
    return makeCore(network, "inv", translationUtil.formatVarInt(len(invHashes)) + "".join(invHashes))

def wrapTransaction(network, signedTransactionHex):
    return makeCore(network, 'tx', signedTransactionHex.decode("hex"))

def makeTransaction(network, *args):
    """ Makes a transaction message from the interface provided by the transaction util signed transaction maker and the message wrapper"""
    return wrapTransaction(network, transactionUtil.makeSigned(*args))

def makeTransactionSimple(network, *args):
    """ Same as above, but for simple signed transactions """
    return wrapTransaction(network, transactionUtil.makeSimpleSigned(*args))

addrCount = 0 
def parse(header, payload):
    """ Processes a response from a peer."""
    magic, cmd, payload_len, checksum = struct.unpack('L12sL4s', header)
    if len(payload) != payload_len:
        print 'BAD PAYLOAD LENGTH', len(payload), payload_len
        
    cmd = cmd.replace('\0', '') # Remove null termination
    print '--- %s ---' % cmd
    
    if cmd == 'version':
        version, services, timestamp, addr_recv, addr_from, nonce = struct.unpack('<LQQ26s26sQ', payload[:80])
        agent_len, agent = translationUtil.unformatVarStr(payload[80:])

        start_height = struct.unpack('<L', payload[80 + agent_len:84 + agent_len])[0]
        print '%d %x %x %s %s %x %s %x' % (
            version, services, timestamp, translationUtil.unformatNetAddress(addr_recv), translationUtil.unformatNetAddress(addr_from),
            nonce, agent, start_height)
    elif cmd == 'inv':
        offset, count = translationUtil.unformatVarInt(payload)
        result = []
        for i in range(0, count):
            type, hash = struct.unpack('<L32s', payload[offset:offset+36])
            # Note: hash is reversed
            print type, hash[::-1].encode('hex')
            if type == 2:
                sys.exit(0)
            result.append([type, hash])
            offset += 36
        print '---\n'
        return result
    elif cmd == 'addr':
        global addrCount
        offset, count = translationUtil.unformatVarInt(payload)
        for i in range(0, count):
            timestamp, = struct.unpack('<L', payload[offset:offset+4])
            addr = translationUtil.unformatNetAddress(payload[offset+4:offset+30])
            offset += 30
            print addrCount, time.ctime(timestamp), addr
            addrCount += 1
    else:
        print "Dumping odd payload:"
        dump(payload)
    print '---\n'


def dump(s):
    print ':'.join(x.encode('hex') for x in s)


class MessageUtilTests(unittest.TestCase):
    
    def test_parse_works(self):
        header = ('\xf9\xbe\xb4\xd9\x76\x65\x72\x73\x69\x6f\x6e\x00\x00\x00\x00\x00' +
                '\x66\x00\x00\x00\x85\xe6\xaa\x94')
        payload = ('\x71\x11\x01\x00\x01\x00\x00\x00' +
               '\x00\x00\x00\x00\xa2\x31\xa0\x52\x00\x00\x00\x00\x01\x00\x00\x00' +
               '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff' +
               '\x6c\x51\xe0\xee\xd8\x73\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
               '\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x62\x91\x98\x16\x20\x8d' +
               '\xf4\x7d\x37\xbf\xe4\xe7\x1f\xd2\x11\x2f\x53\x61\x74\x6f\x73\x68' +
               '\x69\x3a\x30\x2e\x38\x2e\x32\x2e\x32\x2f\x02\x2b\x04\x00')
        parse(header, payload)

if __name__ == "__main__":
    # print makeVersionStandard('main', 60001).encode("hex")
    unittest.main()