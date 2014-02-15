import unittest
import hashlib
import struct

alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
baseCount = len(alphabet)

def formatVarInt(n):
    """ Encodes an variable-length integer in Bitcoin's custom integer format for transactions"""
    if n < 0xfd:
        return struct.pack('<B', n)
    elif n < 0xffff:
        return struct.pack('<cH', '\xfd', n)
    elif n < 0xffffffff:
        return struct.pack('<cL', '\xfe', n)
    else:
        return struct.pack('<cQ', '\xff', n)

def unformatVarInt(s):
    if s[0] == "\xff":
        return 9, struct.unpack('<Q', s[1:9])[0]
    elif s[0] == "\xfe":
        return 5, struct.unpack('<L', s[1:5])[0]
    elif s[0] == "\xfd":
        return 3, struct.unpack('<H', s[1:3])[0]
    else:
        return 1, struct.unpack('<B', s[0])[0]

def formatVarStr(s):
    return formatVarInt(len(s)) + s

def unformatVarStr(s):
    lenLenByte, strLen = unformatVarInt(s)
    return lenLenByte + strLen, s[lenLenByte:lenLenByte+strLen]

def formatNetAddress(time, services, ipAddress, port):
    """ Formatting of IP Address / Port combination for Transaction Messages; Does not support IPV6"""
    ipAddressByteString = "".join([ chr(int(octet)) for octet in ipAddress.split(".") ])
    return (struct.pack("<LQ", time, services) +
        struct.pack("!10sH4sH", "", 0xffff, ipAddressByteString, port))

def unformatNetAddress(s):
    """Parsing of IP Address / Port; Not completely symetric with the format step"""
    assert(len(s) >= 26)
    return '%d.%d.%d.%d:%d' % (ord(s[20]), ord(s[21]),
                               ord(s[22]), ord(s[23]),
                               struct.unpack('!H', s[24:26])[0])


def encodeBase58Check(versionByte, payload):
    """ Encodes payload as Bitcoin-style checked base 58 string. Payload is specified as a byte string."""

    rawOutputUnsigned = chr(versionByte).encode("hex") + payload.encode("hex")
    # print "Version appended payload is : " + rawOutputUnsigned
    rawOutputSigned = rawOutputUnsigned + (hashlib.sha256(
            hashlib.sha256(
                rawOutputUnsigned.decode("hex")
            ).digest()
        ).hexdigest())[0:8]
    # print "Signed, version-appended payload is: " + rawOutputSigned
    rawOutputNum = int(rawOutputSigned, 16)
    # print rawOutputNum

    # Find the encoding of everything that isn't a leading 0
    output = []
    quotient = rawOutputNum
    while quotient > 0:
        quotient, remainder = divmod(quotient, 58)
        output.append(alphabet[remainder])
    output.reverse()
    output = "".join(output)

    # Now find the size of the pad
    padSize = 0
    for character in rawOutputSigned.decode("hex"):
        if character == b"\x00":
            padSize +=1
        else:
            break
    output = alphabet[0]*padSize + output
    
    return output

def decodeBase58Check(payload):
    # Find the size of the pad
    padSize = 0
    for character in payload:
        if character == alphabet[0]:
            padSize +=1
        else:
            break

    # Convert remaining string to base 10
    b58quotient = payload[padSize:]
    quotient = 0
    for i in range(0, len(b58quotient)):
        quotient = quotient * 58 + alphabet.index(b58quotient[i])

    # Convert to base 256 byte string and append back leading zeros
    output = []
    while quotient > 0:
        quotient, remainder = divmod(quotient, 256)
        output.append(chr(remainder))
    output.reverse()
    output = "\0"*padSize + "".join(output)

    # Remove version byte and signature and return
    return  output[1:-4]

def encodeScriptOp(operation):
    """Byte encodes an operation for use in transaction script; implementation is currently limited"""
    if operation == "OP_DUP":
        return b"\x76"
    elif operation == "OP_HASH160":
        return b"\xa9"
    elif operation == "OP_EQUALVERIFY":
        return b"\x88"
    elif operation == "OP_CHECKSIG":
        return b"\xac"
    elif operation == "SIGNHASH_ALL":
        return b"\x01"
    elif operation[0:8] == "PUSHDATA" and int(operation[8:]) <= 75:
        return chr(int(operation[8:]))
    else:
        raise Error("I don't know how to translate script operation {0}".format(operation))
        return False

def encodeScript(operations):
    """Encodes of list of Bitcoin script operations (in words) to a hex-encoded script for transaction conveyance"""
    scriptParts = []
    for op in operations:
        if op[0:8] != "PUSHDATA":
            scriptParts.append(encodeScriptOp(op))
        else:
            opParts = op.split(" ")
            pushDataOpCode = encodeScriptOp("{0} {1}".format(opParts[0], opParts[1]))
            scriptParts.append("{0}{1}".format(pushDataOpCode, opParts[2]))
    return "".join(scriptParts)

def encodeStandardOutputScript(publicKeyHash):
    return encodeScript([
            "OP_DUP",
            "OP_HASH160",
            "PUSHDATA 20 {0}".format(publicKeyHash.decode("hex")),
            "OP_EQUALVERIFY",
            "OP_CHECKSIG"
        ])

def decodeScriptOp(opCode):
    """Decodes a script operation from a byte code back to words"""
    if opCode == b"\x76":
        return "OP_DUP"
    elif opCode == b"\xa9":
        return "OP_HASH160"
    elif opCode == b"\x88":
        return "OP_EQUALVERIFY"
    elif opCode == b"\xac":
        return "OP_CHECKSIG"
    elif opCode == b"\x01":
        return "SIGNHASH_ALL"
    elif ord(opCode) <= 75:
        return "PUSHDATA {0}".format(ord(opCode))
    else:
        raise Error("I don't know how to translate script operation code '{0}' into words".format(opCode))
        return False

def decodeScript(script):
    """Decodes as hex-encoded Bitcoin script back into a list of operations (in words)"""
    ops = []
    i = 0
    while i < len(script):
        opRaw = decodeScriptOp(script[i])
        if opRaw[0:8] != "PUSHDATA":
            ops.append(opRaw)
            i += 1
        else:
            dataLength = int(opRaw.split(" ")[1])
            data = script[(i+1):(i+1+dataLength)]
            ops.append("PUSHDATA {0} {1}".format(dataLength, data))
            i += (1+dataLength)
    return ops

class translationUtilTests(unittest.TestCase):

    def test_formatVarInt_works(self):
        self.assertEqual(formatVarInt(0x42), '\x42')
        self.assertEqual(formatVarInt(0x123), '\xfd\x23\x01')
        self.assertEqual(formatVarInt(0x12345678), '\xfe\x78\x56\x34\x12')
        self.assertEqual(unformatVarInt(formatVarInt(0x42)), (1,0x42))
        self.assertEqual(unformatVarInt(formatVarInt(0x1234)), (3, 0x1234))

    def test_encodeVarStr_works(self):
        self.assertEqual(formatVarStr('abc'), '\x03abc')
        self.assertEqual(unformatVarStr('\x03abc'), (4, 'abc'))
    
    def test_encodeNetAddress(self):
        self.assertEqual(formatNetAddress(1392400607, 60032, "127.0.0.1", 8333).encode("hex"),
            "df58fe52" + "80ea000000000000" + "00000000000000000000ffff" + "7f000001" + "208d")

    def test_alphabet_length(self):
        self.assertEqual(58, len(alphabet))

    def test_encode_normal_works(self):
        result = encodeBase58Check(0x80, "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d".decode("hex"))
        self.assertEqual("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", result)

    def test_encode_leading_zero_works(self):
        result = encodeBase58Check(0, "1")
        self.assertEqual("16Xzqssd", result)

    def test_decode_works(self):
        self.assertEqual(decodeBase58Check(encodeBase58Check(42, 'abcd')), 'abcd')
        self.assertEqual(decodeBase58Check(encodeBase58Check(0, '\0\0abcd')), '\0\0abcd')

    def test_translateScript_works(self):
        # Standard scriptPubKey content with Bitcoin-style address passed in
        operations = [
            "OP_DUP",
            "OP_HASH160",
            "PUSHDATA 20 {0}".format("c8e90996c7c6080ee06284600c684ed904d14c5c".decode("hex")),
            "OP_EQUALVERIFY",
            "OP_CHECKSIG"
        ]
        script = "{0}{1}{2}".format("76a914","c8e90996c7c6080ee06284600c684ed904d14c5c","88ac").decode("hex")
        self.assertEqual(encodeScript(operations), script)
        self.assertEqual(operations, decodeScript(script))
        self.assertEqual(encodeStandardOutputScript("c8e90996c7c6080ee06284600c684ed904d14c5c"), script)

if __name__ == '__main__':
    unittest.main()