import unittest
import struct
import hashlib
import ecdsa
import keyUtil
import translationUtil


def makeRaw(version, inputs, outputs, blockLockTime):
    """ Creates Raw Bitcoin Transaction """

    def makeInput(data):
        inHash, inIndex, script, sequence = data
        return (inHash.decode('hex')[::-1].encode('hex') + # Reverse transaction hash
            struct.pack('<L', inIndex).encode('hex') + # Index within input transaction
            translationUtil.formatVarInt(len(script)).encode("hex") + # length of scriptSig in bytes
            script.encode("hex") + # scriptSig
            struct.pack('<L', sequence).encode('hex')) # sequence

    def makeOutput(data):
        value, script = data
        return (struct.pack("<Q", value).encode("hex") + # Little-endian version decimal point - stripped value
            translationUtil.formatVarInt(len(script)).encode("hex") + # length of scriptPubKey in bytes
            script.encode("hex")) # scriptPubKey

    formattedInputs = ''.join(map(makeInput, inputs))
    formattedOutputs = ''.join(map(makeOutput, outputs))

    return (struct.pack('<L', version).encode('hex') + # Little-endian formatting of version
        translationUtil.formatVarInt(len(inputs)).encode("hex")  + # Number of inputs in hex (variable # or byte)
        formattedInputs + # Inputs
        translationUtil.formatVarInt(len(outputs)).encode("hex")  + # Number of outputs in hex (variable # of bytes)
        formattedOutputs + # Outputs
        struct.pack('<L', blockLockTime).encode('hex')) # Little-endian formatting of block lock time

def parse(transaction):
    """ Parses Bitcoin Transaction into it's component parts"""
    byteStringLength = 2

    # Version
    version = struct.unpack('<L', transaction[0:4*byteStringLength].decode("hex"))[0]
    offset = 4*byteStringLength
    # print "Version is: " + str(version)

    # Inputs
    varLength, inputCount = translationUtil.unformatVarInt(transaction[offset:offset+9*byteStringLength].decode("hex"))
    # print "Input Count is: " + str(inputCount)
    offset += varLength*byteStringLength
    inputs = []
    for i in range(0, inputCount):
        
        # Hash of input (previous output) transaction
        inHash = (transaction[offset:offset+64].decode("hex"))[::-1].encode("hex")
        offset += 64

        # Index of reference within input (previous output) transaction
        inIndex = struct.unpack('<L', transaction[offset:offset+4*byteStringLength].decode("hex"))[0]
        offset += 4*byteStringLength

        # Script signature length
        varLength, scriptLen = translationUtil.unformatVarInt(transaction[offset:offset+9*byteStringLength].decode("hex"))
        offset += varLength*byteStringLength

        # Script
        script = transaction[offset:offset+scriptLen*byteStringLength].decode("hex")
        offset += scriptLen*byteStringLength

        # Sequence
        sequence = struct.unpack('<L', transaction[offset:offset+4*byteStringLength].decode("hex"))[0]
        offset += 4*byteStringLength

        # Append
        # print "Input {0} is: {1}, {2}, {3}, {4}".format(i, inHash, inIndex, script, sequence)
        inputs.append([inHash, inIndex, script, sequence])

    # Outputs
    varLength, outputCount = translationUtil.unformatVarInt(transaction[offset:offset+9*byteStringLength].decode("hex"))
    # print "Output Count is: {0}".format(outputCount)
    offset += varLength*byteStringLength
    outputs = []
    for i in range(0, outputCount):
        
        # Index of reference within input (previous output) transaction
        value = struct.unpack('<Q', transaction[offset:offset+8*byteStringLength].decode("hex"))[0]
        offset += 8*byteStringLength

        # Script signature length
        varLength, scriptLen = translationUtil.unformatVarInt(transaction[offset:offset+9*byteStringLength].decode("hex"))
        offset += varLength*2

        # Script
        script = transaction[offset:offset+scriptLen*byteStringLength].decode("hex")
        offset += scriptLen*byteStringLength

        # Append
        # print "Output {0} is: {1}, {2}".format(i, value, script)
        outputs.append([value, script])

    # Block Lock Time 
    blockLockTime = struct.unpack('<L', transaction[offset:offset+4*byteStringLength].decode("hex"))[0]
    # print "Block Lock Time is: " + str(blockLockTime)

    return (version, inputs, outputs, blockLockTime)

def unsign(parsedTransaction):
    version, inputs, outputs, blockLockTime = parsedTransaction
    inputsUnsigned = []
    for inHash, inIndex, script, sequence in inputs:
        # Divide the input script into signature and public key
        offset, signatureWithHashType = translationUtil.unformatVarStr(script)
        # print offset, signatureWithHashType
        publicKeyWithPrefix = translationUtil.unformatVarStr(script[offset:])[1]
        
        # Create the unsigned version of the script from the address derived from the public key
        unsignedScript = translationUtil.encodeStandardOutputScript(
                keyUtil.publicToPublicHash(publicKeyWithPrefix.encode("hex")))
        # print "Unsigned script version is {0}".format(unsignedScript.encode("hex"))

        inputsUnsigned.append([inHash, inIndex, unsignedScript, sequence])
    
    return (version, inputsUnsigned, outputs, blockLockTime)
        

def verifySignature(transaction):
    # Extract the raw transaction and corresponding hash to be signed
    parsedTransaction = parse(transaction)
    # print "Parsed Transaction (still signed) is: {0}".format(parsedTransaction)
    transactionRaw = (makeRaw(*unsign(parsedTransaction)) + 
        struct.pack('<L', 1).encode('hex')) # Little-endian formatted hashtype
    hashToSign = hashlib.sha256(hashlib.sha256(transactionRaw.decode('hex')).digest()).digest()

    # Sign the raw transaction with each input signature and verify
    signedInputs = parsedTransaction[1]
    for inHash, inIndex, script, sequence in signedInputs:
        # Divide the input script into signature and public key
        offset, signatureWithHashType = translationUtil.unformatVarStr(script)
        publicKeyWithPrefix = translationUtil.unformatVarStr(script[offset:])[1]

        # Verify hashtype on signature and cleave off
        assert(signatureWithHashType[-1:] == chr(1))
        signature = signatureWithHashType[0:-1] 

        # Verify prefix on public key and cleave off
        assert(publicKeyWithPrefix[0:1] == chr(4))
        publicKey = publicKeyWithPrefix[1:]

        # Verify that provided signature matches signing of raw transaction hash with provided signature
        vk = ecdsa.VerifyingKey.from_string(publicKey, curve=ecdsa.SECP256k1)
        assert(vk.verify_digest(signature, hashToSign, sigdecode=ecdsa.util.sigdecode_der))


def makeSigned(version, inputs, outputs, blockLockTime, privateKeyHex):

    # Constuct the raw transaction
    # print version, inputs, outputs, blockLockTime
    # print "Outputs before signing are: {0}".format(outputs)
    transactionRaw = (makeRaw(version, inputs, outputs, blockLockTime) + 
        struct.pack('<L', 1).encode('hex')) # Little-endian formatted hashtype
    # print transactionRaw
    # Construct the raw hash
    unsignedHash = hashlib.sha256(
            hashlib.sha256(
                transactionRaw.decode("hex")
            ).digest()
        ).digest()

    # Construct the signing key from the passed private key
    sk = ecdsa.SigningKey.from_string(privateKeyHex.decode('hex'), curve=ecdsa.SECP256k1)

    # Derive the public key from the private key (with the prefix)
    publicKeyHex = keyUtil.privateToPublic(privateKeyHex)

    # Sign each input
    signedInputs = []
    for inHash, inIndex, script, sequence in inputs:
        
        # Use the signing key to construct the signature (with the postfix)
        signature =  sk.sign_digest(unsignedHash, sigencode=ecdsa.util.sigencode_der) + chr(1) # 1 is hashtype

        # Construct the overall script signature by combining the signature with the public key
        signedScript = (translationUtil.formatVarStr(signature) + 
            translationUtil.formatVarStr(publicKeyHex.decode('hex')))

        signedInputs.append([inHash, inIndex, signedScript, sequence])

    # Create the full signed transaction using the script signature instead of the raw value
    # print "Outputs before signing are: {0}".format(outputs)
    # print "Signed transaction (before packing) is: {0}".format((version, signedInputs, outputs, blockLockTime))
    signedTransaction = makeRaw(version, signedInputs, outputs, blockLockTime)

    # Verify (using only the public keys provided in the inputs)
    verifySignature(signedTransaction)

    # Return
    return signedTransaction
    

def makeSimple(*args, **kwargs):
    """ Creates Bitcoin Transation with One Input and One Output; value must be specified in Satoshis"""
    
    makeComplex, inHash, inIndex, inScript, outValue, outScript = args[0:6]

    inputs = [[ 
        inHash,
        inIndex,
        inScript,
        0xffffffff
    ]]

    outputs = [[
        outValue,
        outScript
    ]]

    newArgs = (1, inputs, outputs, 0) + args[6:] 

    return makeComplex(*newArgs)


def makeSimpleRaw(*args, **kwargs):
    return makeSimple(makeRaw, *args, **kwargs)

def makeSimpleSigned(*args, **kwargs):
    return makeSimple(makeSigned, *args, **kwargs)


class transactionUtilTests(unittest.TestCase):
    
    def test_makeSimpleRaw_works(self):
        
        result = makeSimpleRaw(
           "f2b3eb2deb76566e7324307cd47c35eeb88413f971d88519859b1834307ecfec", # Hash of input transaction
            1, # Index within source transaction
            "76a914010966776006953d5567439e5e39f86a0d273bee88ac".decode("hex"), # scriptSig
            99900000, # Satoshis
            "76a914097072524438d003d23a2f23edb65aae1bb3e46988ac".decode("hex") # scriptPubKey
            ) + "01000000" # hash code type
        self.assertEqual(result,
            "0100000001eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2" +
            "010000001976a914010966776006953d5567439e5e39f86a0d273bee88acffffffff" +
            "01605af405000000001976a914097072524438d003d23a2f23edb65aae1bb3e46988ac" +
            "0000000001000000")

    def test_makeRaw_works(self):

        inputs = [
            [
                "f2b3eb2deb76566e7324307cd47c35eeb88413f971d88519859b1834307ecfec", # Hash of input transaction
                1, # Index within source transaction
                "76a914010966776006953d5567439e5e39f86a0d273bee88ac".decode("hex"), # scriptSig
                0xffffffff # Sequence
            ]
        ]

        outputs = [
            [
                99900000, # Satoshis
                "76a914097072524438d003d23a2f23edb65aae1bb3e46988ac".decode("hex") # scriptPubKey
            ]
        ]
        
        result = makeRaw(1, inputs, outputs, 0) + "01000000" # hash code type
        self.assertEqual(result,
            "0100000001eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2" +
            "010000001976a914010966776006953d5567439e5e39f86a0d273bee88acffffffff" +
            "01605af405000000001976a914097072524438d003d23a2f23edb65aae1bb3e46988ac" +
            "0000000001000000")

    def test_parse_works(self):
        
        result = parse("0100000001eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2" +
            "010000001976a914010966776006953d5567439e5e39f86a0d273bee88acffffffff" +
            "01605af405000000001976a914097072524438d003d23a2f23edb65aae1bb3e46988ac" +
            "0000000001000000")

        inputs = [
            [
                "f2b3eb2deb76566e7324307cd47c35eeb88413f971d88519859b1834307ecfec", # Hash of input transaction
                1, # Index within source transaction
                "76a914010966776006953d5567439e5e39f86a0d273bee88ac".decode("hex"), # scriptSig
                0xffffffff # Sequence
            ]
        ]

        outputs = [
            [
                99900000, # Satoshis
                "76a914097072524438d003d23a2f23edb65aae1bb3e46988ac".decode("hex") # scriptPubKey
            ]
        ]

        self.assertEqual(result, (1, inputs, outputs, 0))

    def test_makeSigned_works(self):
        # Transaction from
        # https://blockchain.info/tx/901a53e7a3ca96ed0b733c0233aad15f11b0c9e436294aa30c367bf06c3b7be8
        # From 133t to 1KKKK
        privateKey = keyUtil.wifToPrivate("5Kb6aGpijtrb8X28GzmWtbcGZCG8jHQWFJcWugqo3MwKRvC8zyu") #133t

        inputs = [
            [
                "c39e394d41e6be2ea58c2d3a78b8c644db34aeff865215c633fe6937933078a9", # Hash of input transaction
                0, # Index within source transaction
                translationUtil.encodeStandardOutputScript(
                    keyUtil.addressToPublicHash("133txdxQmwECTmXqAr9RWNHnzQ175jGb7e")), # scriptSig
                0xffffffff # Sequence
            ]
        ]

        outputs = [
            [
                24321, # Satoshis
                translationUtil.encodeStandardOutputScript(
                    keyUtil.addressToPublicHash("1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa")) # scriptPubKey
            ],
                        [
                20000, # Satoshis
                translationUtil.encodeStandardOutputScript(
                    keyUtil.addressToPublicHash("15nhZbXnLMknZACbb3Jrf1wPCD9DWAcqd7")) # scriptPubKey
            ]
        ]


        signedTransaction = makeSigned(1, inputs, outputs, 0, privateKey)

        verifySignature(signedTransaction)


if __name__ == '__main__':
    unittest.main()