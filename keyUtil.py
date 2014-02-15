import unittest
import hashlib
import ecdsa
import translationUtil

def privateToWif(keyHex):
    """ Return base-58 check encoding of private key """
    return translationUtil.encodeBase58Check(0x80, keyHex.decode("hex"))

def wifToPrivate(wif):
    """ Return a byte-string version of the private key """
    return translationUtil.decodeBase58Check(wif).encode("hex")

def privateToPublic(keyHex):
    """ Generate verifying (public) key from private key using elliptic curve DSA """
    sk = ecdsa.SigningKey.from_string(keyHex.decode('hex'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return ('\04' + sk.verifying_key.to_string()).encode('hex')

def addressToPublicHash(address):
    """ Converts a Bitcoin address back to it's generating 160-bit RIPEMD160 public key hash"""
    return translationUtil.decodeBase58Check(address).encode("hex")

def publicToPublicHash(keyHex):
    """ Converts a 512-bit ECDSA public key to a RIPEMD160 hash """
    ripemd160 = hashlib.new("ripemd160")
    ripemd160.update(hashlib.sha256(keyHex.decode('hex')).digest())
    return ripemd160.hexdigest()

def publicToAddress(keyHex):
    """ Converts base-58 verifying (public) key to Bitcoin address """
    return translationUtil.encodeBase58Check(0, publicToPublicHash(keyHex).decode("hex"))


def privateToAddress(keyHex):
    """ Generates (public) Bitcoin address from hex format private key """
    return publicToAddress(privateToPublic(keyHex))

class keyUtilTests(unittest.TestCase):

    def test_privateToWif_works(self):
        result = privateToWif("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")
        self.assertEqual("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", result)

    def test_wifToPrivate_works(self):
        result = wifToPrivate("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
        self.assertEqual("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d", result)

    def test_privateToPublic_works(self):
        result = privateToPublic("f19c523315891e6e15ae0608a35eec2e00ebd6d1984cf167f46336dabd9b2de4")
        self.assertEqual("04fe43d0c2c3daab30f9472beb5b767be020b81c7cc940ed7a7e910f0c1d9feef10fe85eb3ce193405c2dd8453b7aeb6c1752361efdbf4f52ea8bf8f304aab37ab", result)

    def test_publicToAddress_works(self):
        result = publicToAddress("04fe43d0c2c3daab30f9472beb5b767be020b81c7cc940ed7a7e910f0c1d9feef10fe85eb3ce193405c2dd8453b7aeb6c1752361efdbf4f52ea8bf8f304aab37ab")
        self.assertEqual("1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa", result)

    def test_publicToPublicHash_works(self):
        result = publicToPublicHash("04fe43d0c2c3daab30f9472beb5b767be020b81c7cc940ed7a7e910f0c1d9feef10fe85eb3ce193405c2dd8453b7aeb6c1752361efdbf4f52ea8bf8f304aab37ab")
        self.assertEqual("c8e90996c7c6080ee06284600c684ed904d14c5c", result)

    def test_privateToAddress_works(self):
        result = privateToAddress("f19c523315891e6e15ae0608a35eec2e00ebd6d1984cf167f46336dabd9b2de4")
        self.assertEqual("1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa", result)

    def test_addressToPublicHash_works(self):
        result = addressToPublicHash("1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa")
        self.assertEqual("c8e90996c7c6080ee06284600c684ed904d14c5c", result)

if __name__ == '__main__':
    unittest.main()