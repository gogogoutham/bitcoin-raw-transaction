import unittest
import subprocess
import socket
import messageUtil

names = [
    'main', # Production Net
    'testnet', # Old Test Net
    'testnet3', # Current Test Net
    'namecoin' # Bitcoin-based DNS alternative
]


# Magic 32-bit signifier of which network the message is sent from
magics = {
    'main' : 0xD9B4BEF9,
    'testnet' : 0xDAB5BFFA, 
    'testnet3' : 0x0709110B,
    'namecoin' : 0xFEB4BEF9,
}

# Indicator of ports used for various BTC services provided (these are not RPC ports)
ports = {
    'main' : 8333,
    'testnet' : 18333,
    'testnet3' : 18333,
    'namecoin' : 8334
}


dnsSeeds = [
    "dnsseed.bitcoin.dashjr.org",
    "bitseed.xf2.org"
]


def findPeer(network, version, testHeaderLength):
    """Find the IP address of the first usable peer based on 1) a local store, and 2) nslookup of peer list hosts"""
    peer = findPeerFromCache(network, version, testHeaderLength)
    if not peer:
        peer = findPeerFromDnsSeed(network, version, testHeaderLength)
    return peer

def findPeerFromCache(network, version, testHeaderLength):
    """Finds an active peer from a (file) cached list of peers; NOT IMPLEMENTED"""
    return False

def findPeerFromDnsSeed(network, version, testHeaderLength):
    """Uses an nslookup on DNS names that are known to maintain peer lists"""
    for dnsSeed in dnsSeeds:
        response = subprocess.check_output(["nslookup", dnsSeed])
        lines = response.split("\n")[3:]
        for line in lines:
            if line[0:8] == "Address:":
                ipAddress = line.split(" ")[1].strip()
                ipAddress = "88.198.23.50"
                print "Trying to connect to peer at {0} ...".format(ipAddress)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                try:
                    sock.connect((ipAddress, ports[network]))   
                except Exception:
                    print "Could not connect. Moving on..."
                    continue
                print "Connection established! Sending version message..."
                sock.send(messageUtil.makeVersionStandard('main', version))
                try:
                    response = sock.recv(testHeaderLength)
                except Exception:
                    print "Failed on first contact. Moving on..."
                    continue
                if len(response) == 0:
                    print "Failed on first contact. Moving on..."
                    continue 
                return sock, response
        return False

class NetworkUtilTests(unittest.TestCase):
    
    def test_parse_works(self):
        sock, response = findPeer('main', 70001, 24)
        assert(sock != False)
        if sock != False:
            sock.close()

if __name__ == '__main__':
    unittest.main()