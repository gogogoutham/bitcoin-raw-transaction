import ConfigParser
import socket
import hashlib
import keyUtil
import translationUtil
import transactionUtil
import networkUtil
import messageUtil

# Identity Details
walletName = 'test-wallet-a'

# Network Details
protocolVersion = 70001
network = 'main'
peerHost = "115.29.241.200"

# Transaction Details
fromAddress = '1CsjxDAftnJuG3NwD1RkzQmCirGCytPd4a'
toAddress = '16oTEBsbyVt7DAS8kWUBJSwCymegroYby6' 
transferAmount = 150000 # 150000 Satsoshis will be transfered today!
sourceTransaction = "1d06c3b07c828f871832049c373cdd0d8113050768661ce0612a8ac0bcbe1d2a"
sourceIndex = 0


# Pull in the private key
config = ConfigParser.ConfigParser()
config.read("private-keys.config")
privateKeyHex = config.get(walletName, "key")

# Check that it matches the from address
assert(fromAddress == keyUtil.privateToAddress(privateKeyHex))

# Assemble the transaction and sign it
scriptSig = translationUtil.encodeStandardOutputScript(keyUtil.addressToPublicHash(fromAddress))
scriptPubKey = translationUtil.encodeStandardOutputScript(keyUtil.addressToPublicHash(toAddress))
tx = transactionUtil.makeSimpleSigned(
        sourceTransaction, # Hash of input transaction
        sourceIndex, # Index within source transaction
        scriptSig, # scriptSig
        transferAmount, # Satoshis
        scriptPubKey, # scriptPubKey
        privateKeyHex
    )

print "Transaction is - {0}".format(tx)
print "Transaction hash is - {0}".format(hashlib.sha256(hashlib.sha256(tx.decode("hex")).digest()).hexdigest())

# Connect to a BTC peer
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(30)
sock.connect((peerHost, networkUtil.ports[network]))   

# Send version message
sock.send(messageUtil.makeVersionStandard('main', protocolVersion))

# Process peer response
sock.recv(1000) # Receive version (and discard)
sock.recv(1000) # Receive verack (and discard)

# Send an inventory message containing the transaction hash
sock.send(messageUtil.makeInv('main', [(1,tx.decode("hex"))]))

# Receive the getdata message asking for the transaction details (and discard)
sock.recv(1000)

# Send the transaction
txMsg = messageUtil.wrapTransaction('main', tx)
sock.send(txMsg) # let's see it spread!!

# Go away
sock.close()
