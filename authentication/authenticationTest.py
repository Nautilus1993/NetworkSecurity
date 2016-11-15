from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from twisted.internet.protocol import Protocol, Factory
from zope.interface.declarations import implements
from twisted.internet.interfaces import ITransport, IStreamServerEndpoint
from random import randint

from playground.network.message.StandardMessageSpecifiers import BOOL1, \
    STRING, UINT2, UINT4, LIST, DEFAULT_VALUE, OPTIONAL
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.common.Protocol import StackingTransport,\
    StackingFactoryMixin, StackingProtocolMixin

from playground.network.common.statemachine import StateMachine
from playground.network.common.statemachine import StateMachineError

from playground.playgroundlog import packetTrace, logging
from playground.error import GetErrorReporter
from pprint import pprint
from playground.network.common.Packet import Packet, PacketStorage, IterateMessages

from authentication import CertFactory

class RipMessage(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "RipTestProtocol.RipTestStack.RipMessage"
    MESSAGE_VERSION = "1.0"
    BODY = [
        ("ACK", BOOL1, DEFAULT_VALUE(False)),
        ("SNN", BOOL1, DEFAULT_VALUE(False)),
        ("Signature", STRING, DEFAULT_VALUE("")),
        ("Certificate", LIST(STRING), OPTIONAL),
        ("Data", STRING, DEFAULT_VALUE(""))
    ]

# client side method
def sendSnn():
    snnMsg = RipMessage()
    snnMsg.SNN = True

    # create certificate chain for client
    # assume current address is 20164.1.1936.123
    nonce1 = randint(0, 10000)
    chain = [nonce1]
    with open("./clientkey/client.csr") as f:
        chain.append(f.read())
    with open("./clientkey/client.cert") as f:
        chain.append(f.read())
    snnMsg.Certificate = chain
    print chain




# server side method
def verifyClient(msg):
    chain = msg.Certificate
    nonce1 = chain[0]
    clientPubKey = chain[1]



    # process of verification

# client side sign method
def signMsg(msg):
    rawKey = CertFactory.getPrivateKeyForAddr("20164.0.0.2")
    rsaKey = RSA.importKey(rawKey)
    clientSigner = PKCS1_v1_5.new(rsaKey)

    dataToSign = msg.__serialize__()
    hasher = SHA256.new()
    hasher.update(dataToSign)

    signatureBytes = clientSigner.sign(hasher)
    msg.Signature = signatureBytes
    return msg

def main():
    pass

if __name__ == "__main__":
    msg = sendSnn()
    verifyClient(msg)










