from twisted.internet.protocol import Protocol, Factory
from zope.interface.declarations import implements
from twisted.internet.interfaces import ITransport, IStreamServerEndpoint

from playground.network.message.StandardMessageSpecifiers import BOOL1, \
    STRING, UINT2, UINT4, LIST, DEFAULT_VALUE
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.common.Protocol import StackingTransport,\
    StackingFactoryMixin, StackingProtocolMixin

from playground.network.common.statemachine import StateMachine
from playground.network.common.statemachine import StateMachineError

from playground.playgroundlog import packetTrace, logging
from playground.error import GetErrorReporter
from pprint import pprint
from playground.network.common.Packet import Packet, PacketStorage, IterateMessages

from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random


logger = logging.getLogger(__name__)
errReporter = GetErrorReporter(__name__)

clientKey = "\x01"*32
# print "client key is ", clientKey.encode('hex')
serverKey = "\x02"*32
clientIV = "\x01"*16
serverIV = "\x02"*16

BLOCK_SIZE = 16

"""
    Step 1: Define Kiss Layer Message (for 1. kiss handshake and 2. encrypt data transmission)
"""
class KissHandshake(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "KissHandShake"
    MESSAGE_VERSION = "1.0"
    BODY = [
        ("Key", STRING, DEFAULT_VALUE("")),
        ("IV", STRING, DEFAULT_VALUE("")),
        ("messageType", STRING, DEFAULT_VALUE("handshake"))
    ]

class KissData(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "KissData"
    MESSAGE_VERSION = "1.0"
    BODY = [
        ("Data", STRING, DEFAULT_VALUE("")),
        ("messageType", STRING, DEFAULT_VALUE("data"))
    ]

"""
    Step 2: Define Kiss Transport
"""

class KissTransport(StackingTransport):
    def __init__(self, lowerTransport, protocol):
        StackingTransport.__init__(self, lowerTransport)
        self.protocol = protocol

    def write(self, data):
        print "Kiss Transport: encrypt data and transfer to lower layer -- " + data
        self.protocol.dataSend(data)


"""
    Step 3: KissClientProtocol
"""

class KissClientProtocol(StackingProtocolMixin, Protocol):

    # states for kiss client handshake
    STATE_CLIENT_LOWERTRANSPORT_ESTABLISHED = "KISS CLIENT STATE MACHINE: CLIENT LOWERTRANSPORT ESTABLISHED"
    STATE_CLIENT_KEY_SENT = "KISS CLIENT STATE MACHINE: CLIENT SEND KEY_C"
    STATE_CLIENT_KISS_ESTABLISHED = "KISS CLIENT STATE MACHINE: CLIENT READY TO DATA TRANSMISSION"

    # signal for kiss client handshake
    SIGNAL_CLIENT_SEND_KEY_C = "KISS CLIENT STATE MACHINE: Client send K_c"
    SIGNAL_CLIENT_RCVD_KEY_S = "KISS CLIENT STATE MACHINE: Client received K_s"

    # signal for data transmission
    SIGNAL_CLIENT_RCVD_KISSDATA = "KISS CLIENT STATE MACHINE: Client received enrypted data (kiss data)"


    def __init__(self):
        self.writeIV = clientIV
        self.readIV = ""
        self.writeKey = clientKey
        self.readKey = ""

        self.IV_asCtr1 = Counter.new(128, initial_value=int(self.writeIV.encode('hex'),16))
        #self.IV_asCtr2 = Counter.new(128, initial_value=int(self.readIV.encode('hex'),16))
        self.aesEncrypter = AES.new(self.writeKey, counter=self.IV_asCtr1, mode=AES.MODE_CTR)
        #self.aesDecrypter = AES.new(self.readKey, counter=self.IV_asCtr2, mode=AES.MODE_CTR)

        self.packetStorage = PacketStorage()
        self.SM = StateMachine("Kiss Client Protocol StateMachine")

        self.SM.addState(self.STATE_CLIENT_LOWERTRANSPORT_ESTABLISHED,
                         # transition
                         (self.SIGNAL_CLIENT_SEND_KEY_C, self.STATE_CLIENT_KEY_SENT),
                         # no callback
                         )
        self.SM.addState(self.STATE_CLIENT_KEY_SENT,
                         # transition
                         (self.SIGNAL_CLIENT_RCVD_KEY_S, self.STATE_CLIENT_KISS_ESTABLISHED),
                         # callback
                         onEnter = self.keySend
                         )
        self.SM.addState(self.STATE_CLIENT_KISS_ESTABLISHED,
                         # transition
                         (self.SIGNAL_CLIENT_RCVD_KISSDATA, self.STATE_CLIENT_KISS_ESTABLISHED),
                         # callback
                         onEnter = self.messageHandle)

    def msgToSignal(self, msg):
        if msg.messageType == "data":
            signal = self.SIGNAL_CLIENT_RCVD_KISSDATA
        elif msg.messageType == "handshake": # for client it must be the Key_s from server
            signal = self.SIGNAL_CLIENT_RCVD_KEY_S
        return signal

    # initial kiss layer connection
    def connectionMade(self):
        self.SM.start(self.STATE_CLIENT_LOWERTRANSPORT_ESTABLISHED)
        print "Kiss Client Protocol: connectionMade -- start from state: " + self.SM.currentState()
        self.SM.signal(self.SIGNAL_CLIENT_SEND_KEY_C, "")


    def dataSend(self, data):
        if not self.SM.currentState() == self.STATE_CLIENT_KISS_ESTABLISHED:
            return
        kissMsg = KissData()
        cipherText = self.aesEncrypter.encrypt(data)
        kissMsg.Data = cipherText
        self.transport.write(Packet.MsgToPacketBytes(kissMsg))


    def dataReceived(self, data):
        self.packetStorage.update(data)
        for rcvMsg in IterateMessages(self.packetStorage, logger, errReporter):
            kissSignal = self.msgToSignal(rcvMsg)
            print "Kiss Client Protocol: dataReceived -- kiss signal == " + kissSignal
            self.SM.signal(kissSignal, rcvMsg)


    # onEnter callback for STATE_CLIENT_KEY_SENT
    def keySend(self, signal, data):
        if signal == self.SIGNAL_CLIENT_SEND_KEY_C:
            print "Kiss Client Protocol: keySend -- send client key"
            msg = KissHandshake()
            msg.Key = self.writeKey # Key_c
            msg.IV = self.writeIV

            print "Kiss Client Protocol: keySend -- send client key: " + msg.Key.encode('hex')
            print "Kiss Client Protocol: keySend -- send client IV: " + msg.IV.encode('hex')

            self.transport.write(Packet.MsgToPacketBytes(msg))
        else:
            print "Kiss Client Protocol: keySend -- undefined signal: " + signal


    # onEnter callback for STATE_CLIENT_KISS_ESTABLISHED
    def messageHandle(self, signal, kissmsg):

        '''
         Client received key and IV from server, it will
         1) setup own read key
         2) makeHigherConnection
         '''
        if signal == self.SIGNAL_CLIENT_RCVD_KEY_S:
            print "Kiss Client Protocol: messageHandle -- received server key: " + kissmsg.Key.encode('hex')
            print "Kiss Client Protocol: messageHandle -- received server IV: " + kissmsg.IV.encode('hex')
            self.readKey = kissmsg.Key
            self.readIV = kissmsg.IV
            higherTransport = KissTransport(self.transport, self)
            self.makeHigherConnection(higherTransport)

        elif signal == self.SIGNAL_CLIENT_RCVD_KISSDATA:
            print "Kiss Client Protocol: messageHandle -- received encrypted data from server"
            print "Kiss Client Protocol: messageHandle -- read IV: " + self.readIV
            self.IV_asCtr2 = Counter.new(128, initial_value=int(self.readIV.encode('hex'),16))
            self.aesDecrypter = AES.new(self.readKey, counter=self.IV_asCtr2, mode=AES.MODE_CTR)
            decrypttext = self.aesDecrypter.decrypt(kissmsg.Data)
            self.higherProtocol() and self.higherProtocol().dataReceived(decrypttext)

        else:
            print "Kiss Client Protocol: messageHandle -- undefined signal: " + signal




"""
    Step 4: KissServerProtocol
"""

class KissServerProtocol(StackingProtocolMixin, Protocol):

    # States for handshake
    STATE_SERVER_LOWERTRANSPORT_ESTABLISHED = "KISS SERVER STATE MACHINE: LOWER TRANSPORT ESTABLISHED"
    STATE_SERVER_KISS_ESTABLISHED = "KISS SERVER STATE MACHINE: SERVER READY TO DATA TRANSMISSION"

    # signal for handshake
    SIGNAL_SERVER_RCVD_KEY_C = "KISS SERVER STATE MACHINE: Server received client key"

    # signal for kiss data transmission
    SIGNAL_SERVER_KISSDATA = "KISS SERVER STATE MACHINE: Server received kiss data"


    def __init__(self):
        self.writeIV = serverIV
        self.readIV = ""
        self.writeKey = serverKey
        self.readKey = ""

        self.IV_asCtr1 = Counter.new(128, initial_value=int(self.writeIV.encode('hex'),16))
        #self.IV_asCtr2 = Counter.new(128, initial_value=int(self.readIV.encode('hex'),16))
        self.aesEncrypter = AES.new(self.writeKey, counter=self.IV_asCtr1, mode=AES.MODE_CTR)
        #self.aesDecrypter = AES.new(self.readKey, counter=self.IV_asCtr2, mode=AES.MODE_CTR)

        self.packetStorage = PacketStorage()
        self.SM = StateMachine("Kiss Server Protocol StateMachine")

        self.SM.addState(self.STATE_SERVER_LOWERTRANSPORT_ESTABLISHED,
                         # transition
                         (self.SIGNAL_SERVER_RCVD_KEY_C, self.STATE_SERVER_KISS_ESTABLISHED)
                         # no callback
                         )
        self.SM.addState(self.STATE_SERVER_KISS_ESTABLISHED,
                         # transition
                         (self.SIGNAL_SERVER_KISSDATA, self.STATE_SERVER_KISS_ESTABLISHED),
                         # callback
                         onEnter = self.messageHandle
                         )


    def msgToSignal(self, msg):
        if msg.messageType == "handshake":
            signal = self.SIGNAL_SERVER_RCVD_KEY_C
        if msg.messageType == "data":
            signal = self.SIGNAL_SERVER_KISSDATA
        print signal
        return signal

    def connectionMade(self):
        self.SM.start(self.STATE_SERVER_LOWERTRANSPORT_ESTABLISHED)
        print "Kiss Client Protocol: connectionMade -- start from state" + self.SM.currentState()

    def dataSend(self, data):
        if not self.SM.currentState() == self.STATE_SERVER_KISS_ESTABLISHED:
            return
        cipherText = self.aesEncrypter.encrypt(data)
        kissMsg = KissData()
        kissMsg.Data = cipherText
        self.transport.write(Packet.MsgToPacketBytes(kissMsg))

    def dataReceived(self, data):
        self.packetStorage.update(data)
        for rcvMsg in IterateMessages(self.packetStorage, logger, errReporter):
            kissSignal = self.msgToSignal(rcvMsg)
            print "Kiss Server Protocol: dataReceived -- kiss signal == " + kissSignal
            self.SM.signal(kissSignal, rcvMsg)

    def messageHandle(self, signal, kissmsg):
        '''
         server received client key and IV: it will
         1) set up own read key, IV
         2) send own key back to client
         3) makeHigherConnection
        '''
        if signal == self.SIGNAL_SERVER_RCVD_KEY_C:
            print "Kiss Server Protocol: messageHandle -- received key from client: " + kissmsg.Key.encode('hex')
            self.readKey = kissmsg.Key
            print "Kiss Server Protocol: messageHandle -- received key from client: " + kissmsg.Key.encode('hex')
            self.readIV = kissmsg.IV
            print "Kiss Server Protocol: messageHandle -- received IV from client: " + kissmsg.IV.encode('hex')
            serverKeyMsg = KissHandshake()
            serverKeyMsg.Key = self.writeKey
            serverKeyMsg.IV = self.writeIV

            print "Kiss Server Protocol: messageHandle -- server encrypt key: " + self.writeKey.encode('hex')
            print "Kiss Server Protocol: messageHandle -- server IV: " + self.writeIV.encode('hex')

            self.transport.write(Packet.MsgToPacketBytes(serverKeyMsg))
            print "Kiss Server Protocol: messageHandle -- server send key to client: " + serverKeyMsg.Key.encode('hex')

            higherTransport = KissTransport(self.transport, self)
            self.makeHigherConnection(higherTransport)

        elif signal == self.SIGNAL_SERVER_KISSDATA:
            print "Kiss Server Protocol: messageHandle -- received encrypt data: "
            self.IV_asCtr2 = Counter.new(128, initial_value=int(self.readIV.encode('hex'),16))
            self.aesDecrypter = AES.new(self.readKey, counter=self.IV_asCtr2, mode=AES.MODE_CTR)
            decryptText = self.aesDecrypter.decrypt(kissmsg.Data)
            print "Kiss Server Protocol: messageHandle -- decrypt data: " + decryptText
            self.higherProtocol() and self.higherProtocol().dataReceived(decryptText)
        else:
            print "Kiss Client Protocol: messageHandle -- undefined signal: " + signal


"""
    Step 4: KissServerFactory & KissClientFactory
"""

class KissServerFactory(StackingFactoryMixin, Factory):
    protocol = KissServerProtocol

class KissClientFactory(StackingFactoryMixin, Factory):
    protocol = KissClientProtocol


ConnectFactory = KissClientFactory
ListenFactory = KissServerFactory