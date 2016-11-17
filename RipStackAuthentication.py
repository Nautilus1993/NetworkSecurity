from twisted.internet.protocol import Protocol, Factory
from zope.interface.declarations import implements
from twisted.internet.interfaces import ITransport, IStreamServerEndpoint

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

from CertFactory import getCertsForAddr, getPrivateKeyForAddr, getRootCert
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from random import randint
from playground.crypto import X509Certificate

logger = logging.getLogger(__name__)
errReporter = GetErrorReporter(__name__)

"""
        Step 1: Define Rip Message Body (handshake version)
"""

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

    '''
    private key: 20164.0.0.1.pem
    public key: 20164.0.0.1.csr
    certificate: 20164.0.0.1.cert
    '''


"""
        Step 2: Define Rip Transport with authentication
"""

class RipTransport(StackingTransport):
    def __init__(self, lowerTransport, protocol):
        StackingTransport.__init__(self, lowerTransport)
        self.protocol = protocol

    def write(self, data):
        print "Rip Transport: write data to lower layer -- " + data
        self.protocol.dataSend(data)


"""
                    Step 3: RipClientProtocol
"""

class RipClientProtocol(StackingProtocolMixin, Protocol):

    STATE_CLIENT_CLOSE = "RIP CLIENT STATE MACHINE: CLOSE"
    STATE_CLIENT_SNN_SENT = "RIP CLIENT STATE MACHINE: SNN SENT"
    STATE_CLIENT_ESTABLISHED = "RIP CLIENT STATE MACHINE: ESTABLISHED"

    SIGNAL_CLIENT_SEND_SNN = "RIP CLIENT STATE MACHINE: send snn"
    SIGNAL_CLIENT_RCVD_SNNACK = "RIP CLIENT STATE MACHINE: rcvd snn/ack"
    SIGNAL_CLIENT_RIPMESSAGE = "RIP CLIENT STATE MACHINE: general data without flags"

    def __init__(self):
        self.packetStorage = PacketStorage()
        self.nonce = randint(0, 10000)
        self.SM = StateMachine("Rip Client Protocol StateMachine")

        self.SM.addState(self.STATE_CLIENT_CLOSE,
                        # transition
                        (self.SIGNAL_CLIENT_SEND_SNN, self.STATE_CLIENT_SNN_SENT),
                        # no callback for CLOSE
                        )

        self.SM.addState(self.STATE_CLIENT_SNN_SENT,
                        # transition
                        (self.SIGNAL_CLIENT_RCVD_SNNACK, self.STATE_CLIENT_ESTABLISHED),
                        # callbacks for SNN_SENT
                        onEnter = self.snnSend)


        self.SM.addState(self.STATE_CLIENT_ESTABLISHED,
                        # transtion
                        (self.SIGNAL_CLIENT_RIPMESSAGE, self.STATE_CLIENT_ESTABLISHED),
                        (self.SIGNAL_CLIENT_RCVD_SNNACK, self.STATE_CLIENT_ESTABLISHED),
                        # callback
                        onEnter = self.messageHandle)


    def connectionMade(self):
        print "Gate address: " + self.transport.getHost()[0]
        print "Rip Client Protocol: connection Made"
        self.SM.start(self.STATE_CLIENT_CLOSE)
        print "Rip Client Protocol: start state machine from state -- " + self.SM.currentState()
        self.SM.signal(self.SIGNAL_CLIENT_SEND_SNN, "")
        print "Rip Client Protocol: after snn send current state -- " + self.SM.currentState()


    def dataSend(self, data):
        if not self.SM.currentState() == self.STATE_CLIENT_ESTABLISHED:
            return
        ripMsg = RipMessage()
        ripMsg.Data = data
        print "Rip Client Protocol: data send -- SNN = " + str(ripMsg.SNN) + " Data = " + ripMsg.Data
        self.transport.write(Packet.MsgToPacketBytes(ripMsg))

    def msgToSignal(self, msg):
        if (msg.SNN == True and msg.ACK == True):
            signal = self.SIGNAL_CLIENT_RCVD_SNNACK
        elif(msg.SNN == False and msg.ACK == False):
            signal = self.SIGNAL_CLIENT_RIPMESSAGE
        return signal

    def dataReceived(self, data):
        self.packetStorage.update(data)
        for rcvMsg in IterateMessages(self.packetStorage, logger, errReporter):
            clientSignal = self.msgToSignal(rcvMsg)
            self.SM.signal(clientSignal, rcvMsg)

    # onEnter callback for STATE_CLIENT_SNN_SENT
    def snnSend(self, signal, msg):
        print "Rip Client Protocol: snnSend received signal -- " + signal
        snnMsg = RipMessage()
        snnMsg.SNN = True
        snnMsg.Certificate = self.generateCertificate()
        snnMsg.Signature = self.generateSignature(snnMsg.__serialize__())
        self.transport.write(Packet.MsgToPacketBytes(snnMsg))

    # not a callback, this function will be called at the first time enter established
    def sendAck(self):
        print "Rip Client Protocol: sendAck, current state -- " + self.SM.currentState()
        ackMessage = RipMessage()
        ackMessage.ACK = True
        self.transport.write(Packet.MsgToPacketBytes(ackMessage))

    # onEnter callback for STATE_CLIENT_ESTABLISHED
    def messageHandle(self, signal, msg):

        # first time client 4enter established, must be triggered by signal_receive_snnack
        if signal == self.SIGNAL_CLIENT_RCVD_SNNACK:
            print "Rip Client Protocol: message handle -- signal : " + signal
            if self.verification(msg) == False:
                print "Rip Client Protocol: verification failed!"
                return
            self.sendAck()
            higherTransport = RipTransport(self.transport, self)
            self.makeHigherConnection(higherTransport)

        elif signal == self.SIGNAL_CLIENT_RIPMESSAGE:
            print "Rip Client Protocol: message handle -- receives rip message: ", msg.Data
            self.higherProtocol() and self.higherProtocol().dataReceived(msg.Data)

        else:
            print "Rip Client Protocol: message handle -- undefined signal: ", signal


    def generateCertificate(self):
        addr = self.transport.getHost()[0]
        chain = [self.nonce]
        chain += getCertsForAddr(addr)
        return chain

    def generateSignature(self, data):
        addr = self.transport.getHost()[0]
        clientPrivateKeyBytes = getPrivateKeyForAddr(addr)
        clientPrivateKey = RSA.importKey(clientPrivateKeyBytes)
        clientSigner = PKCS1_v1_5.new(clientPrivateKey)
        hasher = SHA256.new()
        hasher.update(data)
        signatureBytes = clientSigner.sign(hasher)
        return signatureBytes

    def verification(self, snnackMsg):
        signatureBytes = snnackMsg.Signature
        certificateChain = snnackMsg.Certificate

        serverCert = X509Certificate.loadPEM(certificateChain[1])
        CACert = X509Certificate.loadPEM(certificateChain[2])
        rootCert = X509Certificate.loadPEM(getRootCert())

        if(CACert.getIssuer() != rootCert.getSubject()):
            return False
        if(serverCert.getIssuer() != CACert.getSubject()):
            return False

        serverPublicKeyBlob = serverCert.getPublicKeyBlob()
        serverPublicKey = RSA.importKey(serverPublicKeyBlob)
        rsaVerifier = PKCS1_v1_5.new(serverPublicKey)
        hasher = SHA256.new()
        snnackMsg.Signature = ""
        bytesToBeVerified = snnackMsg.__serialize__()

        hasher.update(bytesToBeVerified)
        result = rsaVerifier.verify(hasher, signatureBytes)
        print "Rip Client verification result: " + str(result)
        return result
"""
                    Step 4: RipServerProtocol
"""

class RipServerProtocol(StackingProtocolMixin, Protocol):

    # States for handshake
    STATE_SERVER_LISTEN = "RIP SERVER STATE MACHINE: LISTEN"
    STATE_SERVER_SNN_RCVD = "RIP SERVER STATE MACHINE: SNN_RCVD"
    STATE_SERVER_ESTABLISHED = "RIP SERVER STATE MACHINE: ESTABLISHED"

    # signal
    SIGNAL_SERVER_RCVD_SNN = "RIP SERVER STATE MACHINE: received snn"
    SIGNAL_SERVER_RCVD_ACK = "RIP SERVER STATE MACHINE: received ack"
    SIGNAL_SERVER_RIPMESSAGE = "RIP SERVER STATE MACHINE: general data without flags"

    def __init__(self):
        self.packetStorage = PacketStorage()
        self.nonce = randint(0, 10000)
        self.SM = StateMachine("Rip Server Protocol StateMachine")

        self.SM.addState(self.STATE_SERVER_LISTEN,
                             # transition
                            (self.SIGNAL_SERVER_RCVD_SNN, self.STATE_SERVER_SNN_RCVD),
                             # no callback for LISTEN
                            )
        self.SM.addState(self.STATE_SERVER_SNN_RCVD,
                             # transition
                            (self.SIGNAL_SERVER_RCVD_ACK, self.STATE_SERVER_ESTABLISHED),
                             # callback
                            onEnter = self.sendSnnAck)

        self.SM.addState(self.STATE_SERVER_ESTABLISHED,
                             # transtion
                             (self.SIGNAL_SERVER_RIPMESSAGE, self.STATE_SERVER_ESTABLISHED),
                             # callback
                             onEnter = self.messageHandle)

    def msgToSignal(self, msg):
        if(msg.SNN == True and msg.ACK == False):
            signal = self.SIGNAL_SERVER_RCVD_SNN
        elif(msg.SNN == False and msg.ACK == True):
            signal = self.SIGNAL_SERVER_RCVD_ACK
        elif(msg.SNN == False and msg.ACK == False):
            signal = self.SIGNAL_SERVER_RIPMESSAGE
        return signal


    def connectionMade(self):
        print "Gate address: " + self.transport.getHost()[0]
        self.SM.start(self.STATE_SERVER_LISTEN)

    def dataSend(self, data):
        if not self.SM.currentState() == self.STATE_SERVER_ESTABLISHED:
            return
        ripMsg = RipMessage()
        ripMsg.Data = data
        print "Rip Server Protocol: data send -- Data = " + ripMsg.Data
        self.transport.write(Packet.MsgToPacketBytes(ripMsg))

    def dataReceived(self, data):
        self.packetStorage.update(data)
        for rcvMsg in IterateMessages(self.packetStorage, logger, errReporter):
            serverSignal = self.msgToSignal(rcvMsg)
            self.SM.signal(serverSignal, rcvMsg)


    # onEnter callback for STATE_SERVER_SNN_RCVD
    def sendSnnAck(self, signal, rcvMsg):
        if signal == self.SIGNAL_SERVER_RCVD_SNN:
            if self.verifySnnMessage(rcvMsg) == False:
                print "Rip Server Protocol: verification failed!"
                return
            print "Rip Server Protocol: sendSnnAck"
            snnackMsg = RipMessage()
            snnackMsg.SNN = True
            snnackMsg.ACK = True
            snnackMsg.Certificate = self.generateCertificate()
            snnackMsg.Signature = self.generateSignature(snnackMsg.__serialize__())
            self.transport.write(Packet.MsgToPacketBytes(snnackMsg))
        else:
            print "Rip Server Protocol: sendSnnAck -- undefined signal: " + signal

    # onEnter callback for STATE_SERVER_ESTABLISHED
    def messageHandle(self, signal, msg):

        # server first enter established, must be triggered by signal-received-ack
        if signal == self.SIGNAL_SERVER_RCVD_ACK:
            print "Rip Server Protocol: message handle -- received ack"
            higherTransport = RipTransport(self.transport, self)
            self.makeHigherConnection(higherTransport)

        elif signal == self.SIGNAL_SERVER_RIPMESSAGE:
            print "Rip Server Protocol: message handle -- receives rip message: data -- " + msg.Data
            self.higherProtocol() and self.higherProtocol().dataReceived(msg.Data)

        else:
            print "Rip Server Protocol: message handle -- undefined signal: ", signal

    def verifySnnMessage(self, snnMsg):
        signatureBytes = snnMsg.Signature
        certificate = snnMsg.Certificate

        clientCert = X509Certificate.loadPEM(certificate[1])
        CACert = X509Certificate.loadPEM(certificate[2])
        rootCert = X509Certificate.loadPEM(getRootCert())

        if(CACert.getIssuer() != rootCert.getSubject()):
            return False
        if(clientCert.getIssuer() != CACert.getSubject()):
            return False

        clientPublicKeyBlob = clientCert.getPublicKeyBlob()
        clientPublicKey = RSA.importKey(clientPublicKeyBlob)
        rsaVerifier = PKCS1_v1_5.new(clientPublicKey)
        hasher = SHA256.new()
        snnMsg.Signature = ""
        bytesToBeVerified = snnMsg.__serialize__()


        hasher.update(bytesToBeVerified)
        result = rsaVerifier.verify(hasher, signatureBytes)
        print "Server verification result: " + str(result)
        return result

    def generateCertificate(self):
        addr = self.transport.getHost()[0]
        chain = [self.nonce]
        chain += getCertsForAddr(addr)
        return chain

    def generateSignature(self, data):
        addr = self.transport.getHost()[0]
        serverPrivateKeyBytes = getPrivateKeyForAddr(addr)
        serverPrivateKey = RSA.importKey(serverPrivateKeyBytes)
        serverSigner = PKCS1_v1_5.new(serverPrivateKey)
        hasher = SHA256.new()
        hasher.update(data)
        signatureBytes = serverSigner.sign(hasher)
        return signatureBytes

"""
    Step 4: RipServerFactory & RipClientFactory
"""

class RipServerFactory(StackingFactoryMixin, Factory):
    protocol = RipServerProtocol

class RipClientFactory(StackingFactoryMixin, Factory):
    protocol = RipClientProtocol

ConnectFactory = RipClientFactory
ListenFactory = RipServerFactory