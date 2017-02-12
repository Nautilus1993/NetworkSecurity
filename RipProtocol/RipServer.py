# Transport --> Protocol --> Factory
from twisted.internet.protocol import Protocol, Factory
from playground.network.common.Protocol import StackingFactoryMixin, StackingProtocolMixin
from playground.network.common.Packet import Packet, PacketStorage, IterateMessages

# Statemachine
from playground.network.common.statemachine import StateMachine
from playground.network.common.statemachine import StateMachineError

# Rip Message Body, Rip transport
from RipProtocol.RipMessage import RipMessage
from RipProtocol.RipTransport import RipTransport, logger, errReporter

# Certificate and Signature
from CertFactory import getCertsForAddr, getPrivateKeyForAddr, getRootCert
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from random import randint
from playground.crypto import X509Certificate

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
        #print "Gate address: " + str(self.transport.getHost())
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
            print "Rip Server Protocol: sendSnnAck -- nonce1 from client = " + str(rcvMsg.Certificate[0])
            nonce1 = rcvMsg.Certificate[0]

            snnackMsg = RipMessage()
            snnackMsg.SNN = True
            snnackMsg.ACK = True
            snnackMsg.Certificate = self.generateCertificate(nonce1)
            snnackMsg.Signature = self.generateSignature(snnackMsg.__serialize__())
            self.transport.write(Packet.MsgToPacketBytes(snnackMsg))
        else:
            print "Rip Server Protocol: sendSnnAck -- undefined signal: " + signal

    # onEnter callback for STATE_SERVER_ESTABLISHED
    def messageHandle(self, signal, msg):

        # server first enter established, must be triggered by signal-received-ack
        if signal == self.SIGNAL_SERVER_RCVD_ACK:
            print "Rip Server Protocol: message handle -- received ack: nonce2 + 1 = " + str(msg.Certificate[0]) + " server nonce = " + str(self.nonce)
            nonce2Plus1 = msg.Certificate[0]
            if (int(nonce2Plus1) != (self.nonce + 1)):
                return False
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

        # verify client's certificate chain
        clientCert = X509Certificate.loadPEM(certificate[1])
        CACert = X509Certificate.loadPEM(certificate[2])
        rootCert = X509Certificate.loadPEM(getRootCert())

        if(CACert.getIssuer() != rootCert.getSubject()):
            return False
        if(clientCert.getIssuer() != CACert.getSubject()):
            return False

        # verify signature with client public key
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

    def generateCertificate(self, nonce1):
        # generate certificate chain for SnnAck message: [nonce2, addrCert, CACert, nonce1 + 1]
        #addr = self.transport.getHost().host
        addr = self.transport.getHost()
        chain = [str(self.nonce)]
        chain += getCertsForAddr(addr)
        chain += [str(int(nonce1) + 1)]
        print "Rip Server Protocol: generateCertificate -- server nonce = "+ chain[0] + " nonce1 + 1 = " + chain[3]
        return chain

    def generateSignature(self, data):
        #addr = self.transport.getHost().host
        addr = self.transport.getHost()
        serverPrivateKeyBytes = getPrivateKeyForAddr(addr)
        serverPrivateKey = RSA.importKey(serverPrivateKeyBytes)
        serverSigner = PKCS1_v1_5.new(serverPrivateKey)
        hasher = SHA256.new()
        hasher.update(data)
        signatureBytes = serverSigner.sign(hasher)
        return signatureBytes