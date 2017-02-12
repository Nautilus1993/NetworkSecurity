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

"""
Rip Client State Machine:
 +-------+                     +-----------+
 | CLOSE | ---- send SNN ----> | SNN  SENT |
 +-------+                     +-----------+
                                     |
                                 received
                                  SNN/ACK
            +-----------+            |
      +---- | ESTABLISH | <----------+
      |     +-----------+
      |
   received
     CLS
      |
      |       +-------+
      +-----> | CLOSE |
              +-------+



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
    def sendAck(self, nonce2):
        print "Rip Client Protocol: sendAck, current state -- " + self.SM.currentState()
        ackMessage = RipMessage()
        ackMessage.ACK = True
        # ack message certificate chain only have 1 item : [nonce2 + 1]
        ackMessage.Certificate = [int(nonce2) + 1]
        self.transport.write(Packet.MsgToPacketBytes(ackMessage))

    # onEnter callback for STATE_CLIENT_ESTABLISHED
    def messageHandle(self, signal, msg):

        # first time client enter established, must be triggered by signal_receive_snnack
        if signal == self.SIGNAL_CLIENT_RCVD_SNNACK:
            print "Rip Client Protocol: message handle -- signal : " + signal
            # certificate chain from server [nonce2, addrCert, CACert, nonce1 + 1]
            if self.verification(msg) == False:
                print "Rip Client Protocol: verification failed!"
                return
            nonce2 = msg.Certificate[0]
            nonce1Plus1 = msg.Certificate[3]
            print "Rip Client Protocol: message handle -- rcvd snnack: (nonce1 + 1) from server = " + str(nonce1Plus1) + "nonce2 from server = " + str(nonce2)
            self.sendAck(nonce2)
            higherTransport = RipTransport(self.transport, self)
            self.makeHigherConnection(higherTransport)

        elif signal == self.SIGNAL_CLIENT_RIPMESSAGE:
            print "Rip Client Protocol: message handle -- receives rip message: ", msg.Data
            self.higherProtocol() and self.higherProtocol().dataReceived(msg.Data)

        else:
            print "Rip Client Protocol: message handle -- undefined signal: ", signal


    def generateCertificate(self):
        #addr = self.transport.getHost().host
        addr = self.transport.getHost()
        chain = [self.nonce]
        chain += getCertsForAddr(addr)
        return chain

    def generateSignature(self, data):
        #addr = self.transport.getHost().host
        addr = self.transport.getHost()
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

        # verify nonce1 + 1
        nonce1Plus1 = certificateChain[3]
        if(int(nonce1Plus1) != int(self.nonce + 1)):
            return False

        # verify server's certificate chain
        serverCert = X509Certificate.loadPEM(certificateChain[1])
        CACert = X509Certificate.loadPEM(certificateChain[2])
        rootCert = X509Certificate.loadPEM(getRootCert())
        if(CACert.getIssuer() != rootCert.getSubject()):
            return False
        if(serverCert.getIssuer() != CACert.getSubject()):
            return False

        # verify signature with server's public key
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