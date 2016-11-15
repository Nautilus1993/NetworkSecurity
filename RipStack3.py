from twisted.internet.protocol import Protocol, Factory, connectionDone
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

from authentication.CertFactory import *

logger = logging.getLogger(__name__)
errReporter = GetErrorReporter(__name__)



"""
    Step 1: Define Rip Message Body (ACK, SNN, AckNum and SnnNum)
"""

class RipMessage(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "RipTestProtocol.RipTestStack.RipMessage"
    MESSAGE_VERSION = "1.0"
    BODY = [
        ("Signature", STRING, DEFAULT_VALUE("")),
        ("Certificate", LIST(STRING)), # default value?
        ("ACK", BOOL1, DEFAULT_VALUE(False)),
        ("SNN", BOOL1, DEFAULT_VALUE(False)),
        ("CLS", BOOL1, DEFAULT_VALUE(False)),
        ("Data", STRING, DEFAULT_VALUE(""))
    ]


"""
    Step 2: Define Rip Transport
"""

class RipTransport(StackingTransport):
    def __init__(self, lowerTransport, protocol):
        StackingTransport.__init__(self, lowerTransport)
        self.protocol = protocol

    def write(self, data):
        print "Rip Transport: write data to lower layer -- " + data
        self.protocol.dataSend(data)

    def loseConnection(self):
        self.protocol.connectionLost()


"""
    Step 3: RipClientProtocol
"""

class RipClientProtocol(StackingProtocolMixin, Protocol):

    # states for client handshake
    STATE_CLIENT_CLOSE = "RIP CLIENT STATE MACHINE: CLOSE"
    STATE_CLIENT_SNN_SENT = "RIP CLIENT STATE MACHINE: SNN SENT"
    STATE_CLIENT_ESTABLISHED = "RIP CLIENT STATE MACHINE: ESTABLISHED"

    # states for client close connection
    STATE_CLIENT_CLS_REQ = "RIP CLIENT STATE MACHINE: SEND CLOSE REQUEST"
    STATE_CLIENT_CLS_RCVD = "RIP CLIENT STATE MACHINE: RECEIVED CLOSE REQUEST"

    # signals for client handshake
    SIGNAL_CLIENT_SEND_SNN = "RIP CLIENT STATE MACHINE: send snn"
    SIGNAL_CLIENT_RCVD_SNNACK = "RIP CLIENT STATE MACHINE: rcvd snn/ack"
    SIGNAL_CLIENT_RIPMESSAGE = "RIP CLIENT STATE MACHINE: general data without flags"

    # signals for client close connection
    SIGNAL_CLIENT_SEND_CLS = "RIP CLIENT STATE MACHINE: send close request"
    SIGNAL_CLIENT_RCVD_CLSACK = "RIP CLIENT STATE MACHINE: received close acknowledgement"
    SIGNAL_CLIENT_RCVD_CLS = "RIP CLIENT STATE MACHINE: received close request"
    SIGNAL_CLIENT_SEND_CLSACK = "RIP CLIENT STATE MACHINE: send close acknowledgement"

    # signal for client timeout
    SIGNAL_CLIENT_TIMEOUT = "RIP CLIENT STATE MACHINE: client timeout"

    def __init__(self):
        self.packetStorage = PacketStorage()
        self.SM = StateMachine("Rip Client Protocol StateMachine")

        self.SM.addState(self.STATE_CLIENT_CLOSE,
                        # transition
                        (self.SIGNAL_CLIENT_SEND_SNN, self.STATE_CLIENT_SNN_SENT),
                        # no callback for CLOSE
                        )

        self.SM.addState(self.STATE_CLIENT_SNN_SENT,
                        # transition
                        (self.SIGNAL_CLIENT_RCVD_SNNACK, self.STATE_CLIENT_ESTABLISHED),
                        (self.SIGNAL_CLIENT_TIMEOUT, self.STATE_CLIENT_SNN_SENT), # if timeout client resend snn
                        # callbacks for SNN_SENT
                        onEnter = self.snnSend)

        self.SM.addState(self.STATE_CLIENT_ESTABLISHED,
                        # transition
                        (self.SIGNAL_CLIENT_RIPMESSAGE, self.STATE_CLIENT_ESTABLISHED),
                        (self.SIGNAL_CLIENT_RCVD_SNNACK, self.STATE_CLIENT_ESTABLISHED),
                        (self.SIGNAL_CLIENT_SEND_CLS, self.STATE_CLIENT_CLS_REQ),
                        (self.SIGNAL_CLIENT_RCVD_CLS, self.STATE_CLIENT_CLS_RCVD),
                        (self.SIGNAL_CLIENT_TIMEOUT, self.STATE_CLIENT_ESTABLISHED), # if timeout client resend last message
                        # callback
                        onEnter = self.messageHandle)

        self.SM.addState(self.STATE_CLIENT_CLS_REQ,
                         #transition
                         (self.SIGNAL_CLIENT_RCVD_CLSACK, self.STATE_CLIENT_CLOSE),
                         (self.SIGNAL_CLIENT_TIMEOUT, self.STATE_CLIENT_CLS_REQ), # if timeout client resend close request
                         # callback
                         onEnter = self.sendCls)

        self.SM.addState(self.STATE_CLIENT_CLS_RCVD,
                         # transition
                         (self.SIGNAL_CLIENT_RCVD_CLS, self.STATE_CLIENT_CLS_RCVD),
                         (self.SIGNAL_CLIENT_TIMEOUT, self.STATE_CLIENT_CLS_RCVD),
                         # callback
                         onEnter = self.sendClsAck)


    def connectionMade(self):
        print "Rip Client Protocol: connection Made"
        self.SM.start(self.STATE_CLIENT_CLOSE)
        print "Rip Client Protocol: start state machine from state -- " + self.SM.currentState()
        self.SM.signal(self.SIGNAL_CLIENT_SEND_SNN, "")
        print "Rip Client Protocol: after snn send current state -- " + self.SM.currentState()

    def connectionLost(self, reason=connectionDone):
        print "Rip Client Protocol: connection lost"
        self.SM.signal(self.SIGNAL_CLIENT_SEND_CLS, "")

    def dataSend(self, data):
        if not self.SM.currentState() == self.STATE_CLIENT_ESTABLISHED:
            return
        ripMsg = RipMessage()
        ripMsg.Data = data
        print "Rip Client Protocol: data send -- SNN = " + str(ripMsg.SNN) + " Data = " + ripMsg.Data
        self.transport.write(Packet.MsgToPacketBytes(ripMsg))

    def msgToSignal(self, msg):
        if (msg.SNN == True and msg.ACK == True and msg.CLS == False):
            signal = self.SIGNAL_CLIENT_RCVD_SNNACK
        elif(msg.SNN == False and msg.ACK == False and msg.CLS == False):
            signal = self.SIGNAL_CLIENT_RIPMESSAGE
        elif(msg.SNN == False and msg.ACK == False and msg.CLS == True):
            signal = self.SIGNAL_CLIENT_RCVD_CLS
        elif(msg.SNN == False and msg.ACK == True and msg.CLS == True):
            signal = self.SIGNAL_CLIENT_RCVD_CLSACK
        return signal

    def dataReceived(self, data):
        self.packetStorage.update(data)
        for rcvMsg in IterateMessages(self.packetStorage, logger, errReporter):
            clientSignal = self.msgToSignal(rcvMsg)
            print "Rip Client Protocol: dataReceived -- clientSignal: " + clientSignal
            self.SM.signal(clientSignal, rcvMsg)

    # onEnter callback for STATE_CLIENT_SNN_SENT
    def snnSend(self, signal, msg):
        print "Rip Client Protocol: snnSend received signal -- " + signal
        snnMessage = RipMessage()
        snnMessage.SNN = True

        snnMessage.Certificate = self.generateCertificate()
        sig = self.generateSignature(snnMessage)
        snnMessage.Signature = sig

        # Todo: Here need to add client signature and certificate list.
        # Todo: client signature: hashed message(minus signature field), then enrypted with private key
        # Todo: client certificates:[Nonce1, Yuhang.csr, Yuhang_signed.cert, 20164_root.cert]
        # packet all those things into client

        self.transport.write(Packet.MsgToPacketBytes(snnMessage))

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

            # Todo: Here client received server's signature and certificate, need to verify server
            # Todo: after verify server, client need to send back what? (nonce2 + 1 ...)

            self.sendAck()
            higherTransport = RipTransport(self.transport, self)
            self.makeHigherConnection(higherTransport)

        elif signal == self.SIGNAL_CLIENT_RIPMESSAGE:
            print "Rip Client Protocol: message handle -- receives rip message: ", msg.Data
            self.higherProtocol() and self.higherProtocol().dataReceived(msg.Data)

        else:
            print "Rip Client Protocol: message handle -- undefined signal: ", signal

    # onEnter callback for STATE_CLIENT_CLOSE_REQ
    def sendCls(self, signal, data):
        if (signal == self.SIGNAL_CLIENT_SEND_CLS or signal == self.SIGNAL_CLIENT_TIMEOUT):
            print "Rip Client Protocol: client send close request -- signal : " + signal
            clsMessage = RipMessage()
            clsMessage.CLS = True
            self.transport.write(Packet.MsgToPacketBytes(clsMessage))
        else:
            print "Rip Client Protocol: client send close request -- undefined signal : " + signal

    # onEnter callback for STATE_CLIENT_CLOSE_RCVD
    def sendClsAck(self,signal, data):
        if (signal == self.SIGNAL_CLIENT_RCVD_CLSACK or signal == self.SIGNAL_CLIENT_TIMEOUT):
            print "Rip Client Protocol: client send close acknowledgement -- signal : " + signal
            clsackMessage = RipMessage()
            clsackMessage.CLS = True
            clsackMessage.ACK = True
            self.transport.write(Packet.MsgToPacketBytes(clsackMessage))
        else:
            print "Rip Client Protocol: client send close acknowledgement -- undefined signal : " + signal

    def generateSignature(self, msg):
        print "Rip Client Protocol: generateSignature -- add signature field into message"
        return "Client Signature Here~~"

    def generateCertificate(self):
        print "Rip Client Protocol: generateCertificate -- nonce1, self_addr_cert, intermidiate CA's cert"
        return "Client Certificate List here #o# ~"

"""
    Step 4: RipServerProtocol
"""

class RipServerProtocol(StackingProtocolMixin, Protocol):

    # States for handshake
    STATE_SERVER_LISTEN = "RIP SERVER STATE MACHINE: SERVER LISTEN"
    STATE_SERVER_SNN_RCVD = "RIP SERVER STATE MACHINE: SNN_RCVD"
    STATE_SERVER_ESTABLISHED = "RIP SERVER STATE MACHINE: ESTABLISHED"

    # States for close connection
    STATE_SERVER_CLOSE_REQ = "RIP SERVER STATE MACHINE: CLOSE REQUEST"
    STATE_SERVER_CLOSE_RCVD = "RIP SERVER STATE MACHINE: CLOSE RECEIVED"
    STATE_SERVER_CLOSE = "RIP SERVER STATE MACHINE: SERVER CLOSE"


    # signal for handshake
    SIGNAL_SERVER_RCVD_SNN = "RIP SERVER STATE MACHINE: received snn"
    SIGNAL_SERVER_RCVD_ACK = "RIP SERVER STATE MACHINE: received ack"
    SIGNAL_SERVER_RIPMESSAGE = "RIP SERVER STATE MACHINE: general data without flags"

    # signal for close connection
    SIGNAL_SERVER_SEND_CLS = "RIP SERVER STATE MACHINE: send close request"
    SIGNAL_SERVER_RCVD_CLSACK = "RIP SERVER STATE MACHINE: received close acknowledge"
    SIGNAL_SERVER_RCVD_CLS = "RIP SERVER STATE MACHINE: received close request"
    SIGNAL_SERVER_SEND_CLSACK = "RIP SERVER STATE MACHINE: send close acknowledge"

    # signal for timeout
    SIGNAL_SERVER_TIMEOUT = "RIP SERVER STATE MACHINE: timeout"

    def __init__(self):
        self.packetStorage = PacketStorage()
        self.SM = StateMachine("Rip Server Protocol StateMachine")

        self.SM.addState(self.STATE_SERVER_LISTEN,
                             # transition
                            (self.SIGNAL_SERVER_RCVD_SNN, self.STATE_SERVER_SNN_RCVD),
                             # no callback for LISTEN
                            )
        self.SM.addState(self.STATE_SERVER_SNN_RCVD,
                             # transitions
                            (self.SIGNAL_SERVER_RCVD_ACK, self.STATE_SERVER_ESTABLISHED),
                            (self.SIGNAL_SERVER_TIMEOUT, self.STATE_SERVER_SNN_RCVD), # if timeout server resend snn/ack
                             # callback
                            onEnter = self.sendSnnAck)

        self.SM.addState(self.STATE_SERVER_ESTABLISHED,
                             # transtions
                             (self.SIGNAL_SERVER_RIPMESSAGE, self.STATE_SERVER_ESTABLISHED),
                             (self.SIGNAL_SERVER_SEND_CLS, self.STATE_SERVER_CLOSE_REQ),
                             (self.SIGNAL_SERVER_RCVD_CLS, self.STATE_SERVER_CLOSE_RCVD),
                             (self.SIGNAL_SERVER_TIMEOUT, self.STATE_SERVER_ESTABLISHED), # if timeout server resend rip message
                             # callback
                             onEnter = self.messageHandle)

        self.SM.addState(self.STATE_SERVER_CLOSE_REQ,
                             # transitions
                             (self.SIGNAL_SERVER_RCVD_CLSACK, self.STATE_SERVER_CLOSE),
                             (self.SIGNAL_SERVER_TIMEOUT, self.STATE_SERVER_CLOSE_REQ), # if timeout server resend close request
                             # callback
                             onEnter = self.sendCls)

        self.SM.addState(self.STATE_SERVER_CLOSE_RCVD,
                             # transition
                             (self.SIGNAL_SERVER_TIMEOUT, self.STATE_SERVER_CLOSE), # if timeout server enter close
                             # callback
                             onEnter = self.sendClsAck)

    # this function transfer message flags into a signal. only used in dataReceived
    def msgToSignal(self, msg):
        if(msg.SNN == True and msg.ACK == False and msg.CLS == False):
            signal = self.SIGNAL_SERVER_RCVD_SNN
        elif(msg.SNN == False and msg.ACK == True and msg.CLS == False):
            signal = self.SIGNAL_SERVER_RCVD_ACK
        elif(msg.SNN == False and msg.ACK == False and msg.CLS == False):
            signal = self.SIGNAL_SERVER_RIPMESSAGE
        elif(msg.SNN == False and msg.ACK == False and msg.CLS == True):
            signal = self.SIGNAL_SERVER_RCVD_CLS
        return signal


    def connectionMade(self):
        print "Rip Server Protocol: connectionMade "
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
    def sendSnnAck(self, signal, data):
        if signal == self.SIGNAL_SERVER_RCVD_SNN:
            print "Rip Server Protocol: sendSnnAck"
            snnackMessage = RipMessage()
            snnackMessage.SNN = True
            snnackMessage.ACK = True

            # Todo: here server need to verify the signature and certificates from client
            # Todo: after verification, server need generate self signature and certificate
            # Server signature: {H(M)} _ private key --> ? which is server's private key
            # Server Certificate list: [Nonce2, Nonce1 + 1, ] --> how many certificates included in server?

            self.verifyClient()

            self.transport.write(Packet.MsgToPacketBytes(snnackMessage))
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

    # onEnter callback for STATE_SERVER_CLOSE_REQ
    def sendCls(self, signal, msg):
        if signal == self.SIGNAL_SERVER_SEND_CLS:
            print "Rip Server Protocol: send close -- signal by: " + signal
            clsMessage = RipMessage()
            clsMessage.CLS = True
            self.transport.write(Packet.MsgToPacketBytes(clsMessage))
        else:
            print "Rip Server Protocol: send close -- undefined signal: " + signal

    # onEnter callback for STATE_SERVER_CLOSE_RCVD
    def sendClsAck(self, signal, msg):
        if signal == self.SIGNAL_SERVER_RCVD_CLS:
            print "Rip Server Protocol: send close acknowledgement -- signal by: " + signal
            clsackMessage = RipMessage()
            clsackMessage.CLS = True
            clsackMessage.ACK = True
            self.transport.write(Packet.MsgToPacketBytes(clsackMessage))
        else:
            print "Rip Server Protocol: send close acknowledgement -- undefined signal: " + signal

    def verifyClient(self, msg):
        clientSignature = msg.Signature
        clientCertificate = msg.Certificate

"""
    Step 4: RipServerFactory & RipClientFactory
"""

class RipServerFactory(StackingFactoryMixin, Factory):
    protocol = RipServerProtocol

class RipClientFactory(StackingFactoryMixin, Factory):
    protocol = RipClientProtocol

ConnectFactory = RipClientFactory
ListenFactory = RipServerFactory