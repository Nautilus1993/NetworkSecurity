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
        ("Data", STRING, DEFAULT_VALUE(""))
    ]


"""
    Step 2: Define Rip Test Transport
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
        snnMessage = RipMessage()
        snnMessage.SNN = True
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
            self.sendAck()
            higherTransport = RipTransport(self.transport, self)
            self.makeHigherConnection(higherTransport)

        elif signal == self.SIGNAL_CLIENT_RIPMESSAGE:
            print "Rip Client Protocol: message handle -- receives rip message: ", msg.Data
            self.higherProtocol() and self.higherProtocol().dataReceived(msg.Data)

        else:
            print "Rip Client Protocol: message handle -- undefined signal: ", signal


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

"""
    Step 4: RipServerFactory & RipClientFactory
"""

class RipServerFactory(StackingFactoryMixin, Factory):
    protocol = RipServerProtocol

class RipClientFactory(StackingFactoryMixin, Factory):
    protocol = RipClientProtocol

ConnectFactory = RipClientFactory
ListenFactory = RipServerFactory