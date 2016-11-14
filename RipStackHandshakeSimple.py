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
    Step 1: Define Rip Message Body (simple handshake version)
"""

class RipMessage(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "RipTestProtocol.RipTestStack.RipHandshakeMessage"
    MESSAGE_VERSION = "1.0"
    BODY = [
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
    STATE_CLIENT_ESTABLISHED = "RIP CLIENT STATE MACHINE: ESTABLISHED"

    SIGNAL_CLIENT_SEND_SNN = "RIP CLIENT STATE MACHINE: send snn"
    SIGNAL_CLIENT_RIPMESSAGE = "RIP CLIENT STATE MACHINE: general data without flags"

    def __init__(self):
        self.packetStorage = PacketStorage()
        self.SM = StateMachine("Rip Client Protocol StateMachine")

        self.SM.addState(self.STATE_CLIENT_CLOSE,
                             # transition
                            (self.SIGNAL_CLIENT_SEND_SNN, self.STATE_CLIENT_ESTABLISHED),
                             # no callback for CLOSE
                            )
        self.SM.addState(self.STATE_CLIENT_ESTABLISHED,
                             # transtion
                             (self.SIGNAL_CLIENT_RIPMESSAGE, self.STATE_CLIENT_ESTABLISHED),
                             # callback
                             onEnter = self.messageHandle)

    def dataSend(self, data):
        if not self.SM.currentState() == self.STATE_CLIENT_ESTABLISHED:
            return
        ripMsg = RipMessage()
        ripMsg.Data = data
        print "Rip Client Protocol: data send -- SNN = " + str(ripMsg.SNN) + " Data = " + ripMsg.Data
        self.transport.write(Packet.MsgToPacketBytes(ripMsg))

    def dataReceived(self, data):
        self.packetStorage.update(data)
        for rcvMsg in IterateMessages(self.packetStorage, logger, errReporter):
            print "Rip Client Protocol: dataReceived -- rip message received, current state: ", self.SM.currentState()
            dataToUpper = rcvMsg.Data
            self.SM.signal(self.SIGNAL_CLIENT_RIPMESSAGE, dataToUpper)
            print "Rip Client Protocol: dataReceived -- after signal_ripmessage, current state: ", self.SM.currentState()

    def messageHandle(self, signal, dataToUpper):
        if signal == self.SIGNAL_CLIENT_SEND_SNN:
            print "Rip Client Protocol: message handle -- send snn: ", dataToUpper
            higherTransport = RipTransport(self.transport, self)
            self.makeHigherConnection(higherTransport)

        elif signal == self.SIGNAL_CLIENT_RIPMESSAGE:
            print "Rip Client Protocol: message handle -- receives rip message: ", dataToUpper
            self.higherProtocol() and self.higherProtocol().dataReceived(dataToUpper)

        else:
            print "Rip Client Protocol: message handle -- undefined signal: ", signal

    def connectionMade(self):
        print "Rip Client Protocol: connection Made"
        self.SM.start(self.STATE_CLIENT_CLOSE)
        print "Rip Client Protocol: start state machine from state -- " + self.SM.currentState()
        self.snnSend()
        self.SM.signal(self.SIGNAL_CLIENT_SEND_SNN, "")
        print "Rip Client Protocol: after snn send current state -- " + self.SM.currentState()

    def snnSend(self):
        snnMessage = RipMessage()
        snnMessage.SNN = True
        self.transport.write(Packet.MsgToPacketBytes(snnMessage))
        print "Rip Client Protocol: send snn"

"""
    Step 4: RipServerProtocol
"""

class RipServerProtocol(StackingProtocolMixin, Protocol):

    # States for handshake
    STATE_SERVER_LISTEN = "RIP STATE MACHINE: LISTEN"
    STATE_SERVER_ESTABLISHED = "RIP STATE MACHINE: ESTABLISHED"

    # signal
    SIGNAL_SERVER_RCVD_SNN = "RIP STATE MACHINE: received snn"
    SIGNAL_SERVER_RIPMESSAGE = "RIP STATE MACHINE: general data without flags"

    def __init__(self):
        self.packetStorage = PacketStorage()
        self.SM = StateMachine("Rip Server Protocol StateMachine")

        self.SM.addState(self.STATE_SERVER_LISTEN,
                             # transition
                            (self.SIGNAL_SERVER_RCVD_SNN, self.STATE_SERVER_ESTABLISHED),
                             # no callback for LISTEN
                            )
        self.SM.addState(self.STATE_SERVER_ESTABLISHED,
                             # transtion
                             (self.SIGNAL_SERVER_RIPMESSAGE, self.STATE_SERVER_ESTABLISHED),
                             # callback
                             onEnter = self.messageHandle)

    def connectionMade(self):
        self.SM.start(self.STATE_SERVER_LISTEN)

    def dataSend(self, data):
        if not self.SM.currentState() == self.STATE_SERVER_ESTABLISHED:
            return
        ripMsg = RipMessage()
        ripMsg.Data = data
        print "Rip Server Protocol: data send -- SNN = " + str(ripMsg.SNN) + " Data = " + ripMsg.Data
        self.transport.write(Packet.MsgToPacketBytes(ripMsg))

    def dataReceived(self, data):
        self.packetStorage.update(data)
        for rcvMsg in IterateMessages(self.packetStorage, logger, errReporter):
            if(rcvMsg.SNN == True):
                print "Rip Protocol: dataReceived -- snn received, current state: ", self.SM.currentState()
                self.SM.signal(self.SIGNAL_SERVER_RCVD_SNN, rcvMsg)
                print "Rip Protocol: dataReceived -- after;l signal_rcvd_snn, current state: ", self.SM.currentState()
            else:
                print "Rip Protocol: dataReceived -- rip message received, current state: ", self.SM.currentState()
                dataToUpper = rcvMsg.Data
                self.SM.signal(self.SIGNAL_SERVER_RIPMESSAGE, dataToUpper)
                print "Rip Protocol: dataReceived -- after signal_ripmessage, current state: ", self.SM.currentState()

    def messageHandle(self, signal, dataToUpper):

        if signal == self.SIGNAL_SERVER_RCVD_SNN:
            print "Rip Server Protocol: message handle -- receives snn: ", dataToUpper
            higherTransport = RipTransport(self.transport, self)
            self.makeHigherConnection(higherTransport)

        elif signal == self.SIGNAL_SERVER_RIPMESSAGE:
            print "Rip Protocol: message handle -- receives rip message: ", dataToUpper
            self.higherProtocol() and self.higherProtocol().dataReceived(dataToUpper)

        else:
            print "Rip Protocol: message handle -- undefined signal: ", signal

"""
    Step 4: RipServerFactory & RipClientFactory
"""

class RipServerFactory(StackingFactoryMixin, Factory):
    protocol = RipServerProtocol

class RipClientFactory(StackingFactoryMixin, Factory):
    protocol = RipClientProtocol

ConnectFactory = RipClientFactory
ListenFactory = RipServerFactory