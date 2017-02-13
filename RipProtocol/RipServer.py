from twisted.internet.protocol import Protocol, Factory, connectionDone
from playground.network.common.Protocol import StackingFactoryMixin, StackingProtocolMixin
from playground.network.common.Packet import Packet, PacketStorage, IterateMessages

from playground.network.common.statemachine import StateMachine
from playground.network.common.statemachine import StateMachineError

from RipProtocol.RipMessage import RipMessage
from RipProtocol.RipTransport import RipTransport, logger, errReporter

from RipProtocol.Authentication import generateServerCertificate, generateSignature, verification
from random import randint

class RipServerProtocol(StackingProtocolMixin, Protocol):

    """
            Rip Server State Machine
    """
    STATE_SERVER_LISTEN = "RIP SERVER STATE MACHINE: LISTEN"
    STATE_SERVER_SNN_RCVD = "RIP SERVER STATE MACHINE: SNN_RCVD"
    STATE_SERVER_ESTABLISHED = "RIP SERVER STATE MACHINE: ESTABLISHED"
    STATE_SERVER_CLS_RCVD = "RIP SERVER STATE MACHINE: CLS_RCVD"
    STATE_SERVER_CLS_SEND = "RIP SERVER STATE MACHINE: CLS_SEND"

    SIGNAL_SERVER_RCVD_SNN = "RIP SERVER STATE MACHINE: received snn"
    SIGNAL_SERVER_RCVD_ACK = "RIP SERVER STATE MACHINE: received ack"
    SIGNAL_SERVER_RIPMESSAGE = "RIP SERVER STATE MACHINE: general data without flags"
    SIGNAL_SERVER_RCVD_CLS = "RIP SERVER STATE MACHINE: rcvd cls"
    SIGNAL_SERVER_SEND_CLS = "RIP SERVER STATE MACHINE: send cls"
    SIGNAL_SERVER_RCVD_CLSACK = "RIP SERVER STATE MACHINE: rcvd cls/ack from client"
    SIGNAL_SERVER_SEND_CLSACK = "RIP SERVER STATE MACHINE: send cls/ack back to client"

    def __init__(self):
        self.packetStorage = PacketStorage()
        self.nonce = randint(0, 10000)
        self.SM = StateMachine("Rip Server Protocol StateMachine")

        self.SM.addState(self.STATE_SERVER_LISTEN,
                        (self.SIGNAL_SERVER_RCVD_SNN, self.STATE_SERVER_SNN_RCVD),
                        )
        self.SM.addState(self.STATE_SERVER_SNN_RCVD,
                        (self.SIGNAL_SERVER_RCVD_ACK, self.STATE_SERVER_ESTABLISHED),
                        onEnter = self.sendSnnAck)

        self.SM.addState(self.STATE_SERVER_ESTABLISHED,
                        (self.SIGNAL_SERVER_RIPMESSAGE, self.STATE_SERVER_ESTABLISHED),
                        (self.SIGNAL_SERVER_RCVD_CLS, self.STATE_SERVER_CLS_RCVD),
                        (self.SIGNAL_SERVER_SEND_CLS, self.STATE_SERVER_CLS_SEND),
                        onEnter = self.messageHandle)

        self.SM.addState(self.STATE_SERVER_CLS_SEND,
                         (self.SIGNAL_SERVER_RCVD_CLSACK, self.STATE_SERVER_LISTEN),
                         onEnter = self.sendCls)

        self.SM.addState(self.STATE_SERVER_CLS_RCVD,
                         (self.SIGNAL_SERVER_SEND_CLSACK, self.STATE_SERVER_LISTEN),
                         onEnter = self.sendClsAck)

    def connectionMade(self):
        self.SM.start(self.STATE_SERVER_LISTEN)

    def connectionLost(self, reason=connectionDone):
        self.SM.signal(self.SIGNAL_SERVER_SEND_CLS, "")
        print "Rip Server Protocol: connection lost"
        self.transport.loseConnection()

    def dataSend(self, data):
        if not self.SM.currentState() == self.STATE_SERVER_ESTABLISHED:
            return
        ripMsg = RipMessage()
        ripMsg.Data = data
        print "Rip Server Protocol: data send -- Data = " + ripMsg.Data
        self.transport.write(Packet.MsgToPacketBytes(ripMsg))

    def msgToSignal(self, msg): # only used by dataReceived()
        snn = msg.SNN
        ack = msg.ACK
        cls = msg.CLS
        if(snn and not ack):
            signal = self.SIGNAL_SERVER_RCVD_SNN
        elif(not snn and ack):
            signal = self.SIGNAL_SERVER_RCVD_ACK
        elif(not snn and not ack):
            signal = self.SIGNAL_SERVER_RIPMESSAGE
        elif(cls and not ack):
            print "server received cls"
            signal = self.SIGNAL_SERVER_RCVD_CLS
        elif(cls and ack):
            signal = self.SIGNAL_SERVER_RCVD_CLSACK
        return signal


    def dataReceived(self, data):
        self.packetStorage.update(data)
        for rcvMsg in IterateMessages(self.packetStorage, logger, errReporter):
            serverSignal = self.msgToSignal(rcvMsg)
            print "server signal" + str(serverSignal)
            self.SM.signal(serverSignal, rcvMsg)

    """     RipServer OnEnter Callback Functions    """

    # 1. STATE_SERVER_SNN_RCVD
    def sendSnnAck(self, signal, rcvMsg):
        if signal == self.SIGNAL_SERVER_RCVD_SNN:
            if verification(0, rcvMsg) == False:
                return
            print "Rip Server Protocol: 1. sendSnnAck -- nonce1 from client = " + str(rcvMsg.Certificate[0])
            nonce1 = rcvMsg.Certificate[0]

            msg = RipMessage()
            msg.SNN = True
            msg.ACK = True
            msg.Certificate = generateServerCertificate(self.transport.getHost(), nonce1, self.nonce)
            msg.Signature = generateSignature(self.transport.getHost(), msg.__serialize__())
            self.transport.write(Packet.MsgToPacketBytes(msg))
        else:
            print "Rip Server Protocol: 1. sendSnnAck -- undefined signal: " + signal

    # 2. STATE_SERVER_ESTABLISHED
    def messageHandle(self, signal, msg):
        if signal == self.SIGNAL_SERVER_RCVD_ACK:
            print "Rip Server Protocol: 2. message handle -- received ack: nonce2 + 1 = " + str(msg.Certificate[0]) + " server nonce = " + str(self.nonce)
            nonce2Plus1 = msg.Certificate[0]
            if (int(nonce2Plus1) != (self.nonce + 1)):
                return False
            higherTransport = RipTransport(self.transport, self)
            self.makeHigherConnection(higherTransport)

        elif signal == self.SIGNAL_SERVER_RIPMESSAGE:
            print "Rip Server Protocol: 2. message handle -- receives rip message: data -- " + msg.Data
            self.higherProtocol() and self.higherProtocol().dataReceived(msg.Data)

        else:
            print "Rip Server Protocol: 2. message handle -- undefined signal: ", signal

    # 3.1 STATE_SERVER_CLS_SEND
    def sendCls(self, signal, msg):
        if signal == self.SIGNAL_SERVER_SEND_CLS:
            print "Rip Server Protocol: 3.1 sendCls -- send CLS"
            msg = RipMessage()
            msg.CLS = True
            self.transport.write(Packet.MsgToPacketBytes(msg))
            # timer here
        else:
            print "Rip Server Protocol: 3.1 sendCls -- undefined signal: ", signal

    # 3.2 STATE_CLIENT_CLS_RCVD
    def sendClsAck(self,signal, msg):
        if signal == self.SIGNAL_SERVER_RCVD_CLS:
            print "Rip Server Protocol: 3.2 sendClsAck -- rcvd CLS"
            msg = RipMessage()
            msg.CLS = True
            msg.ACK = True
            self.transport.write(Packet.MsgToPacketBytes(msg))
            self.SM.signal(self.SIGNAL_SERVER_SEND_CLSACK, msg)
            self.transport.loseConnection()
        else:
            print "Rip Server Protocol: 3.2 sendClsAck -- undefined signal: ", signal