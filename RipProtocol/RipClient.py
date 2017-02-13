from twisted.internet.protocol import Protocol, Factory, connectionDone
from playground.network.common.Protocol import StackingFactoryMixin, StackingProtocolMixin
from playground.network.common.Packet import Packet, PacketStorage, IterateMessages

from playground.network.common.statemachine import StateMachine
from playground.network.common.statemachine import StateMachineError

from RipProtocol.RipMessage import RipMessage
from RipProtocol.RipTransport import RipTransport, logger, errReporter

from Authentication import generateClientCertificate, generateSignature, verification
from random import randint

class RipClientProtocol(StackingProtocolMixin, Protocol, RipTransport):

    """
            Rip Client State Machine
    """

    STATE_CLIENT_CLOSE = "RIP CLIENT STATE MACHINE: CLOSE"
    STATE_CLIENT_SNN_SENT = "RIP CLIENT STATE MACHINE: SNN SENT"
    STATE_CLIENT_CLS_RCVD = "RIP CLIENT STATE MACHINE: CLS RECEIVED"
    STATE_CLIENT_CLS_SEND = "RIP CLIENT STATE MACHINE: CLS SENT"
    STATE_CLIENT_ESTABLISHED = "RIP CLIENT STATE MACHINE: ESTABLISHED"

    SIGNAL_CLIENT_SEND_SNN = "RIP CLIENT STATE MACHINE: send snn"
    SIGNAL_CLIENT_RCVD_SNNACK = "RIP CLIENT STATE MACHINE: rcvd snn/ack"
    SIGNAL_CLIENT_RIPMESSAGE = "RIP CLIENT STATE MACHINE: general data without flags"
    SIGNAL_CLIENT_RCVD_CLS = "RIP CLIENT STATE MACHINE: rcvd cls"
    SIGNAL_CLIENT_SEND_CLS = "RIP CLIENT STATE MACHINE: send cls"
    SIGNAL_CLIENT_RCVD_CLSACK = "RIP CLIENT STATE MACHINE: rcvd cls/ack from server"
    SIGNAL_CLIENT_SEND_CLSACK = "RIP CLIENT STATE MACHINE: send cls/ack back to server"

    def __init__(self):
        self.packetStorage = PacketStorage()
        self.nonce = randint(0, 10000)
        self.SM = StateMachine("Rip Client Protocol StateMachine")

        self.SM.addState(self.STATE_CLIENT_CLOSE,
                        (self.SIGNAL_CLIENT_SEND_SNN, self.STATE_CLIENT_SNN_SENT))

        self.SM.addState(self.STATE_CLIENT_SNN_SENT,
                        (self.SIGNAL_CLIENT_RCVD_SNNACK, self.STATE_CLIENT_ESTABLISHED),
                        onEnter = self.sendSnn)


        self.SM.addState(self.STATE_CLIENT_ESTABLISHED,
                        (self.SIGNAL_CLIENT_RIPMESSAGE, self.STATE_CLIENT_ESTABLISHED),
                        (self.SIGNAL_CLIENT_RCVD_SNNACK, self.STATE_CLIENT_ESTABLISHED),
                        (self.SIGNAL_CLIENT_RCVD_CLS, self.STATE_CLIENT_CLS_RCVD),
                        (self.SIGNAL_CLIENT_SEND_CLS, self.STATE_CLIENT_CLS_SEND),
                        onEnter = self.messageHandle)

        self.SM.addState(self.STATE_CLIENT_CLS_SEND,
                         (self.SIGNAL_CLIENT_RCVD_CLSACK, self.STATE_CLIENT_CLOSE),
                         onEnter = self.sendCls)

        self.SM.addState(self.STATE_CLIENT_CLS_RCVD,
                         (self.SIGNAL_CLIENT_SEND_CLSACK, self.STATE_CLIENT_CLOSE),
                         onEnter = self.sendClsAck)


    def connectionMade(self):
        print "Rip Client Protocol: connection Made"
        self.SM.start(self.STATE_CLIENT_CLOSE)
        print "Rip Client Protocol: start state machine from state -- " + self.SM.currentState()
        self.SM.signal(self.SIGNAL_CLIENT_SEND_SNN, "")
        print "Rip Client Protocol: after snn send current state -- " + self.SM.currentState()

    def connectionLost(self, reason=connectionDone):
        self.SM.signal(self.SIGNAL_CLIENT_SEND_CLS, "")
        print "Rip Client Protocol: connection lost"
        self.transport.loseConnection()

    def dataSend(self, data):
        if not self.SM.currentState() == self.STATE_CLIENT_ESTABLISHED:
            return
        ripMsg = RipMessage()
        ripMsg.Data = data
        print "Rip Client Protocol: data send -- SNN = " + str(ripMsg.SNN) + " Data = " + ripMsg.Data
        self.transport.write(Packet.MsgToPacketBytes(ripMsg))

    def msgToSignal(self, msg): # only used by dataReceived()
        snn = msg.SNN
        ack = msg.ACK
        cls = msg.CLS
        if (snn and ack):
            signal = self.SIGNAL_CLIENT_RCVD_SNNACK
        elif(not snn and not ack):
            signal = self.SIGNAL_CLIENT_RIPMESSAGE
        elif(cls and not ack):
            signal = self.SIGNAL_CLIENT_RCVD_CLS
        elif(cls and ack):
            signal = self.SIGNAL_CLIENT_RCVD_CLSACK
        return signal

    def dataReceived(self, data):
        self.packetStorage.update(data)
        for rcvMsg in IterateMessages(self.packetStorage, logger, errReporter):
            clientSignal = self.msgToSignal(rcvMsg)
            self.SM.signal(clientSignal, rcvMsg)

    """    RipClient OnEnter Callback Functions    """

    # 1. STATE_CLIENT_SNN_SENT
    def sendSnn(self, signal, msg):
        print "Rip Client Protocol: 1. sendSnn -- " + signal
        snnMsg = RipMessage()
        snnMsg.SNN = True
        snnMsg.Certificate = generateClientCertificate(self.transport.getHost(), self.nonce)
        snnMsg.Signature = generateSignature(self.transport.getHost(), snnMsg.__serialize__())
        self.transport.write(Packet.MsgToPacketBytes(snnMsg))

     # 2. STATE_CLIENT_ESTABLISHED
    def messageHandle(self, signal, msg):

        # first time client enter established, must be triggered by signal_receive_snnack
        if signal == self.SIGNAL_CLIENT_RCVD_SNNACK:
            print "Rip Client Protocol: 2. message handle -- signal : " + signal
            # certificate chain from server [nonce2, addrCert, CACert, nonce1 + 1]
            if verification(self.nonce, msg) == False:
                print "Rip Client Protocol: verification failed!"
                return
            nonce2 = msg.Certificate[0]
            nonce1Plus1 = msg.Certificate[3]
            print "Rip Client Protocol: 2. message handle -- rcvd snnack: (nonce1 + 1) from server = " + str(nonce1Plus1) + "nonce2 from server = " + str(nonce2)
            self.sendAck(nonce2)
            higherTransport = RipTransport(self.transport, self)
            self.makeHigherConnection(higherTransport)

        elif signal == self.SIGNAL_CLIENT_RIPMESSAGE:
            print "Rip Client Protocol: 2. message handle -- receives rip message: ", msg.Data
            self.higherProtocol() and self.higherProtocol().dataReceived(msg.Data)

        else:
            print "Rip Client Protocol: 2. message handle -- undefined signal: ", signal

    # 3.1 STATE_CLIENT_CLS_SEND
    def sendCls(self, signal, msg):
        if signal == self.SIGNAL_CLIENT_SEND_CLS:
            print "Rip Client Protocol: 3.1 sendCls -- send CLS"
            msg = RipMessage()
            msg.CLS = True
            self.transport.write(Packet.MsgToPacketBytes(msg))
        else:
            print "Rip Client Protocol: 3.1 sendCls -- undefined signal: ", signal

    # 3.2 STATE_CLIENT_CLS_RCVD
    def sendClsAck(self, signal, msg):
        if signal == self.SIGNAL_CLIENT_RCVD_CLS:
            print "Rip Client Protocol: 3.2 sendClsAck -- send cls/ack back"
            # CLS/ACK package
            msg = RipMessage()
            msg.CLS = True
            msg.ACK = True
            self.transport.write(Packet.MsgToPacketBytes(msg))
            # !! here need to add timer before signal to close
            self.SM.signal(self.SIGNAL_CLIENT_SEND_CLSACK, msg)
            self.transport.loseConnection()
        else:
            print "Rip Client Protocol: 3.2 sendClsAck -- undefined signal: ", signal

    # not a callback, this function will be called at the first time enter established
    def sendAck(self, nonce2):
        print "Rip Client Protocol: sendAck, current state -- " + self.SM.currentState()
        msg = RipMessage()
        msg.ACK = True
        msg.Certificate = [int(nonce2) + 1]
        self.transport.write(Packet.MsgToPacketBytes(msg))