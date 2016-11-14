'''
Created on Sep 21, 2016

@author: sethjn
'''

from random import randint
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256
from playground.crypto import X509Certificate
import CertFactory

from twisted.internet.protocol import Protocol, Factory
from zope.interface.declarations import implements
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.StandardMessageSpecifiers import STRING
from playground.network.common.Protocol import StackingTransport,\
    StackingProtocolMixin, StackingFactoryMixin
from playground.network.message.StandardMessageSpecifiers import UINT4, UINT2, BOOL1, STRING, DEFAULT_VALUE, LIST, OPTIONAL
from twisted.internet import task
from twisted.internet import reactor
from playground.network.common.Protocol import MessageStorage

from apps.samples import KissProtocol

clientDataBuffer = []
clientSendBuffer = []
clientIncomingData = []
serverDataBuffer = []
serverSendBuffer = []
serverIncomingData = []
i = 0

class RIPMessage(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "RIPMessageID"
    MESSAGE_VERSION = "1.0"
    
    BODY = [ 
        ("sequence_number", UINT4),
        ("acknowledgement_number", UINT4, OPTIONAL),
        ("signature", STRING, DEFAULT_VALUE("")),
        ("certificate", LIST(STRING), OPTIONAL),
        ("sessionID", STRING, DEFAULT_VALUE("")),
        ("acknowledgement_flag", BOOL1, DEFAULT_VALUE(False)),
        ("close_flag", BOOL1, DEFAULT_VALUE(False)),
        ("sequence_number_notification_flag", BOOL1, DEFAULT_VALUE(False)),
        ("reset_flag", BOOL1, DEFAULT_VALUE(False)),
        ("data", STRING,DEFAULT_VALUE("")),
        ("OPTIONS", LIST(STRING), OPTIONAL)
      ]

class RIPMessageTransportClient(StackingTransport):
    def __init__(self, lowerTransport, protocol):
        StackingTransport.__init__(self, lowerTransport)
        self.SEQUENCE_NUMBER = protocol.SEQUENCE_NUMBER
        self.SESSION_ID = protocol.sessionId

        # LOOP--------------------------------------------------------
        l = task.LoopingCall(self.checkBufferForPackets)
        l.start(2.0) # call every second

    def checkBufferForPackets(self):
        global clientSendBuffer
        if(len(clientSendBuffer) != 0):
            for message in clientSendBuffer:
                self.sendData(message)
        else:
            self.segmentData()
        
    def write(self, data):

        # Cant transmit data if it is more than 4 GB
        if(len(data) > 4294967296):
            print "Data above the limit - Dropping Data"
            return

        self.saveDataInBuffer(data)
        self.segmentData()        

    def loseConnection(self):
        closeMessage = RIPMessage()
        closeMessage.close_flag = True
        closeMessage.sequence_number = 0 # How to pass sequence number
        self.lowerTransport().write(closeMessage.__serialize__())

    def makeSegments(self):
        global clientDataBuffer
        global clientSendBuffer
        for data in clientDataBuffer:
            message = RIPMessage()
            message.data = data
            message.sequence_number = len(message.data) # How to pass sequence number
            self.SEQUENCE_NUMBER += len(message.data)
            message.sessionId = self.SESSION_ID # How to get sessionId

            # Creating the signature field
            rawKey = CertFactory.getPrivateKeyForAddr("")
            rsaKey = RSA.importKey(rawKey)
            rsaSigner = PKCS1_v1_5.new(rsaKey)

            # Hashing and Signing
            hasher = SHA256.new()
            hasher.update(str(message))
            signatureBytes = rsaSigner.sign(hasher)
            message.signature = signatureBytes
            clientSendBuffer.extend([message])
            clientDataBuffer.remove(data)
            self.sendData(message)

    def segmentData(self):
        global clientDataBuffer
        global clientIncomingData
        if(len(clientDataBuffer) == 0 and len(clientIncomingData) > 0):
            data = clientIncomingData.pop(0)
            n = 4096 # Size of packet
            clientDataBuffer = [data[i:i+n] for i in range(0, len(data), n)]
            #print clientDataBuffer
            self.makeSegments()
        else:
            return  # Don't do anything if the databuffer has content

    def saveDataInBuffer(self, data):
        global clientIncomingData
        clientIncomingData.extend([data])

    def sendData(self, message):
        self.lowerTransport().write(message.__serialize__()) 


class RIPMessageTransportServer(StackingTransport):
    def __init__(self, lowerTransport, protocol):
        StackingTransport.__init__(self, lowerTransport)
        self.SEQUENCE_NUMBER = protocol.SEQUENCE_NUMBER
        self.SESSION_ID = protocol.sessionId
        
        # LOOP--------------------------------------------------------
        l = task.LoopingCall(self.checkBufferForPackets)
        l.start(2.0) # call every second

    def checkBufferForPackets(self):
        global serverSendBuffer
        if(len(serverSendBuffer) != 0):
            for message in serverSendBuffer:
                self.sendData(message)
        else:
            self.segmentData()
        
    def write(self, data):

        # Cant transmit data if it is more than 4 GB
        if(len(data) > 4294967296):
            print "Data above the limit - Dropping Data"
            return

        self.saveDataInBuffer(data)
        self.segmentData()        

    def loseConnection(self):
        closeMessage = RIPMessage()
        closeMessage.close_flag = True
        closeMessage.sequence_number = 0 # How to pass sequence number
        self.lowerTransport().write(closeMessage.__serialize__())

    def makeSegments(self):
        global serverDataBuffer
        global serverSendBuffer
        for data in serverDataBuffer:
            message = RIPMessage()
            message.data = data
            message.sequence_number = len(message.data) # How to pass sequence number
            self.SEQUENCE_NUMBER += len(message.data)
            message.sessionId = self.SESSION_ID # How to get sessionId

            # Creating the signature field
            rawKey = CertFactory.getPrivateKeyForAddr("")
            rsaKey = RSA.importKey(rawKey)
            rsaSigner = PKCS1_v1_5.new(rsaKey)

            # Hashing and Signing
            hasher = SHA256.new()
            hasher.update(str(message))
            signatureBytes = rsaSigner.sign(hasher)
            message.signature = signatureBytes
            clientSendBuffer.extend([message])
            serverDataBuffer.remove(data)
            self.sendData(message)

    def segmentData(self):
        global serverDataBuffer
        global serverIncomingData
        if(len(serverDataBuffer) == 0 and len(serverIncomingData) > 0):
            data = serverIncomingData.pop(0)
            n = 4096 # Size of packet
            serverDataBuffer = [data[i:i+n] for i in range(0, len(data), n)]
            #print serverDataBuffer
            self.makeSegments()
        else:
            return  # Don't do anything if the databuffer has content

    def saveDataInBuffer(self, data):
        global serverIncomingData
        serverIncomingData.extend([data])

    def sendData(self, message):
        self.lowerTransport().write(message.__serialize__()) 
class ServerProtocol(StackingProtocolMixin, Protocol):
    def __init__(self):
        self.buffer = ""
        self.storage = MessageStorage()
        self.sessionId = ""
        self.STATE = "None"
        self.SEQUENCE_NUMBER = 0;
        self.ACKNOWLEDGEMENT_NUMBER = 0;
        self.dataBuffer = []
        self.sendBuffer = []
        
    def connectionMade(self):
        print "Connection Initiating ..."
        
    def dataReceived(self, data):
        # self.buffer += data
        # try:
        #     message, bytesUsed = RIPMessage.Deserialize(data)
        #     self.buffer = self.buffer[bytesUsed:]
        # except Exception, e:
        #     print "We had a deserialization error", e
        #     return

        self.storage.update(data)
        for msg in self.storage.iterateMessages():
            self.processIncomingData(msg)

    def processIncomingData(self, message):

        global serverSendBuffer

        for recvMessage in serverSendBuffer:
            if(message.acknowledgement_number == recvMessage.sequence_number+1):
                serverSendBuffer.remove(recvMessage)
                break

        # HANDSHAKE ------------------------------------------------------------
        if(self.STATE == "None" and message.sequence_number_notification_flag == True):
            self.completeHandshake(message)
            return
        elif(self.STATE == "RECV_SNN_SEND_ACK" and message.acknowledgement_flag == True):
            self.STATE = "CONNECTION_ESTABLISHED"
            higherTransport = RIPMessageTransportServer(self.transport, self)
            self.makeHigherConnection(higherTransport)
            return
        elif(message.reset_flag == True):
            # Reset Connection
            print " Connection Reset \n"
            SYNACKmessage = RIPMessage()

            nounceReceived = int(message.certificate[0])
            nounceToBeSent = nounceReceived + 1

            # Getting the private key for signing
            rawKey = CertFactory.getPrivateKeyForAddr("")
            rsaKey = RSA.importKey(rawKey)
            rsaSigner = PKCS1_v1_5.new(rsaKey)

            # Hashing and Signing
            hasher = SHA256.new()
            hasher.update(str(nounceToBeSent))
            signatureBytes = rsaSigner.sign(hasher)

            #with open("apps/samples/cert2_signed.cert") as f:
            #    clientCertificate = f.read()
            clientCertificate = str(message.certificate[1])
            nounceReceived = str(message.certificate[0])

            signCheck = message.signature
            message.signature = ""

            # Verifying the Certificates
            cert = X509Certificate.loadPEM(clientCertificate)
            peerPublicKeyBlob = cert.getPublicKeyBlob()
            peerPublicKey = RSA.importKey(peerPublicKeyBlob)
            rsaVerifier = PKCS1_v1_5.new(peerPublicKey)
            hasher1 = SHA256.new()
            hasher1.update(str(message))
            result = rsaVerifier.verify(hasher1, signCheck)
# ----------CHECK VERIFY -------------------------------------------------------------------
            print result

            # Creating the certificate field of the message
            nounce = randint(0, 10000)
            # with open("apps/samples/cert1_signed.cert") as f:
            #     serverCertBytes = f.read()
            # with open("apps/samples/shirishs_signed.cert") as f:
            #     CACertBytes = f.read()
            certificate = [nounce, signatureBytes]  #, serverCertBytes, CACertBytes]
            certificate.extend(CertFactory.getCertsForAddr("apps/samples/cert1_signed.cert"))
            SYNACKmessage.certificate = certificate

            # SETTING SESSION ID
            self.sessionId = str(nounce) + str(nounceReceived)

            SYNACKmessage.sequence_number_notification_flag = True
            SYNACKmessage.acknowledgement_flag = True
            SYNACKmessage.acknowledgement_number = message.sequence_number + 1
            SYNACKmessage.sequence_number = self.SEQUENCE_NUMBER
            self.SEQUENCE_NUMBER += 1
            self.STATE = "RECV_SNN_SEND_ACK"
            self.transport.write(SYNACKmessage.__serialize__())
            return
        # END HANDSHAKE --------------------------------------------------------

        #self.higherProtocol()
        self.higherProtocol().dataReceived(message.data)
        self.buffer and self.dataReceived("")

        # DATA ACKNOWLEDGE SEND ------------------------------------------------
        if(message.acknowledgement_flag == False and message.reset_flag == False):
            ACKMessage = RIPMessage()
            ACKMessage.sequence_number = self.SEQUENCE_NUMBER
            self.SEQUENCE_NUMBER += 1
            ACKMessage.acknowledgement_flag = True
            ACKMessage.acknowledgement_number = message.sequence_number + 1
            ACKMessage.sessionID = self.sessionId
            self.transport.write(ACKMessage.__serialize__())
            return
        # DATA ACKNOWLEDGE SEND ************************************************

        # CLOSING CONNECTION ---------------------------------------------------
        if(message.close_flag == True):
            print " SERVER CLOSING CONNECTION \n"
            CloseConnectionMessage = RIPMessage()
            CloseConnectionMessage.acknowledgement_flag = True
            CloseConnectionMessage.close_flag = True
            CloseConnectionMessage.sequence_number = self.SEQUENCE_NUMBER
            self.SEQUENCE_NUMBER += 1
            self.transport.write(CloseConnectionMessage.__serialize__())
            return
        # END CLOSING ----------------------------------------------------------

    def completeHandshake(self, message):
        print " 2 - RECEIVED SYN FROM CLIENT SENDING SYNACK TO CLIENT \n"
        SYNACKmessage = RIPMessage()

        nounceReceived = int(message.certificate[0])
        nounceToBeSent = nounceReceived + 1

        # Getting the private key for signing
        rawKey = CertFactory.getPrivateKeyForAddr("")
        rsaKey = RSA.importKey(rawKey)
        rsaSigner = PKCS1_v1_5.new(rsaKey)

        # Hashing and Signing
        hasher = SHA256.new()
        hasher.update(str(nounceToBeSent))
        signatureBytes = rsaSigner.sign(hasher)

        # Creating the certificate field of the message
        nounce = randint(0, 10000)
        # with open("apps/samples/cert1_signed.cert") as f:
        #     serverCertBytes = f.read()
        # with open("apps/samples/shirishs_signed.cert") as f:
        #     CACertBytes = f.read()
        certificate = [nounce, signatureBytes] #, serverCertBytes, CACertBytes]
        #print self.transport.getHost().host
        certificate.extend(CertFactory.getCertsForAddr("apps/samples/cert1_signed.cert"))
        SYNACKmessage.certificate = certificate

        # SETTING SESSION ID
        self.sessionId = str(nounce) + str(nounceReceived)

        SYNACKmessage.sequence_number_notification_flag = True
        SYNACKmessage.acknowledgement_flag = True
        SYNACKmessage.acknowledgement_number = message.sequence_number + 1
        SYNACKmessage.sequence_number = self.SEQUENCE_NUMBER
        self.SEQUENCE_NUMBER += 1
        self.STATE = "RECV_SNN_SEND_ACK"
        self.transport.write(SYNACKmessage.__serialize__())
        return
        
class ClientProtocol(StackingProtocolMixin, Protocol):
    def __init__(self):
        self.buffer = ""
        self.storage = MessageStorage()
        self.nounce = ""
        self.sessionId = ""
        self.STATE = "None"
        self.SEQUENCE_NUMBER = 0;
        self.ACKNOWLEDGEMENT_NUMBER = 0;
        self.dataBuffer = []
        self.sendBuffer = []
        
    def connectionMade(self):
    # HANDSHAKE START ------------------------------------------------------------
        if(self.STATE == "None"):
            print "1 - SENDING SYN TO SERVER \n"
            SYNmessage = RIPMessage()

            # Creating the certificate field of the message
            nounce = randint(0, 10000)
            self.nounce = nounce
            certificate = [nounce]
            certificate.extend(CertFactory.getCertsForAddr("apps/samples/cert2_signed.cert"))
            SYNmessage.certificate = certificate

            SYNmessage.sequence_number_notification_flag = True
            SYNmessage.sequence_number = self.SEQUENCE_NUMBER
            self.SEQUENCE_NUMBER += 1
            self.STATE = "SEND_SNN_WAIT_ACK"
            self.transport.write(SYNmessage.__serialize__())
            return
    # END HANDSHAKE --------------------------------------------------------
        
    def dataReceived(self, data):
        # self.buffer += data
        # try:
        #     message, bytesUsed = RIPMessage.Deserialize(data)
        #     self.buffer = self.buffer[bytesUsed:]
        # except Exception, e:
        #     print "We had a deserialization error", e
        #     return

        self.storage.update(data)
        for msg in self.storage.iterateMessages():
            self.processIncomingData(msg)
    
    def processIncomingData(self, message):

        global clientSendBuffer

        for recvMessage in clientSendBuffer:
            if(message.acknowledgement_number == recvMessage.sequence_number+1):
                clientSendBuffer.remove(recvMessage)
                break

    # HANDSHAKE ------------------------------------------------------------
        if(self.STATE == "SEND_SNN_WAIT_ACK" and message.acknowledgement_flag == True):
            threeWayEstablished = self.finishHandshake(message)
            if(threeWayEstablished == True):
                # After handshake create the higher transport
                higherTransport = RIPMessageTransportClient(self.transport, self)
                self.makeHigherConnection(higherTransport)
                return
            else:
                # Re-establish connection
                return
    # END HANDSHAKE ********************************************************

        self.higherProtocol().dataReceived(message.data)
        self.buffer #and self.dataReceived("")

    # DATA ACKNOWLEDGE SEND ------------------------------------------------
        if(message.acknowledgement_flag == False and message.reset_flag == False):
            ACKMessage = RIPMessage()
            ACKMessage.sequence_number = self.SEQUENCE_NUMBER
            self.SEQUENCE_NUMBER += 1
            ACKMessage.acknowledgement_flag = True
            ACKMessage.acknowledgement_number = message.sequence_number + 1
            ACKMessage.sessionID = self.sessionId
            self.transport.write(ACKMessage.__serialize__())
            return
    # DATA ACKNOWLEDGE SEND ************************************************


    # CLOSING CONNECTION ---------------------------------------------------
        if(message.close_flag == True):
            print " CLIENT CLOSING CONNECTION \n"
            return
    # END CLOSING **********************************************************

        #self.higherProtocol()
        #self.higherProtocol().dataReceived(message.data)
        #self.buffer and self.dataReceived("")

    def finishHandshake(self, message):
        SYNmessage = RIPMessage()
        SYNmessage.data = "ACK"

        serverCertificate = str(message.certificate[2])
        nounceReceivedToBeVerified = str(message.certificate[1])
        nounceReceived = str(message.certificate[0])
        
        # Verifying the Certificates
        cert = X509Certificate.loadPEM(serverCertificate)
        peerPublicKeyBlob = cert.getPublicKeyBlob()
        peerPublicKey = RSA.importKey(peerPublicKeyBlob)
        rsaVerifier = PKCS1_v1_5.new(peerPublicKey)
        hasher = SHA256.new()
        hasher.update(str(self.nounce + 1))
        result = rsaVerifier.verify(hasher, nounceReceivedToBeVerified)
        
        if(result == True):
            print "3 - RECEIVED SYNACK FROM SERVER SENDING ACK TO SERVER \n"
            nounceReceivedToBeSent = int(message.certificate[0])

            # Getting the private key for signing
            rawKey = CertFactory.getPrivateKeyForAddr("")
            rsaKey = RSA.importKey(rawKey)
            rsaSigner = PKCS1_v1_5.new(rsaKey)

            # Hashing and Signing
            hasher = SHA256.new()
            hasher.update(str(nounceReceivedToBeSent))
            signatureBytes = rsaSigner.sign(hasher)

            # SETTING SESSION ID
            self.sessionId = str(self.nounce) + str(nounceReceived)

            SYNmessage.sequence_number_notification_flag = True
            SYNmessage.sequence_number = self.SEQUENCE_NUMBER
            SYNmessage.acknowledgement_flag = True
            SYNmessage.acknowledgement_number = message.sequence_number + 1
            self.SEQUENCE_NUMBER += 1
            self.STATE = "RECV_SYNACK_SEND_ACK"
            self.transport.write(SYNmessage.__serialize__())
            return True
        else:
            # Reset Connection : Cannot verify
            print " Connection Reset \n"
            ResetMessage = RIPMessage()
            ResetMessage.sequence_number = self.SEQUENCE_NUMBER
            self.SEQUENCE_NUMBER += 1
            ResetMessage.sequence_number_notification_flag = True
            ResetMessage.reset_flag = True
            self.STATE = "SEND_SNN_WAIT_ACK"

            # Creating the certificate field of the message
            nounce = randint(0, 10000)
            self.nounce = nounce
            certificate = [nounce]
            certificate.extend(CertFactory.getCertsForAddr("apps/samples/cert2_signed.cert"))
            ResetMessage.certificate = certificate

            # Creating the signature field
            rawKey = CertFactory.getPrivateKeyForAddr("")
            rsaKey = RSA.importKey(rawKey)
            rsaSigner = PKCS1_v1_5.new(rsaKey)

            # Hashing and Signing
            hasher = SHA256.new()
            hasher.update(str(ResetMessage))
            signatureBytes = rsaSigner.sign(hasher)

#-----------Verifying the Certificates----------------------------------------------------
            cert = X509Certificate.loadPEM(certificate[1])
            peerPublicKeyBlob = cert.getPublicKeyBlob()
            peerPublicKey = RSA.importKey(peerPublicKeyBlob)
            rsaVerifier = PKCS1_v1_5.new(peerPublicKey)
            result = rsaVerifier.verify(hasher, signatureBytes)
            print result

            ResetMessage.signature = signatureBytes
            self.transport.write(ResetMessage.__serialize__())
            return False

class ServerFactory(StackingFactoryMixin, Factory):
    protocol = ServerProtocol

class ClientFactory(StackingFactoryMixin, Factory):
    protocol = ClientProtocol

ConnectFactory = ClientFactory.StackType(KissClientFactory)
ListenFactory = ServerFactory.StackType(KissServerFactory)
    
# ConnectFactory = ClientFactory
# ListenFactory = ServerFactory


# class ClientProtocol(StackingProtocolMixin, Protocol):
#     def __init__(self):
#         self.buffer = ""
        
#     def connectionMade(self):
#         higherTransport = RIPMessageTransport(self.transport)
#         self.makeHigherConnection(higherTransport)
        
#     def dataReceived(self, data):
#         self.buffer += data
#         try:
#             message, bytesUsed = RIPMessage.Deserialize(data)
#         except Exception, e:
#             #print "We had a deserialization error", e
#             return
#         #self.higherProtocol()
#         self.higherProtocol().dataReceived(message.Data)