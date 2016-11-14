from twisted.internet import protocol, reactor
#from twisted.internet.endpoints import TCP4ClientEndpoint
import sys

import KissProtocol
import RipStackTest
import RipStackHandshakeSimple
from playground.twisted.endpoints import GateClientEndpoint, GateServerEndpoint

class EchoClient(protocol.Protocol):
    def connectionMade(self):
        print "Http Client Protocol: connection made"
        request = "GET " + "test/index.html" + " HTTP/1.0\r\n"
        #request = "GET test/test.html HTTP/1.0\r\n"
        self.transport.write(request)

    def dataReceived(self, data):
        print "Message from server:" , data
        self.transport.loseConnection()

class EchoFactory(protocol.ClientFactory):
    def buildProtocol(self, addr):
        return EchoClient()

    def clientConnectionFailed(self, connector, reason):
        print "Connection failed."
        reactor.stop()

    def clientConnectionLost(self, connector, reason):
        print "Connection lost."
        reactor.stop()

def main():
    #endpoint = GateClientEndpoint.CreateFromConfig(reactor, "20164.0.0.1", 101, "gatekey2", networkStack=KissProtocol)
    endpoint = GateClientEndpoint.CreateFromConfig(reactor, "20164.0.0.1", 101, "gatekey2", networkStack= RipStackHandshakeSimple)
    endpoint.connect(EchoFactory())
    reactor.run()

if __name__ == '__main__':
    main()
