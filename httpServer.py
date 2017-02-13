from twisted.internet import protocol, reactor
#from twisted.internet.endpoints import TCP4ServerEndpoint
#from RipProtocol import RipStackAuthentication
from RipProtocol import RipStack
from playground.twisted.endpoints import GateServerEndpoint

class Echo(protocol.Protocol):
    def dataReceived(self, data):
        print "Http Server Protocol: received data: "+ data
        self.sendResponse(data)

    def sendResponse(self,data):
        path = self.getPagePath(data)
        page = self.findPage(path)
        print "Http Server Protocol: send response: " + page
        self.transport.write(page)

    def getPagePath(self, data):
        request = data.split(' ')
        path = request[1]
        return path

    def findPage(self, path):
        try:
            if(path[-1] == '/'): # path is a directory, return index.html if found.
                path += 'index.html'
            f = open('./' + path, 'r')
            page = f.read()
            f.close()
        except Exception, e:
            print e
            return ('404 Not Found!')
        return page

class EchoFactory(protocol.Factory):
    def buildProtocol(self, addr):
        return Echo()
    def serverConncectionLost(self, connnector, reason):
        print "http server connection lost: return to listen"

def main():
    #endpoint = GateServerEndpoint.CreateFromConfig(reactor, 101, "gatekey1", networkStack=KissProtocol)
    endpoint = GateServerEndpoint.CreateFromConfig(reactor, 101, "gatekey1", networkStack=RipStack)
    endpoint.listen(EchoFactory())
    reactor.run()

if __name__ == '__main__':
    main()