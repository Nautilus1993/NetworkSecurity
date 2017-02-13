from twisted.internet.protocol import connectionDone
from playground.network.common.Protocol import StackingTransport
from playground.playgroundlog import packetTrace, logging
from playground.error import GetErrorReporter

logger = logging.getLogger(__name__)
errReporter = GetErrorReporter(__name__)

class RipTransport(StackingTransport):
    def __init__(self, lowerTransport, lowerProtocol):
        StackingTransport.__init__(self, lowerTransport)
        self.lowerProtocol = lowerProtocol

    def write(self, data):
        self.lowerProtocol.dataSend(data)

    def lostConnection(self):
        self.lowerProtocol.loseConnection()