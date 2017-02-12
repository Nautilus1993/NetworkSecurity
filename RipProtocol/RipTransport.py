from playground.network.common.Protocol import StackingTransport
from playground.playgroundlog import packetTrace, logging
from playground.error import GetErrorReporter

logger = logging.getLogger(__name__)
errReporter = GetErrorReporter(__name__)

class RipTransport(StackingTransport):
    def __init__(self, lowerTransport, protocol):
        StackingTransport.__init__(self, lowerTransport)
        self.protocol = protocol

    def write(self, data):
        #print "Rip Transport: write data to lower layer -- " + data
        self.protocol.dataSend(data)