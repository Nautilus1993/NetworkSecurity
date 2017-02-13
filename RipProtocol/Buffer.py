from playground.network.common.Packet import Packet, PacketStorage, IterateMessages
from playground.network.message.StandardMessageSpecifiers import BOOL1, \
    STRING, UINT2, UINT4, LIST, DEFAULT_VALUE, OPTIONAL

from random import randint

from RipProtocol.RipMessage import RipMessage
from playground.network.common.Timer import OneshotTimer, callLater

class bufferEntity(object):
    def __init__(self, msg, callLater):
        self.msg = msg
        self.timer = OneshotTimer(callLater)

'''
For each entity in buffer (both sending and receiving buffer)
it includes:

    1. Massage. (need to be send or already received)
    2. Timer.
    3. Callback (if timer is timeout what to do next)

Both send buffer and receive buffer will maintain a
list of Buffer Entities.
'''
class RipMsgBuffer(object):
    def size(self):
        pass
    def append(self, buf):
        pass
    def remove(self, index):
        pass

class SendBuffer(object):

    def __init__(self):
        self.bufQueue = []

    # append function will return current buf index
    # for later remove it from buf queue
    def append(self, buf):
        self.bufQueue.append(buf)
        return len(self.bufQueue) - 1



