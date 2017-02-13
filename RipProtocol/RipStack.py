from twisted.internet.protocol import Factory
from playground.network.common.Protocol import StackingFactoryMixin

from RipProtocol.RipClient import RipClientProtocol
from RipProtocol.RipServer import RipServerProtocol

class RipServerFactory(StackingFactoryMixin, Factory):
    protocol = RipServerProtocol

class RipClientFactory(StackingFactoryMixin, Factory):
    protocol = RipClientProtocol

ConnectFactory = RipClientFactory
ListenFactory = RipServerFactory

"""

Future cooperators,

    This is the inheritance relation of RipProtocol modules.

    I'm go to add more functions into "RipClient.py" and "RipServer.py".

    All the functions should be add into level 3.
    That means most cases you won't need to change level 1, 2, 4.

    Similar or same functions will be extracted as modules of level 2.


                        +---------------+
    Level 1             | RipMessage.py |
                        +---------------+
                                |
                                |
                                |
                       +-----------------+
    Level 2            | RipTransport.py |  ... more function modules here.
                       +-----------------+
                            |       |
                            |       |
                            |       |
                    +-------+       +-------+
                    |                       |
                    |                       |
            +--------------+         +--------------+
    Level 3 | RipServer.py |         | RipClient.py |
            +--------------+         +--------------+
                    |                       |
                    |                       |
                    +-------+       +-------+
                            |       |
                            |       |
                            |       |
                         +-------------+
    Level 4              | RipStack.py |
                         +-------------+
"""