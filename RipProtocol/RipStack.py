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

    This is the inheritance relation of RipProtocol module.

    I'm going to add more functions into "RipClient.py" and "RipServer.py".
    Same functions will be extracted as new modules, at the same level with
    "RipTransport.py."

    Most cases you don't need to change level 1, 2, 4.
    All the functions should be add into level 2.


                        +---------------+
                        | RipMessage.py |
                        +---------------+
                                |
                                |
                                |
                       +-----------------+
                       | RipTransport.py |  ... more function modules here.
                       +-----------------+
                            |       |
                            |       |
                            |       |
                    +-------+       +-------+
                    |                       |
                    |                       |
            +--------------+         +--------------+
            | RipServer.py |         | RipClient.py |
            +--------------+         +--------------+
                    |                       |
                    |                       |
                    +-------+       +-------+
                            |       |
                            |       |
                            |       |
                         +-------------+
                         | RipStack.py |
                         +-------------+
"""