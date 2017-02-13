from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.StandardMessageSpecifiers import BOOL1, \
    STRING, UINT2, UINT4, LIST, DEFAULT_VALUE, OPTIONAL

"""
        Define Rip Message Body
"""

class RipMessage(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "RipTestProtocol.RipTestStack.RipMessage"
    MESSAGE_VERSION = "1.0"
    BODY = [
        ("ACK", BOOL1, DEFAULT_VALUE(False)),
        ("SNN", BOOL1, DEFAULT_VALUE(False)),
        ("CLS", BOOL1, DEFAULT_VALUE(False)),
        ("Signature", STRING, DEFAULT_VALUE("")),
        ("Certificate", LIST(STRING), OPTIONAL),
        ("Data", STRING, DEFAULT_VALUE(""))
    ]

    '''

           Part I: Rip Message field need to be finished

           BODY = [

              [("sequence_number", UINT4),
              ("acknowledgement_number", UINT4, OPTIONAL),
              ("sessionID", STRING),
              ("reset_flag", BOOL1, DEFAULT_VALUE(False)),
              ("OPTIONS", LIST(STRING), OPTIONAL)

           ]
    '''
   #==========================================================
    '''

                    Part II: State Machine

                         Rip Client


 +-------+                     +-----------+
 | CLOSE | ---- send SNN ----> | SNN  SENT |
 +-------+                     +-----------+
                                     |
                                     |
                                 received
                                  SNN/ACK
                                     |
                                     |
                                +-----------+
                          +---- | ESTABLISH | ----+
                          |     +-----------+     |
                          |                       |
                       received                  send
                         CLS                     CLS
                          |                       |
                          |                       |
                    +----------+             +----------+
                    | CLS_RCVD |             | CLS_SEND |
                    +----------+             +----------+
                          |                       |
                          |                       |
                        send                   received
                       ACK/CLS                 ACK/CLS
                          |                       |
                          |                       |
                          |      +---------+      |
                          +----- |  CLOSE  | -----+
                                 +---------+



                        Rip Server


 +--------+                         +-----------+
 | LISTEN | ---- received SNN ----> | SNN  RCVD |
 +--------+                         +-----------+
                                          |
                                          |
                                       received
                                         ACK
                                          |
                                          |
                                    +-----------+
                              +---- | ESTABLISH | ----+
                              |     +-----------+     |
                              |                       |
                           received                  send
                             CLS                     CLS
                              |                       |
                              |                       |
                        +----------+             +----------+
                        | CLS_RCVD |             | CLS_SEND |
                        +----------+             +----------+
                              |                       |
                              |                       |
                            send                   received
                           ACK/CLS                 ACK/CLS
                              |                       |
                              |                       |
                              |      +---------+      |
                              +----- |  CLOSE  | -----+
                                     +---------+

    '''
    #==========================================================
    '''
                Part III: Authentication Process

    private key:                    20164.0.0.1.pem
    public key:                     20164.0.0.1.csr
    self-certificate:               20164.0.0.1.cert
    certificate signed by Prof:     CA.cert
    root certificate:               root.cert

        Certificate Chain:

        Client  -------   send SNN message   ------->  Server

                        +------------------+
                        | 20164.0.0.1.cert |
                        +------------------+
                        |     CA.cert      |
                        +------------------+
                        |    root.cert     |
                        +------------------+


        Client  <------- send SNN/ACK message -------  Server

                        +------------------+
                        | 20164.0.0.2.cert |
                        +------------------+
                        |     CA.cert      |
                        +------------------+
                        |    root.cert     |
                        +------------------+

    '''

