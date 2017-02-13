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
        ("RST", BOOL1, DEFAULT_VALUE(False)),
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
              ("OPTIONS", LIST(STRING), OPTIONAL)

           ]
    '''
    '''
        RIP 1                                                        RIP 2
       SNN-SENT ----->      [SEQ:460,SNN ,Nonce1, certs] ----->     SNN-RECV

       ESTABLISHED <----- [SEQ:300, ACK:461, SNN,  ACK,
                           Nonce2, Signed(Nonce1+1), certs] <----   SNN-RECV

       ESTABLISHED -----> [SEQ:461, ACK:301, ACK,
                                       Signed(Nonce2)]  ----->      ESTABLISHED
   '''
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

