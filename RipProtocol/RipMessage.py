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
        ("Signature", STRING, DEFAULT_VALUE("")),
        ("Certificate", LIST(STRING), OPTIONAL),
        ("Data", STRING, DEFAULT_VALUE(""))
    ]

    ''' Key Name Principles:

    private key:                    20164.0.0.1.pem
    public key:                     20164.0.0.1.csr
    self-certificate:               20164.0.0.1.cert
    certificate signed by Prof:     CA.cert
    root certificate:               root.cert

        Certificate Chain:

            Me  -------    send message   ------->  someone else

                        +------------------+
                        | 20164.0.0.1.cert |
                        +------------------+
                        |     CA.cert      |
                        +------------------+
                        |    root.cert     |
                        +------------------+
    '''

    '''
               Rip Message field need to be finished

           BODY = [

              [("sequence_number", UINT4),
              ("acknowledgement_number", UINT4, OPTIONAL),
              ("sessionID", STRING),
              ("close_flag", BOOL1, DEFAULT_VALUE(False)),
              ("reset_flag", BOOL1, DEFAULT_VALUE(False)),
              ("OPTIONS", LIST(STRING), OPTIONAL)

           ]
    '''