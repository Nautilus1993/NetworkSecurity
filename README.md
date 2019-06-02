

##  1. Introduction

   The Reliable Interaction Protocol (RIP) provides a method of
   transmitting packets of data between hosts, identified by a session.
   The data transmitted is guaranteed to be received without errors, in
   the order it was sent.  In order to ensure the sender's identity,
   signatures will be passed in the messages

   This document defines the functions that comprise the protocol, the
   requirements of the program that implements it and the interfaces
   necessary to use the protocol.  Here packet refers to the data of one
   transaction between a network and its host.

   This protocol is based on the Transmission Control Protocol (TCP),
   RFC 793 [RFC0793].  It is designed to correspond to the forth
   transport layer in the OSI Model, shown in figure 1.  The third
   Network layer provides a way for RIP to send packets across the
   network.  Like TCP, the underlying connection is not assumed to be
   reliable.

                       +---------------------+
                       |   7. Application    |
                       +---------------------+
                       |   6. Presentation   |
                       +---------------------+
                       |      5. Session     |
                       +---------------------+
                       |  4. Transport (RIP) |
                       +---------------------+
                       |      3. Network     |
                       +---------------------+
                       |    2. Data Link     |
                       +---------------------+
                       |    1. Physical      |
                       +---------------------+

                             Figure 1

## 2. Operation

   To provide a service on top of an unreliable internet we need to
   focus on the following areas: Basic Data Transfer, Reliability, and
   Connections

### 2.1 Basic Data Transfer

   The data will be transferred via a continuous stream of packets that
   can flow in either direction.  In general, RIP will transfer packets as soon as it is able.

### 2.2 Reliability

   RIP MUST be able to handle the loss, damage, duplication, or
   reordering of data that may occur due to the unreliable internet
   connection.

   RIP MUST assign a sequence number to each packet transmitted in order
   to detect packet loss, duplication, and reordering.  The receiver
   MUST send an acknowledgment if it has received all packets up to the
   sequence number.  If the receiver detects that there is a missing
   packet, it MUST send a packet request to the transmitter.  If the
   transmitter receives a packet request or does not receive an
   acknowledgment in a specified timeout period, it SHALL resend the
   packet.

   In order to detect if the packets were damaged, or send by someone
   other than the expected sender, a signature SHALL be created from a
   hash of the message.  When the receivers get a message, it MUST first
   check the signature.  If the signature is not what is expected, it
   MUST discard the packet and wait for the resend.

###2.3 Connections

   Each connection SHALL be identified by a pair of sockets.  In order
   to initialize the connection between two sockets, a handshake
   procedure MUST be followed.  This will ensure that both sides are
   able to to authenticate and connect as well as allowing the
   initialization of status information.

### 2.4 Interface

   The RIP user interface provides calls to open or close a connection,
   send messages, and get status information for an open connection.



## 3.  Specifications


### 3.1.  Messages

   A message MUST contain the following elements:

	   PLAYGROUND_IDENTIFIER = "RIP.RIPMessageID"
	
	   MESSAGE_VERSION = "1.0"

	   BODY = [
	
	      [("sequence_number", UINT4),
	
	      ("acknowledgement_number", UINT4, OPTIONAL),
	
	      ("signature", STRING, DEFAULT_VALUE("")),
	
	      ("certificate", LIST(STRING), OPTIONAL),
	
	      ("sessionID", STRING),
	
	      ("acknowledgement_flag", BOOL1, DEFAULT_VALUE(False)),
	
	      ("close_flag", BOOL1, DEFAULT_VALUE(False)),
	
	      ("sequence_number_notification_flag", BOOL1,
	      DEFAULT_VALUE(False)),
	
	      ("reset_flag", BOOL1, DEFAULT_VALUE(False)),
	
	      ("data", STRING,DEFAULT_VALUE("")),
	
	      ("OPTIONS", LIST(STRING), OPTIONAL)
	
	   ]

#### 3.1.1.  Sequence Number

   The sequence number of the first data in the message.  If the
   Sequence Number Notification Flag is set, this field contains the
   initial sequence number (ISN).  The sequence number increases by the
   size of the data field for each message sent.  If the data field is
   empty it increases the sequence number by 1.

#### 3.1.2.  Acknowledgement Number

   This field contains the next sequence number that the sender expects
   to receive.  The acknowledgements are cumulative, meaning that
   acknowledging a sequence number also acknowledges any preceding sequence numbers.

#### 3.1.3.  Signature

   The signature field is the signed(the sender's private key) hash of
   the entire message not including the signature field.  To create the
   signature, the message should be created with all data, except the
   signature field should be set to the empty string.  This message is
   then hashed and signed.  The resulting signature should be placed in
   the signature field and sent.

#### 3.1.4.  Certificate

   This field is only used in the handshake procedure.  The first
   element in this list would correspond to a Nonce value and the second
   element would correspond to the sender's certificate (eg A.B.C.D) and
   and the third element in the list would corresponds to the
   Intermediate CA's certificate (eg.  A.B.C), etc.  If both a signed
   nonce and a clear nonce need to be sent, the clear nonce should be
   sent followed by the signed nonce, followed by any certificates.

#### 3.1.5.  Session ID

   The session ID will be the concatenated string "Nonce1Nonce2" for the
   client and "Nonce2Nonce1" for the server.

#### 3.1.6.  Acknowledgement Flag

   If the Acknowledgement Flag is set, this signifies that this is an
   acknowledgement message.

#### 3.1.7.  Close Flag

   If the Close Flag is set, this indicates that the sender has no more
   data to send and wishes to close the connection.

#### 3.1.8.  Sequence Number Notification Flag

   If the Sequence Number Notification Flag is set, the sender is
   notifying the receiving RIP of its initial sequence number (ISN),
   which is found in the Sequence Number.  This flag is only used during
   a handshake procedure.

#### 3.1.9.  Reset Flag

   If the Reset Flag is set, the sender received two conflicting
   Sequence Number Notifications and wants to restart the handshake
   procedure.


#### 3.1.10.  Options

   The options are a list of strings that, if included in the list, have
   the following meanings:

   + "Recover": If "Recover" is included in the options, the sender is
      recovering from a crash or connection loss.  It is trying
      reestablish the connection.  The receiver SHALL send the last
      arrived sequence number in the acknowledgement number field with
      both the acknowledgement and recover flags set.  If the
      acknowledgement is set and "Recover" is included in the options,
      this informs RIP of its last known sequence number.  For more
      information, see the reconnect section.

  + "RequestPacket": If "RequestPacket" is included in the options,
      the sender is missing an intermediate packet.  The receiver MUST
      resend the unacknowledged message with the lowest sequence number.

### 3.2.  Connections

   RIP provides full-duplex service between two hosts.  Since one RIP
   can have multiple connections, it must have some way of identifying
   connections.  RIP provides a point-to-point connection; therefore, a
   connection can be uniquely identified based on the two hosts.  In
   order to provide unique identifiers, a host is known by its internet
   address concatenated with its RIP port.  Each RIP will keep track of
   its open connections via a control block.  Each cell in the control
   block will keep data about one connection.  This data SHALL include
   the address and port of the other process, the local connection
   identifier, and the local port number.

#### 3.2.1.  Open

   When a host opens a connection, it has the choice of becoming an
   active open request or a passive open request.  If the host chooses a
   passive open request, it will wait to obtain an incoming connection
   request.  The host can also choose to specify a foreign socket,
   indicating that it is waiting for a specific host.  Conversely, the
   host can choose to specify an active open request and a required
   foreign socket.  In this case, RIP will look for another active open
   request with the same foreign socket, a passive request with the same
   foreign socket, or a passive request with no foreign socket
   specified, respectively.

   Once two open requests from two RIPs are matched to each other, a
   three-way handshake procedure is followed as outlined in the
   authentication section.  Once the is established and the connection
   MUST be added to RIP's respective control blocks.
In some cases, it may be possible that two conflicting SNNs are
   received by RIP.  In this case RIP MUST respond with an reset
   message.  This will return the sending RIP to return to a LISTEN
   state and the handshake procedure can be restarted.  This typically
   occurs due to a crash, as discussed in the following section.

##### 3.2.1.1.  Authentication

   Authentication is guaranteed in this layer by employing certificate
   chaining in the initial handshake.  The RIP1 sends a nonce (say
   Nonce1), the certificate chain.  The sequence number and the SNN flag
   are also set in this initial exchange.

   RIP2 MUST set it to (Nonce1 + 1).  Then the RIP2 sends (Nonce1 + 1)
   signed with its private key, and it's certificate chain.  In addition
   to this the RIP2 also sends a nonce (say Nonce2).  In the final
   handshake the RIP1 sends an ACK to the RIP2 with (Nonce2 + 1) signed
   with it's private key.  This process is shown in figure 2.  If at any
   time the authentication of the certificates fails or the nonce is not
   correctly encoded, a reset message should be sent and the handshake
   should be restarted.
		
		   RIP 1                                                   RIP 2
		   1. SNN-SENT -->      [SEQ:460,SNN ,Nonce1, certs] -->SNN-RECV
		   2. ESTABLISHED <-- [SEQ:300, ACK:461, SNN,  ACK,
		                 Nonce2, Signed(Nonce1+1), certs] <-- SNN-RECV
		   3. ESTABLISHED --> [SEQ:461, ACK:301, ACK,
		                                   Signed(Nonce2)]--> ESTABLISHED
		
		                               Figure 2

   To prevent a replay attack a session ID variable is set using the the
   two nonces, as specified in the message definition.

   The certificates are verified in the following manner:

   a. 20164.1.100.10 receives a packet from 20164.1.100.20.  This packet
   has 2 certificates in it (20164.1.100.20 and 20164.100's certificate)

   b. 20164.1.100.10 checks the first certificate(second element in the
   list) and avails its subject name.  He checks if this subject name
   matches the source IP address of the packet.  If yes, go to step c

   c. 20164.1.100.10 would avail the public key from 20164.1.100's
   certificate.  He also avails the subject name of 20164.1.100's
   certificate and verifies that it is the one signing 20164.1.100.20

   d. 20164.1.100.10's would validate the first certificate using



Coston                       Standards Track                    [Page 8]

RFC 1                           RIP PRFC                    October 2016


   20164.1.100's public key availed in step c

   e.  Similarly, he verifies if 20164.1.100's certificate is signed by
   the root as 20164.1.100.10 has root's public key.

#### 3.2.2.  Reconnect

   In the case of one side of the connection crashes or loses
   connection, it will automatically restart and try to re-establish any
   lost connections, provided the control block was not lost.  RIP, will
   then be in RECOVERY state.  For each connection in control block, RIP
   MUST send a recovery message.  Upon receipt of the recovery message
   RIP will move to the LISTEN state and send a recovery acknowledgement
   and the last known sequence number of the recovered RIP.  The
   recovered RCP MUST then begin the handshake procedure, choosing a new
   initial sequence number that is sufficiently far away from its
   previous sequence number.  This will avoid any messages from being
   sent that have the same number as a message that was sent just prior
   to the crash.  The two RIPs must repeat the authentication steps.

   If RIP tries to send a message to a machine that has crashed or lost
   its connection, it MUST receive an error message and move to the
   RECOVERY state.  It MUST then begin a timeout timer.  If RIP does not
   receive a recovery message from the crashed or lost RIP within the
   timeout period, it SHALL move to the LISTEN state.  Otherwise, it
   will follow the procedure above.

##### 3.2.3.  Close

   If a host has no more information to send, it SHALL send a close
   message.  However, the connection is only closed if the other side
   sends an acknowledgement to the close message.  RIP SHOULD resend all
   unacknowledged messages, and ensure that they are received before
   closing.  There are two cases in which a close may occur: the local
   user initiates the close, RIP receives an uninitiated close message

   In the case where the local user(say RIP1) initiates the close, RIP1
   MUST send a close message and transfer to the CLOSE-REQ state.  RIP1
   will no longer be able to send any new messages, but SHALL re-send
   all unacknowledged messages, and ensure that they are received before
   closing.  The other RIP(say RIP2) will transfer to the CLOSE-RCVD
   state and MUST send an acknowledgement to all the packets received to
   close the connection.  Once RIP1 has received the acknowledgement the
   connection MUST be closed.

   If RIP2 receives an uninitiated close message, it MUST wait to
   acknowledge the close until all previous messages have been received
   and is transfered to the CLOSE-RCVD state.  Once RIP2 acknowledges the close message, the connection MUST be closed.

   If both RIPs send the close message simultaneously, once a close
   acknowledgement is received it MUST close the connection.

### 3.3.  Data Transmission

   Both sending and receiving RIPs must follow a protocol, defined below
   to ensure that it will be able to handle loss, damage, duplication,
   or reordering of data.  Since RIP is a full-duplex, it must be able
   to act as both a sending and receiving RIP.  For simplicity they are
   described separately.

#### 3.3.1.  Sending

   In order to send data with RIP, the calling process must provide
   buffers of data.  RIP MUST then segment these buffers into packets,
   adding a sequence number and a signature.  RIP MUST then call the
   underlying Network layer to transmit the packet to the receiving RIP.
   RIP SHALL then place the transmitted packet into a resending buffer
   until it receives an acknowledgement from the receiving RIP.  If the
   sending RIP does not receive an acknowledgement from the receiving
   RIP in the specified timeout period or it receives a request packet
   from the receiving RIP, then it MUST resend the packet.  The resent
   packet SHALL remain in the resend buffer until an acknowledgement is
   received.


      nextSeqNum = initialSeqNum
      ackSeqNum = null

      while true:
         switch(event):
            event1: data y received from calling process
               #create RIP packet
               packet.data = y
               packet.sequenceNum = nextSeqNum
               packet.signature = packet.sign()
               timeoutTimer.start()
               nextSeqNum = nextSeqNum + len(packet.data)
               retransmitBuff.add(packet)
               break

            event2: timeoutTimer reaches 0
               retransmit packet with smallest unacknowledged sendSeq
               timeoutTimer.start()
               break

            event3: retransmit packet received
               retransmit packet with smallest unacknowledged sendSeq
               timeoutTimer.start()
               break

            event4: acknowledgement received with seqNum x
               ackSeqNum = x
               for packet in retransmitBuff:
                  if packet.sequenceNum < x:
                     retransmitBuff.remove(packet)
               if len(retransmitBuff) == 0:
                  timeoutTime.stop()


               Figure 3: Sending RIP pseudo code

#### 3.3.2.  Receiving

   Upon arrival the receiving RIP will place the packet into an incoming
   data buffer.  First the receiving RIP must check if this is a
   duplicate sequence number; if it is the newly arrived packet is
   discarded.  The receiving RIP MUST then check the signature and
   verify that the preceding packet has also arrived.  If the preceding
   packet has not arrived, then it will send a packet request to the
   sending RIP.  It will then wait to receive the preceding packet
   before acknowledging the later sequence numbered packet.  Next, the
   receiving RIP MUST notify sending RIP it has received the packet by
   sending an acknowledgement.  The acknowledgement does not mean that
   the end user has received the packet, only that the receiving RIP has
   taken responsibility of the packet.  Finally, the receiving RIP
   notifies the user of the packet.  This process is shown in Figure 4.
   Note that this does not include specialized messages (acknowledge,
   request packet, etc).

   The RIP MUST set a transfer window size.  This specifies the number
   of messages it will receive before sending an Acknowledgement.  This
   MUST be in the range of 1 to 20, with the recommended value of 5.


       nextSeqNum = initialSeqNum
       waitingList = []

       while true:
           switch(event):
               event1: packet y received from sending RIP
                   incomingBuffer.add(y)
                   if duplicate(y)
                       incomingBuffer.discard(y)
                       break
                   if verifySignature(y):
                       if y.sequenceNum > nextSeqNum:
                           sendPacketRequest()
                           #Packets are added to the waiting list in
                           #order by sequence number
                           waitingList.addInOrder(y)
                           break
                       else:
                           nextSeqNum = nextSeqNum + len(y.data)
                           while len(waitingList) > 0:
                               p = waitingList.getNext()
                               if p.sequenceNum > nextSeqNum:
                                   sendPacketRequest()
                                   break
                               else:
                                   nextSeqNum = nextSeqNum + len(p.data)
                                   waitingList.remove(p)
                           sendAcknowledgement(nextSeqNum)
                           notifyUser(nextSeqNum)
                           break

                       else:
                           sendPacketRequest()
                           break


               Figure 4: Simplified Receiving  RIP pseudo code

### 3.4.  User Interface

   RIP MUST provide the following functions to its calling process:
   open, close, send, and status.

#### 3.4.1.  Open

   The open function follows the procedure outlined in section 2.1.1 and
   MUST have the following parameters:

   + local port: The local port of the connection

   + foreign socket: The address of the connection we want to obtain,
   + optional unless connection type is set to active

   + connection type: specifies if the connection should be active or passive

   + receive buffer: an area in memory to store incoming messages

   + (timeout period (optional): the user can specify how long they are
   + willing to wait for the connection, if none is specified RIP
   + default will be used

   The function SHALL return local connection name, pointer to entry in
   the control block.

#### 3.4.2.  Close

   The status function SHALL have one parameter, local connection.  RIP
   MUST send a close message on the specified connection.

#### 3.4.3.  Send

   The send function follows the procedure outlined in section 2.3.1.
   If no connection is open, calling send is considered an error.  Send
   MUST have the following parameters:

   + control block pointer: pointer to the connection to use

   + buffer address: pointer to the data to send

   + length: the length of the data to send

   + timeout period (optional): the time until resend, if none is
   + specified RIP default will be used

#### 3.4.4.  Status

   The status function SHALL have one optional parameter, local
   connection.  If there is a parameter, it MUST return the data in the
   corresponding control block entry in a human-readable format.
   Otherwise, it MUST return the elements of the control block in a
   human-readable format.


## 4.  Allowable States and Transitions

   The connection will progress through a series of states.  RIP MUST
   have the following states: CLOSED, LISTEN, SNN-SENT, SNN-RECEIVED,
   ESTABLISHED, RECOVER, CLOSE-REQ, CLOSING

### 4.1.  Closed

   This represents state in which either a host that has terminated the
   connection or currently has no connection.

### 4.2.  Listen

   This represents a host that is waiting for a connection from a remote
   RIP and port.

### 4.3.  SNN-Sent

   This represents a host that is waiting for a SNN acknowledgement and
   a SNN from a remote RIP.

### 4.4.  SNN-Received

   This represents a host that is waiting for a SNN acknowledgement
   after having both sent and received a SNN from a remote RIP.

### 4.5.  Established

   This represents an open connection after the handshake is completed.
   It is expected that the connection will be in this state for most of
   its lifetime.  Data can now be exchanged with the remote RIP.

####4.6.  Close-Requested

   This represents a host that has sent the close request to the remote
   RIP.

### 4.7.  Close-Received

   This represents a receiver after it has received the close request
   from the RIP.

### 4.8.  State Diagram



		                       _active open_______.
		                      |                   |
		                      V      close     +------+
		               +--------+  .---------->|CLOSED|
		          .--->|SNN-SENT|--|           +------+
		          |    +--------+              ^ close|passive
		          |      |   | ^               |      |open
		    recv  |  recv|   | | send SNN      |      V
		   recover|  SSN,|   | .------------.  +------+
		    send  |   AWK|   |              |--|LISTEN|
		     SSN  |      |   |                 +------+
		     AWK  |      |   |                    |recv SNN, send
		          |      |   |                    |AWK,SSN
		          |      |   |                    V
		          |      |   |recv SSN, send AWK +-----+
		          |      |   .------------------>|SSN- |
		          |      |  .--------------------|RECV |
		          |      V  V   recv AWK of SSN  +-----+
		          |   +-----+                       ^ recv AWK
		          .---|ESTAB|-----------------.     |
		       +------+-----+                 |  +-------+
		       |         |send close          .->|RECOVER|
		   rcv |         |request                +-------+
		   close         V
		   req |     +------+ recv close req, ACK
		       |     |CLOSE-|------------------------+
		       |     |REQ   |                        |
		       |     +------+                        |
		       V                                     |
		       +-----------+                         |
		       |CLOSE-RCVD |                         V
		       +-----------+  send  close req, ACK +------+
		             +---------------------------->|CLOSED|
		                                           +------+

## 5.  Allowable Configurations

   The timeout period SHOULD be set to a reasonable amount of time based
   on the connection speed of the network.  If the timeout is too long
   the user will experience data lags; however, if the timeout is too
   short RIP will unnecessarily resend messages, causing network
   congestion.

   RIP SHOULD have a large number of possible sequence numbers, so that
   many messages can be sent and acknowledged before sequence numbers
   begin to repeat.


## 6.  Security Considerations

   RIP is vulnerable to man-in-the-middle attacks.  In this type of
   attack, a third-party sits between the two hosts and intercepts
   messages between them.  The third party can then send messages,
   impersonating one or both of the hosts.  In order to mitigate these
   risks a secure socket layer (SSL) SHOULD be implemented.  This
   requires a modified handshake as described in RFC 6101 [RFC6101].


