from RipProtocol.RipMessage import RipMessage
from playground.network.message.ProtoBuilder import MessageDefinition

from CertFactory import getCertsForAddr, getPrivateKeyForAddr, getRootCert
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from playground.crypto import X509Certificate



def generateClientCertificate(addr, nonce):
    chain = [nonce]
    chain += getCertsForAddr(addr)
    return chain

def generateServerCertificate(addr, nonce1, nonce2):
    chain = [str(nonce2)]
    chain += getCertsForAddr(addr)
    chain += [str(int(nonce1) + 1)]
    return chain

def generateSignature(addr, data):
    PrivateKeyBytes = getPrivateKeyForAddr(addr)
    PrivateKey = RSA.importKey(PrivateKeyBytes)
    Signer = PKCS1_v1_5.new(PrivateKey)
    hasher = SHA256.new()
    hasher.update(data)
    signatureBytes = Signer.sign(hasher)
    return signatureBytes

def verification(nonce, msg):
    signatureBytes = msg.Signature
    certChain = msg.Certificate

    '''  Step 1: verify nonce
    '''
    if nonce != 0: # client mode
        # Verify nonce + 1
        noncePlus1 = certChain[3]
        if (int(noncePlus1) != int(nonce + 1)):
            return False
    if nonce == 0: # server mode
        # server no need to check nonce1 when first receive snn
        pass

    '''  Step 2: verify certificate chain

    For client, cert is server public key signed by server-self
    For server, cert is client public key signed by client-self
    '''
    cert = X509Certificate.loadPEM(certChain[1])
    CAcert = X509Certificate.loadPEM(certChain[2])
    rootCert = X509Certificate.loadPEM(getRootCert())

    if(CAcert.getIssuer() != rootCert.getSubject()):
        return False
    if(cert.getIssuer() != CAcert.getSubject()):
        return False

    '''  Step 3: verify Signature
    '''
    publicKeyBlob = cert.getPublicKeyBlob()
    publicKey = RSA.importKey(publicKeyBlob)
    rsaVerifier = PKCS1_v1_5.new(publicKey)
    hasher = SHA256.new()
    msg.Signature = ""
    bytesTobeVerified = msg.__serialize__()

    hasher.update(bytesTobeVerified)
    result = rsaVerifier.verify(hasher, signatureBytes)
    print "Rip HandShake verification result:" + str(result)
    return result



















