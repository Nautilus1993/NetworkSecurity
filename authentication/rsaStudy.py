from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from random import randint
from playground.crypto import X509Certificate

import os

#=========     Part1. Sign (by private key)      =========#

'''
    Step1. load privatekey from <.pem> file, generate signer
'''

with open("./clientkey/client.pem", 'r') as f:
    rawkey = f.read()
rsaKey = RSA.importKey(rawkey)
rsaSigner = PKCS1_v1_5.new(rsaKey)

'''
    Step2. using signer get the signature of data.
'''

data = "Test data for signing"
print "data before sign: " + data
hasher = SHA256.new()
hasher.update(data)
signatureBytes = rsaSigner.sign(hasher)

#=========   Part2. Verification (by public key)   =========#

'''
    Step1. load public key from <.csr> file, generate verifier
'''

with open("./clientkey/client.cert", 'r') as f:
    certBytes = f.read()
cert = X509Certificate.loadPEM(certBytes)
publicKeyBlob = cert.getPublicKeyBlob()
publicKey = RSA.importKey(publicKeyBlob)
rsaVerifier = PKCS1_v1_5.new(publicKey)

'''
    Step2. Verify signature
'''
#data = "data from evil"
hasher = SHA256.new()
hasher.update(data)
result = rsaVerifier.verify(hasher, signatureBytes)
print "verification result : " + str(result)


#============   Part3. Certificate Chain   ============#

'''
    Step1. generate certificate chain
'''

chain = []
nonce = randint(0, 10000)
chain.append(nonce)
with open("./clientkey/client.cert", 'r') as f:
    chain.append(f.read())
with open("./clientkey/CA.cert", 'r') as f:
    chain.append(f.read())
with open("./clientkey/root.cert", 'r') as f:
    chain.append(f.read())

'''
    Step2. verify certificate chain
    (Real Rip certificate chain doesn't include root.cert)
'''

nonce = chain[0]
clientCertBytes = chain[1]
CACertBytes = chain[2]
rootCertBytes = chain[3]

clientCert = X509Certificate.loadPEM(clientCertBytes)
CACert = X509Certificate.loadPEM(CACertBytes)
rootCert = X509Certificate.loadPEM(rootCertBytes)

# verify certificate chain step by step
if (CACert.getIssuer() != rootCert.getSubject()):
    print "False"

if (clientCert.getIssuer() != CACert.getSubject()):
    print "False"

#============   Part4. Certificate Factory   ============#
def getCertsForAddr(addr):
    # define the file name of private key, public key, self_signed certificate.
    privateKeyFile = addr + ".pem"
    publicKeyFile = addr + ".csr"
    certificateFile = addr + ".cert"
    intermidiateCAFile = "Yuhang_signed.cert"

    # construct the command lines
    generatePrivateKey = "openssl genrsa -out " + privateKeyFile + " 2048"
    generatePublicKey = "openssl req -new -key " + privateKeyFile + " -out " + publicKeyFile
    generateCertificate = "openssl x509 -req -days 360 -in " + publicKeyFile \
                          + " -CA " + intermidiateCAFile + " -CAkey " + privateKeyFile \
                          + " -out " + certificateFile + " -set_serial " + str(randint(0,1000))

    # execute the command lines in shell
    os.system(generatePrivateKey)
    os.system(generatePublicKey)
    os.system("US")

def main():
    addr = "20164.1.1936.123" # test playground address
    getCertsForAddr(addr)

if __name__ == '__main__':
    main()