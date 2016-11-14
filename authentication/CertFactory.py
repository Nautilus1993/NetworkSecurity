from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA



# addr should be current connection peer address like: 20164.1.1936.123
def getPrivateKeyForAddr(addr):
    with open("./private.pem", 'r') as f:
        addrPrivateKey = RSA.importKey(f.read())
        addrSigner = PKCS1_v1_5.new(addrPrivateKey)
    return addrSigner

def getCertsForAddr(addr):
    # 1) generate private key for that addr 20164.1.1936.123 --> new.pem
    # 2) generate new.csr (public key + request) for addr 20164.1.1936.123 --> new.csr
    # 3) intermidiate CA Yuhang_signed.cert sign addr 20164.1.1936.123 --> new_signed.cert
    # 4) construct certificate chain: [new_signed.cert, Yuhang_signed.cert]


    chain = []
    with open("./new.cert", 'r') as f:
        chain.append(f.read())

    with open("./Yuhang_signed.cert", 'r') as f:
        chain.append(f.read())

    print "CertFactory: certificate chain: " + chain
    return chain

def getRootCert():
    with open("./20164_signed.cert", 'r') as f:
        return f.read()
