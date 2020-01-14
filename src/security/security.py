import os
from os import listdir 
import sys
import base64
import hashlib
import json
import cryptography
import OpenSSL
from OpenSSL.crypto import load_certificate, load_crl, FILETYPE_ASN1, FILETYPE_PEM, Error, X509Store, X509StoreContext,\
    X509StoreFlags, X509StoreContextError
from cryptography.hazmat.primitives.asymmetric import padding as _paadding
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import random
import string

def get_algorithm_from_name(name):
    algs = {'AES':algorithms.AES,'Camellia':algorithms.Camellia,'TripleDES':algorithms.TripleDES,
            'CAST5':algorithms.CAST5,'SEED':algorithms.SEED, 'Blowfish':algorithms.Blowfish, 'IDEA':algorithms.IDEA}
    try:
        return algs[name]
    except KeyError:
        print('No algorithm with name %s found'%(name))
        return None

def get_mode_from_name(name):
    mds = {'CBC':modes.CBC,'OFB':modes.OFB,'CFB':modes.CFB}
    try:
        return mds[name]
    except KeyError:
        print('No mode with name %s found'%(name))
        return None

class SymmetricCipher:
    def __init__(self,algorithm='AES',mode='CBC'):
        self.key = None
        self.algorithm = get_algorithm_from_name(algorithm)
        self.mode = get_mode_from_name(mode)

    def generate_secret_key(self,pwd):
        if not pwd:
            raise Exception('SymmetricCipher object must have a valid pwd.')
        pwd = base64.b64decode(pwd)
        secretKey = pwd
        self.key = secretKey
        return secretKey

    def encrypt(self, cleartext):
        if not self.key:
            raise Exception('SymmetricCipher object has no secret key defined.')
        iv = os.urandom(self.algorithm.block_size//8)
        cipher = Cipher(self.algorithm(self.key), self.mode(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = cryptography.hazmat.primitives.padding.PKCS7(self.algorithm.block_size).padder()
        return base64.b64encode(iv+encryptor.update(padder.update( cleartext if isinstance(cleartext, bytes) else bytes(cleartext,'utf-8')) + padder.finalize())+encryptor.finalize()).decode('utf-8')

    def decrypt(self,ciphertext):
        if not self.key:
            raise Exception('SymmetricCipher object has no secret key defined.')
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:self.algorithm.block_size//8]
        ciphertext_text = ciphertext[self.algorithm.block_size//8:]
        cipher = Cipher(self.algorithm(self.key), self.mode(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = cryptography.hazmat.primitives.padding.PKCS7(self.algorithm.block_size).unpadder()
        plaintext = (unpadder.update(decryptor.update(ciphertext_text)+decryptor.finalize()) + unpadder.finalize())
        try:
            plaintext = plaintext.decode('utf-8') #If plaintext is a string
        except:
            plaintext = base64.b64encode(plaintext).decode('utf-8') #If plaintext is bytes encodes it to base64
        return plaintext

class RSACipher:
    def __init__(self):
        self.priv_key = None
        self.pub_key = None

    def generate_key_pair(self,pwd):
        if not pwd:
            raise Exception('RSACipher object requires a password to generate key pair.')
        # Use 65537(2^16 + 1) as public exponent
        #chosen 2048 for key_size since 1024 and below are considered breakable
        self.priv_key = rsa.generate_private_key( 65537 , 2048 , default_backend() )
        self.pub_key = self.priv_key.public_key()
        encoding_privkey = self.priv_key.private_bytes(serialization.Encoding.PEM,
                                                serialization.PrivateFormat.PKCS8,
                                                serialization.BestAvailableEncryption(pwd if isinstance(pwd, bytes) else bytes(pwd,
                                                "utf-8")))
        encoding_pubkey = self.pub_key.public_bytes(serialization.Encoding.PEM,
                                                    serialization.PublicFormat.PKCS1)
        key_pair = {
            'publicKey': base64.b64encode(encoding_pubkey).decode('utf-8'),
            'privateKey': base64.b64encode(encoding_privkey).decode('utf-8')
        }
        return key_pair

    def load_pub_key(self, pubk):
        if not pubk:
            raise Exception('RSACipher object requires a valid public key.')
        pubk = base64.b64decode(pubk)
        self.pub_key = serialization.load_pem_public_key(pubk, default_backend())

    def load_priv_key(self, privk, pwd):
        if not privk:
            raise Exception('RSACipher object requires a valid private key.')
        privk = base64.b64decode(privk)
        self.priv_key = serialization.load_pem_private_key(privk, bytes(pwd,"utf -8"), default_backend())

    def encrypt(self, cleartext):
        if not self.pub_key:
            raise Exception('RSACipher object public key cannot have value None.')
        # Calculate the maximum amount of data we can encrypt with OAEP + SHA256
        #maxLen = 190 bytes
        maxLen =( self.pub_key.key_size // 8) - 2 * hashes.SHA256.digest_size - 2
        if len(cleartext) > maxLen:
            raise Exception('Cannot cipher more than %d bytes. Cleartext has %d bytes.' % (maxLen,len(cleartext)))
        ciphertext = self.pub_key.encrypt( cleartext if isinstance(cleartext,bytes) else bytes(cleartext,'utf-8') ,
                                        cryptography.hazmat.primitives.asymmetric.padding.OAEP(
                                            cryptography.hazmat.primitives.asymmetric.padding.MGF1( hashes.SHA256() ) ,
                                        hashes.SHA256() , None ) )
        return base64.b64encode(ciphertext).decode('utf-8')

    def decrypt(self, ciphertext):
        if not self.priv_key:
            raise Exception('RSACipher object private key cannot have value None.')
        ciphertext = base64.b64decode(ciphertext)
        plaintext = self.priv_key.decrypt(ciphertext,
                                        cryptography.hazmat.primitives.asymmetric.padding.OAEP(
                                            mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None
                                        ))
        try:
            plaintext = plaintext.decode('utf-8') #If plaintext is a string
        except:
            plaintext = base64.b64encode(plaintext).decode('utf-8') #If plaintext is bytes encodes it to base64
        return plaintext

    def sign(self,message):
        if not self.priv_key:
            raise Exception('RSACipher object private key cannot have value None.')
        signature = self.priv_key.sign(
            data=message.encode('utf-8'),
            padding=cryptography.hazmat.primitives.asymmetric.padding.PSS(
                mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(hashes.SHA256()),
                salt_length=cryptography.hazmat.primitives.asymmetric.padding.PSS.MAX_LENGTH
            ),
            algorithm=hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    def verify(self,signature,original_message):
        if not self.pub_key:
            raise Exception('RSACipher object public key cannot have value None.')
        try:
            self.pub_key.verify(
                signature=base64.b64decode(signature),
                data=original_message.encode('utf-8'),
                padding=cryptography.hazmat.primitives.asymmetric.padding.PSS(
                    mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(hashes.SHA256()),
                    salt_length=cryptography.hazmat.primitives.asymmetric.padding.PSS.MAX_LENGTH
                ),
                algorithm=hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

class ECCipher:
    def __init__(self):
        self.priv_key = None
        self.pub_key = None

    def load_priv_key(self,privk):
        if not privk:
            raise Exception('RSACipher object requires a valid private key.')
        privk = base64.b64decode(privk)
        self.priv_key = serialization.load_pem_private_key(
            privk,
            password=None,
            backend=default_backend()
        )

    def generate_key_pair(self):
        self.priv_key = ec.generate_private_key(
            ec.SECP384R1(), default_backend()
        )
        self.pub_key = self.priv_key.public_key()
        encoding_privkey = self.priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        encoding_pubkey = self.pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_pair = {
            'publicKey': base64.b64encode(encoding_pubkey).decode('utf-8'),
            'privateKey': base64.b64encode(encoding_privkey).decode('utf-8')
        }
        return key_pair

    def derive_key(self,peer_public_key):
        peer_public_key = base64.b64decode(peer_public_key)
        peer_public_key = serialization.load_pem_public_key(
            peer_public_key,
            backend=default_backend()
        )
        shared_key = self.priv_key.exchange(ec.ECDH(), peer_public_key)
        # Perform key derivation.
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=None,
            backend=default_backend()
        ).derive(shared_key)
        return base64.b64encode(shared_key).decode('utf-8')

# cert = certificate; data = original data that was signed, signature = signed data
def verify_signed_certificate(cert, data, signature):
    cert = base64.b64decode(cert)
    data = bytes(data,'utf-8')
    signature = base64.b64decode(signature)
    cert = x509.load_pem_x509_certificate(cert, default_backend())
    publicKey = cert.public_key()
    padding = _paadding.PKCS1v15()
    #publicKey = publicKey.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
    #print(publicKey)
    if not isinstance(publicKey, rsa.RSAPublicKey):
        print("The provided certificate doesn't have a RSA public Key")
        return False
    try:
        state = publicKey.verify(
            signature,
            data,
            padding,
            hashes.SHA256(),
        )
    except InvalidSignature as strerror:
        # print("Invalid Signature %s".format(strerror.__doc__))
        return False
    else:
        # print("Verified")
        return True

def ccStore(rootCerts, trustedCerts, crlList):
    try:
        store = X509Store()
        i = 0
        for root in rootCerts:
            store.add_cert(root)
            i += 1
        # print("Root Certificates Added to the X509 Store Context description : {:d}".format(i))
        i = 0
        for trusted in trustedCerts:
            store.add_cert(trusted)
            i += 1
        # print("Trusted Authentication Certificates Added to the X509 Store Context description : {:d}".format(i))

        i = 0
        for crl in crlList:
            store.add_crl(crl)
            i += 1
        # print("Certificates Revocation Lists Added to the X509 Store Context description : {:d}".format(i))
        store.set_flags(X509StoreFlags.CRL_CHECK | X509StoreFlags.IGNORE_CRITICAL)
    except X509StoreContext:
        print("Store Context description failed")
        return None
    else:
        return store

def verify_chain_of_trust(cert,ccStoreContext):
    if cert is None:
        return None
    cert = base64.b64decode(cert)
    storecontext = None
    try:
        certx509 = load_certificate(FILETYPE_PEM, cert)
        storecontext = X509StoreContext(ccStoreContext, certx509).verify_certificate()
    except OpenSSL.crypto.X509StoreContextError as e:
        return False
    if storecontext is None:
        #print("The smartcard  was sucessfully verified")
        return True
    else:
        return False

def load_certificates_and_revogation_lists():
    # root => issuer== commom name 
    rootCerts = ()
    trustedCerts = ()
    crlList = ()
    dirname = ["../security/CCCerts/", "../security/CRL/"]
    for filename in listdir(dirname[0]):
        try:
            cert_info = open(dirname[0] + filename, 'rb').read()
        except IOError:
            print("IO Exception while reading file : {:s} {:s}".format(dirname[0], filename))
            exit(10)
        else:
            if ".cer" in filename:
                try:
                    if "0012" in filename or "0013" in filename or "0015" in filename:
                        certAuth = load_certificate(FILETYPE_PEM, cert_info)
                    elif "Raiz" in filename:
                        root = load_certificate(FILETYPE_ASN1,cert_info)
                    else:
                        certAuth = load_certificate(FILETYPE_ASN1, cert_info)
                except:
                    print("Exception while loading certificate from file : {:s} {:s}".format(dirname[0], filename))
                    exit(10)
                else:
                    trustedCerts = trustedCerts + (certAuth,)
            elif ".crt" in filename:
                try:
                    if "ca_ecc" in filename:
                        root = load_certificate(FILETYPE_PEM, cert_info)
                    elif "-self" in filename:
                        root = load_certificate(FILETYPE_PEM, cert_info)
                    else:
                        root = load_certificate(FILETYPE_ASN1, cert_info)
                except :
                    print("Exception while loading certificate from file : {:s} {:s}".format(
                    dirname[0], filename))
                    exit(10)
                else:
                    rootCerts = rootCerts + (root,)
    # print("Loaded Root certificates : {:d} out of {:d} ".format(len(rootCerts), len(listdir(dirname[0]))))
    # print("Loaded Authentication certificates: {:d} out of {:d} ".format(len(trustedCerts), len(listdir(dirname[0]))))
    for filename in listdir(dirname[1]):
        try:
            crl_info = open(dirname[1] + "/" + filename, 'rb').read()
        except IOError:
            print("IO Exception while reading file : {:s} {:s}".format(dirname[0], filename))
        else:
            if ".crl" in filename:
                crls = load_crl(FILETYPE_ASN1, crl_info)
        crlList = crlList + (crls,)
    # print("Certificate revocation lists loaded: {:d} out of {:d} ".format(len(crlList), len(listdir(dirname[1]))))
    return rootCerts, trustedCerts, crlList

def test(n):
    for i in range(n):
        # print('############## TEST %s ##############'%i)
        # #server generates keypair
        # RSA_PASSWORD = '12345678'
        # server_rsa = RSACipher()
        # server_keypair = server_rsa.generate_key_pair(RSA_PASSWORD)
        # print('Server public key:%s'%(server_keypair['publicKey']))
        # print('Server private key:%s'%(server_keypair['privateKey']))

        # #client encrypts his aes_password with the server's public key
        # AES_PASSWORD = generate_random_password(100,150)
        # print('Client/server AES key before:%s'%(AES_PASSWORD))
        # server_clientside_rsa = RSACipher()
        # server_clientside_rsa.load_pub_key(server_keypair['publicKey'])
        # aes_key_enc = server_clientside_rsa.encrypt(AES_PASSWORD)
        # print('Client/server AES key ciphertext:%s'%(aes_key_enc))

        # #the server decrypts the client's aes password with it's private key
        # server_rsa_2 = RSACipher()
        # server_rsa_2.load_priv_key(server_keypair['privateKey'],RSA_PASSWORD)
        # client_server_aes_key_cleartext = server_rsa_2.decrypt(aes_key_enc)
        # print('Client/server AES key decrypted:%s'%(client_server_aes_key_cleartext))
    
        ############# ELLIPTIC CURVE ##################
        # private_key = ec.generate_private_key(
        #     ec.SECP384R1(), default_backend()
        # )
        # print('client privatekey', private_key)
        # In a real handshake the peer_public_key will be received from the
        # other party. For this example we'll generate another private key
        # and get a public key from that.
        # peer_public_key = ec.generate_private_key(
        #     ec.SECP384R1(), default_backend()
        # ).public_key()
        # serialized_public = peer_public_key.public_bytes(
        #     encoding=serialization.Encoding.PEM,
        #     format=serialization.PublicFormat.SubjectPublicKeyInfo
        # ).decode('utf-8')
        # print('serialized pub\n',serialized_public)
        #SEND PUBLIC KEY TO SERVER...
        # loaded_public_key = serialization.load_pem_public_key(
        #     bytes(serialized_public,'utf-8'),
        #     backend=default_backend()
        # )
        # print('server publickey', peer_public_key)
        # shared_key = private_key.exchange(ec.ECDH(), loaded_public_key)
        # print('shared key ', shared_key)
        # # Perform key derivation.
        # derived_key = HKDF(
        #     algorithm=hashes.SHA256(),
        #     length=16,
        #     salt=None,
        #     info=None,
        #     backend=default_backend()
        # ).derive(shared_key)
        # print('derived key ', derived_key)

        ############# sYMETRIC algorithms and modes #################
        #Algorithms: AES, Camellia, TripleDES, CAST5, SEED, Blowfish, IDEA
        #Modes: CBC, OFB, CFB
        # cipher = SymmetricCipher(algorithm='IDEA',mode='CFB')
        # secret_key = generate_random_password(16,16)
        # cipher.generate_secret_key(base64.b64encode(secret_key))
        # ciphertext = cipher.encrypt('my name is slim shady')
        # print(ciphertext)
        # cleartext = cipher.decrypt(ciphertext)
        # print(cleartext)
        a = 1

#remove later. only for testing
import secrets
def generate_random_password(mn,mx):
    return secrets.token_bytes(random.randint(mn,mx))

######################### INVOKE FROM COMMAND LINE #########################
if __name__=='__main__':
    if sys.argv[1] == 'hash':
        #python security.py hash sha256 R1(base64) R2(base64) C(a:b:c:d, where a,b,c and d are the cards of the hand)
        if sys.argv[2] == 'sha256':
            C = sys.argv[5].split(':') #C
            hash_object = hashlib.sha256()
            hash_object.update(base64.b64decode(sys.argv[3])) #R1
            hash_object.update(base64.b64decode(sys.argv[4])) #R2
            for enc_card in C:
                hash_object.update(bytes(enc_card,'utf-8'))
            hex_dig = hash_object.hexdigest()
            print(json.dumps({'algorithm':'hash','function':'sha256','hash':hex_dig}))
        else:
            raise Exception('No such function: '+str(sys.argv[2]))
    elif sys.argv[1] == 'sym':
        sym_cipher = SymmetricCipher(algorithm=sys.argv[5],mode=sys.argv[6])
        #python security.py sym encrypt <password> <cleartext> <algorithm> <mode>
        if sys.argv[2] == 'encrypt':
            sym_cipher.generate_secret_key(sys.argv[3])
            print(json.dumps({'algorithm':sys.argv[5],'function':'encrypt','ciphertext':sym_cipher.encrypt(sys.argv[4])}))
        #python security.py sym decrypt <password> <ciphertext(base64)> <algorithm> <mode>
        elif sys.argv[2] == 'decrypt':
            sym_cipher.generate_secret_key(sys.argv[3])
            print(json.dumps({'algorithm':sys.argv[5],'function':'decrypt','cleartext':sym_cipher.decrypt(sys.argv[4])}))
        else:
            raise Exception('No such function: '+str(sys.argv[2]))
    elif sys.argv[1] == 'rsa':
        rsa_cipher = RSACipher()
        #python security.py rsa generate_key_pair <password>
        if sys.argv[2] == 'generate_key_pair':
            key_pair = rsa_cipher.generate_key_pair(sys.argv[3])
            key_pair['algorithm'] = 'rsa'
            key_pair['function'] = 'generate_key_pair'
            print(json.dumps(key_pair))
        #python security.py rsa encrypt <publicKey> <cleartext>
        elif sys.argv[2] == 'encrypt':
            rsa_cipher.load_pub_key(sys.argv[3])
            print(json.dumps({'algorithm':'rsa','function':'encrypt','ciphertext':rsa_cipher.encrypt(sys.argv[4])}))
        #python security.py rsa decrypt <password> <privateKey> <ciphertext(base64)>
        elif sys.argv[2] == 'decrypt':
            rsa_cipher.load_priv_key(sys.argv[4],sys.argv[3])
            print(json.dumps({'algorithm':'rsa','function':'decrypt','cleartext':rsa_cipher.decrypt(sys.argv[5])}))
        #python security.py rsa sign <password> <privateKey> <message>
        elif sys.argv[2] == 'sign':
            rsa_cipher.load_priv_key(sys.argv[4],sys.argv[3])
            print(json.dumps({'algorithm':'rsa','function':'sign','signature':rsa_cipher.sign(sys.argv[5])}))
        #python security.py rsa verify <publicKey> <signature> <message>
        elif sys.argv[2] == 'verify':
            rsa_cipher.load_pub_key(sys.argv[3])
            print(json.dumps({'algorithm':'rsa','function':'verify','valid':rsa_cipher.verify(sys.argv[4],sys.argv[5])}))
        #python security.py rsa verify_signed_certificate <certificate>(base64) <original_data>(string) <signature>(base64)
        elif sys.argv[2] == 'verify_signed_certificate':
            print(json.dumps({'algorithm':'rsa','function':'verify_signed_certificate','valid':verify_signed_certificate(
                                                                                                                        sys.argv[3], #certificate
                                                                                                                        sys.argv[4], #original data
                                                                                                                        sys.argv[5])})) # signature
        else:
            raise Exception('No such function: '+str(sys.argv[2]))
    elif sys.argv[1] == 'citizen_card':
        rootCerts, trustedCerts, crlList = load_certificates_and_revogation_lists()
        ccStoreContext = ccStore(rootCerts, trustedCerts, crlList)
        if sys.argv[2] == 'verify_chain_of_trust':
            print(json.dumps({'algorithm':'citizen_card','function':'verify_chain_of_trust','valid':verify_chain_of_trust(sys.argv[3],ccStoreContext)}))
        else:
            raise Exception('No such function: '+str(sys.argv[2]))
    elif sys.argv[1] == 'ec':
        eliptic_cipher = ECCipher()
        #python security.py ec generate_key_pair
        if sys.argv[2] == 'generate_key_pair':
            result = {'algorithm':'elliptic_curve','function':'generate_key_pair'}
            result.update(eliptic_cipher.generate_key_pair())
            print(json.dumps(result))
        #python security.py ec derive_key <privatekey>(base64) <peer_publickey>(base64)
        elif sys.argv[2] == 'derive_key':
            eliptic_cipher.load_priv_key(sys.argv[3])
            print(json.dumps({'algorithm':'elliptic_curve','function':'derive_key','sharedKey':eliptic_cipher.derive_key(sys.argv[4])}))
        else:
            raise Exception('No such function: '+str(sys.argv[2]))
    elif sys.argv[1] == 'test':
        test(int(sys.argv[2]))
    else:
        raise Exception('No such encryption/decryption algorithm: '+str(sys.argv[2]))


