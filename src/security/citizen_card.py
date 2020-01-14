from PyKCS11 import *
import platform
import sys
from os import listdir 
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as _paadding
from OpenSSL.crypto import load_certificate, load_crl, FILETYPE_ASN1, FILETYPE_PEM, Error, X509Store, X509StoreContext,\
    X509StoreFlags, X509StoreContextError

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as _aspaadding
from cryptography.exceptions import *
from cryptography import x509
from OpenSSL.crypto import *
# from puass import getpass
import base64
import unicodedata

class CitizenCard:
    def __init__(self):
        self._certificate = None
        rootCerts, trustedCerts, crlList = self.load_certificates()
        self.ccStoreContext = self.ccStore(rootCerts, trustedCerts, crlList)
        self.lib = '/usr/local/lib/libpteidpkcs11.so'
        self.cipherMechanism = Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, "")
        self.sessions = self.initPkcs()
        self.fullnames = self.getcardsNames()

    def load_certificates(self):
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
    
    
    def ccStore(self, rootCerts, trustedCerts, crlList):
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
    
    def initPkcs(self):
        AUTH_CERT_LABEL = "CITIZEN AUTHENTICATION CERTIFICATE"
        AUTH_KEY_LABEL = "CITIZEN AUTHENTICATIOcrlList"
        SIGN_CERT_LABEL = "CITIZEN SIGNATURE CEcrlListATE"
        SIGN_KEY_LABEL = "CITIZEN SIGNATURE KEYcrlList"
        # print("Entering PyKCS11 init ")
        try:
            pkcs11 = PyKCS11Lib()
            pkcs11.load(self.lib)
        except PyKCS11Error:
            print("PortugueseCitizenCard:   We couldn't load the PyKCS11 lib")
            Exception("We couldn't load the lib")
            exit(10)
        except KeyboardInterrupt:
            print("PortugueseCitizenCard:   Exiting Module by Keyboard Interruption")
            exit(0)
        else:
            try:
                # listing all card slots
                self.slots = pkcs11.getSlotList(tokenPresent=True)
                # print("The program found " + str(len(self.slots)) + " slots")
                if len(self.slots) < 1:
                    exit(-1)
                return [pkcs11.openSession(self.slots[x]) for x in range(0, len(self.slots))]
            except PyKCS11Error:
                print("couldn't execute the method openSession")
                exit(10)
            except:
                print("no CC was found")
                exit(11)

    def getId(self,sessionIdx):
        AUTH_CERT_LABEL = "CITIZEN AUTHENTICATION CERTIFICATE"
        # print("Entering getID with session id: {:2d}".format(sessionIdx))
        try:
            info = self.sessions[sessionIdx].findObjects(template=([(PyKCS11.CKA_LABEL, AUTH_CERT_LABEL),
                                                                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]))
        except PyKCS11Error:
            print("The the smartcard with the id: {:3d} unexpectedly closed the session".format(sessionIdx))
            return None
        else:
            try:
                infos1 = ''.join(chr(c) for c in [c.to_dict()['CKA_SUBJECT'] for c in info][0])
            except (IndexError, TypeError):
                print(" Certificate \"{:15s}\" not found in PyKCSS session with the id :{:2d}".format(
                                      AUTH_CERT_LABEL))
                return None
            else:
                names = infos1.split("BI")[1].split("\x0c")
                # print(names)
                return ' '.join(names[i] for i in range(1, len(names)))

    def getBI(self, sessionIdx):
        AUTH_CERT_LABEL = "CITIZEN AUTHENTICATION CERTIFICATE"
        # print("Entering getID with session id: {:2d}".format(sessionIdx))
        try:
            info = self.sessions[sessionIdx].findObjects(template=([(PyKCS11.CKA_LABEL, AUTH_CERT_LABEL),
                                                                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]))
        except PyKCS11Error:
            print("The the smartcard with the id: {:3d} unexpectedly closed the session".format(sessionIdx))
            return None
        else:
            try:
                infos1 = ''.join(chr(c) for c in [c.to_dict()['CKA_SUBJECT'] for c in info][0])
            except (IndexError, TypeError):
                print(" Certificate \"{:15s}\" not found in PyKCSS session with the id :{:2d}".format(AUTH_CERT_LABEL))
                return None
            else:
                bi = infos1.split("BI")[1][:8]
                return bi

    def certGetSerial(self):
        return self.cert.serial_number

    def getCerts(self, sessionIdx):
        AUTH_CERT_LABEL = "CITIZEN AUTHENTICATION CERTIFICATE"
        # print("Entering getCerts with session id :{:2d}".format(sessionIdx))
        try:
            info = self.sessions[sessionIdx].findObjects(template=([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE), (PyKCS11.CKA_LABEL, AUTH_CERT_LABEL)]))
        except PyKCS11Error:
            print("The the smartcard in the sessionIdx with the id: {:3d} unexpectedly closed the session".format(sessionIdx))
            exit(12)
        else:
            try:
                der = bytes([c.to_dict()['CKA_VALUE'] for c in info][0])
                #print(der)
            except (IndexError, TypeError):
                print(" Certificate \"{:15s}\" not found in PyKCSS session with the id :{:2d}".format(AUTH_CERT_LABEL))
                return None
            else:
                # converting DER format to x509 certificate
                try:
                    cert = x509.load_der_x509_certificate(der, default_backend()).public_bytes(Encoding.PEM)
                except:
                    print("cert was not loaded")
                    return None
                else:
                    # print(" Certificate for smartcard in the slot:{:2d} loaded:\n".format(sessionIdx))
                    self.cert = x509.load_pem_x509_certificate(cert, default_backend())
                    return cert   

    def getcardsNames(self):
        fullnames = [self.getId(i) for i in self.slots]
        # print()
        return fullnames

    def verifyChainOfTrust(self, cert):
        if cert is None:
            return None
        cert = base64.b64decode(cert)
        storecontext = None
        certx509 = load_certificate(FILETYPE_PEM, cert)
        storecontext = X509StoreContext(self.ccStoreContext, certx509).verify_certificate()
        if storecontext is None:
            print("The smartcard  was sucessfully verified")
            return True
        else:
            return False

    def sign(self,sessionIdx, message):
        label = "CITIZEN AUTHENTICATION KEY"
        session = self.sessions[sessionIdx]
        cipherMechnism = Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, "")
        privateKey = self.sessions[sessionIdx].findObjects(template=([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),(PyKCS11.CKA_LABEL, "CITIZEN AUTHENTICATION KEY")]))[0]
        signedlist = session.sign(privateKey, message.encode(), cipherMechnism)
        return bytes(signedlist)

    def verifySign(self, cert, data, signature):
        print(cert)
        cert = x509.load_pem_x509_certificate(cert, default_backend())
        publicKey = cert.public_key()
        padding = _paadding.PKCS1v15()
        print("####################")
        #publicKey = publicKey.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
        #print(publicKey)
        if not isinstance(publicKey, rsa.RSAPublicKey):
            print("The provided certificate doesn't have a RSA public Key")
            return False
        try:
            state = publicKey.verify(
                signature,
                bytes(data.encode()),
                padding,
                hashes.SHA256(),
            )
        except InvalidSignature as strerror:
            print("Invalid Signature %s".format(strerror.__doc__))
            return False
        else:
            print("Verified")
            return True

    def login(self,sessionIdx):
        session = self.sessions[sessionIdx]
        pin = None
        while True:
            pin = input('PIN: ') 
            try:
                session.login(pin)
            except PyKCS11Error:
                raise PinError()
                return False
            else:
                return True

    def logout(self, sessionIdx):
        session = self.sessions[slot]
        session.logout()
        session.closeSession()
    
if __name__ == '__main__':
    try:
        pteid = CitizenCard()
        fullnames = pteid.getcardsNames()
        slot = -1
        if len(pteid.sessions) > 0:
            temp = ''.join('Slot{:3d}-> Fullname: {:10s}\n'.format(i, fullnames[i]) for i in range(0, len(fullnames)))

            while slot < 0 or slot > len(pteid.sessions):
                slot = input("Available Slots: \n{:40s} \n\nWhich Slot do you wish to use? ".format(temp))
                if slot.isdigit():
                    slot = int(slot)
                else:
                    slot = -1
        for i in range(0, len(pteid.sessions)):
            if slot != i:
                pteid.sessions[i].closeSession()
        print(pteid.getBI(slot))

        cert = pteid.getCerts(slot)
        cert = base64.b64encode(cert).decode('utf-8')
        print("\nIs this certificate valid: {:s}".format(str(pteid.verifyChainOfTrust(cert))))
        exit(3)
        pteid.login(slot)

        datatobeSigned = cert.decode('utf-8')
        signedData = pteid.sign(slot, datatobeSigned)
        print("SIGNE###################w")
        print(signedData)
        print(datatobeSigned + "\n")
        if (pteid.verifySign(pteid.getCerts(slot), datatobeSigned, signedData)):
            print("Verified")

    except KeyboardInterrupt:
        pteid.logout(slot)
        pteid.sessions[slot].closeSession()   