import logging
import base64
from struct import unpack
from xml.dom.minidom import parseString

import olefile

from . import base
from ..method.ecma376 import ECMA376

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

def _parseinfo(ole):
    versionMajor, versionMinor = unpack('<HH', ole.read(4))
    if versionMajor != 4 or versionMinor != 4:
        raise AssertionError("Unsupported EncryptionInfo version")
    ole.seek(8)
    xml = parseString(ole.read())
    keyDataSalt = base64.b64decode(xml.getElementsByTagName('keyData')[0].getAttribute('saltValue'))
    keyDataHashAlgorithm = xml.getElementsByTagName('keyData')[0].getAttribute('hashAlgorithm')
    password_node = xml.getElementsByTagNameNS("http://schemas.microsoft.com/office/2006/keyEncryptor/password", 'encryptedKey')[0]
    spinValue = int(password_node.getAttribute('spinCount'))
    encryptedKeyValue = base64.b64decode(password_node.getAttribute('encryptedKeyValue'))
    passwordSalt = base64.b64decode(password_node.getAttribute('saltValue'))
    passwordHashAlgorithm = password_node.getAttribute('hashAlgorithm')
    passwordKeyBits = int(password_node.getAttribute('keyBits'))
    info = {
        'keyDataSalt': keyDataSalt,
        'keyDataHashAlgorithm': keyDataHashAlgorithm,
        'encryptedKeyValue': encryptedKeyValue,
        'spinValue': spinValue,
        'passwordSalt': passwordSalt,
        'passwordHashAlgorithm': passwordHashAlgorithm,
        'passwordKeyBits': passwordKeyBits,
    }
    return info

class OOXMLFile(base.BaseOfficeFile):
    def __init__(self, file):
        self.spec = "OOXML"
        ole = olefile.OleFileIO(file)
        self.file = ole
        self.info = _parseinfo(self.file.openstream('EncryptionInfo'))
        self.secret_key = None
        ## TODO: Support aliases?
        self.keyTypes = ('password', 'private_key', 'secret_key')

    def load_key(self, password=None, private_key=None, secret_key=None):
        if password:
            self.secret_key = ECMA376.generate_skey_from_password(password, self.info['passwordSalt'], self.info['passwordHashAlgorithm'], self.info['encryptedKeyValue'], self.info['spinValue'], self.info['passwordKeyBits'])        
        elif private_key:
            self.secret_key = ECMA376.generate_skey_from_privkey(private_key, self.info['encryptedKeyValue'])
        elif secret_key:
            self.secret_key = secret_key

    def decrypt(self, ofile):
        obuf = ECMA376.decrypt(self.secret_key, self.info['keyDataSalt'], self.info['keyDataHashAlgorithm'], self.file.openstream('EncryptedPackage'))
        ofile.write(obuf)

    ## For backward compatibility; Should be removed in 4.0
    def load_password(self, password):
        self.load_key(password=password)
    
    def load_privkey(self, privkey):
        self.load_key(private_key=privkey)
    
    def load_skey(self, skey):
        self.load_key(secret_key=skey)
    