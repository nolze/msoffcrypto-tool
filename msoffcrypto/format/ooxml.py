import logging
import base64, io
from struct import unpack
from xml.dom.minidom import parseString
import zipfile

import olefile

from . import base
from .common import _parse_encryptionheader, _parse_encryptionverifier
from ..method.ecma376_agile import ECMA376Agile
from ..method.ecma376_standard import ECMA376Standard

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def _parseinfo_standard(ole):
    headerFlags, = unpack('<I', ole.read(4))
    encryptionHeaderSize, = unpack('<I', ole.read(4))
    block = ole.read(encryptionHeaderSize)
    blob = io.BytesIO(block)
    header = _parse_encryptionheader(blob)
    block = ole.read()
    blob = io.BytesIO(block)
    algIdMap = {
        0x0000660E: 'AES-128',
        0x0000660F: 'AES-192',
        0x00006610: 'AES-256',
    }
    verifier = _parse_encryptionverifier(blob, "AES" if header['algId'] & 0xFF00 == 0x6600 else "RC4")  # TODO: Fix
    info = {
        'header': header,
        'verifier': verifier,
    }
    return info


def _parseinfo_agile(ole):
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


def _parseinfo(ole):
    versionMajor, versionMinor = unpack('<HH', ole.read(4))
    if versionMajor == 4 and versionMinor == 4:  # Agile
        return 'agile', _parseinfo_agile(ole)
    elif versionMajor in [2, 3, 4] and versionMinor == 2:  # Standard
        return 'standard', _parseinfo_standard(ole)
    elif versionMajor in [3, 4] and versionMinor == 3:  # Extensible
        raise Exception("Unsupported EncryptionInfo version (Extensible Encryption)")


class OOXMLFile(base.BaseOfficeFile):
    def __init__(self, file):
        self.format = "ooxml"
        file.seek(0)  # TODO: Investigate the effect (required for olefile.isOleFile)
        # olefile cannot process non password protected ooxml files.
        # TODO: this code is duplicate of OfficeFile(). Merge?
        if olefile.isOleFile(file):
            ole = olefile.OleFileIO(file)
            self.file = ole
            with self.file.openstream('EncryptionInfo') as stream:
                self.type, self.info = _parseinfo(stream)
            logger.debug("OOXMLFile.type: {}".format(self.type))
            self.secret_key = None
            if self.type == 'agile':
                # TODO: Support aliases?
                self.keyTypes = ('password', 'private_key', 'secret_key')
            elif self.type == 'standard':
                self.keyTypes = ('password', 'secret_key')
            elif self.type == 'extensible':
                pass
        elif zipfile.is_zipfile(file):
            self.file = file
            self.type, self.info = None, None
            self.secret_key = None
        else:
            raise Exception("Unsupported file format")

    def load_key(self, password=None, private_key=None, secret_key=None, strict=False):
        if password:
            if self.type == 'agile':
                self.secret_key = ECMA376Agile.makekey_from_password(
                    password,
                    self.info['passwordSalt'],
                    self.info['passwordHashAlgorithm'],
                    self.info['encryptedKeyValue'],
                    self.info['spinValue'],
                    self.info['passwordKeyBits']
                )
            elif self.type == 'standard':
                self.secret_key = ECMA376Standard.makekey_from_password(
                    password,
                    self.info['header']['algId'],
                    self.info['header']['algIdHash'],
                    self.info['header']['providerType'],
                    self.info['header']['keySize'],
                    self.info['verifier']['saltSize'],
                    self.info['verifier']['salt']
                )
                verified = ECMA376Standard.verifykey(
                    self.secret_key,
                    self.info['verifier']['encryptedVerifier'],
                    self.info['verifier']['encryptedVerifierHash']
                )
                if not verified:
                    raise Exception("Key verification failed")
            elif self.type == 'extensible':
                pass
        elif private_key:
            if self.type == 'agile':
                self.secret_key = ECMA376Agile.makekey_from_privkey(private_key, self.info['encryptedKeyValue'])
            else:
                raise Exception("Unsupported key type for the encryption method")
        elif secret_key:
            self.secret_key = secret_key

    def decrypt(self, ofile):
        if self.type == 'agile':
            with self.file.openstream('EncryptedPackage') as stream:
                obuf = ECMA376Agile.decrypt(
                    self.secret_key, self.info['keyDataSalt'],
                    self.info['keyDataHashAlgorithm'],
                    stream
                )
            ofile.write(obuf)
        elif self.type == 'standard':
            with self.file.openstream('EncryptedPackage') as stream:
                obuf = ECMA376Standard.decrypt(self.secret_key, stream)
            ofile.write(obuf)

        # If the file is successfully decrypted, there must be a valid OOXML file, i.e. a valid zip file
        if not zipfile.is_zipfile(io.BytesIO(obuf)):
            raise Exception("The file could not be decrypted with this password")

    def is_encrypted(self):
        # Heuristic
        if isinstance(self.file, olefile.OleFileIO):
            return True
        else:
            return False
