import logging
import base64, io
from struct import unpack
from xml.dom.minidom import parseString
import zipfile

import olefile

from . import base
from ..method.ecma376_agile import ECMA376Agile
from ..method.ecma376_standard import ECMA376Standard

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def _parse_encryptionheader(blob):
    flags, = unpack('<I', blob.read(4))
    # if mode == 'strict': compare values with spec.
    sizeExtra, = unpack('<I', blob.read(4))
    algId, = unpack('<I', blob.read(4))
    algIdHash, = unpack('<I', blob.read(4))
    keySize, = unpack('<I', blob.read(4))
    providerType, = unpack('<I', blob.read(4))
    reserved1, = unpack('<I', blob.read(4))
    reserved2, = unpack('<I', blob.read(4))
    cspName = blob.read().decode('utf-16le')
    header = {
        'flags': flags,
        'sizeExtra': sizeExtra,
        'algId': algId,
        'algIdHash': algIdHash,
        'keySize': keySize,
        'providerType': providerType,
        'reserved1': reserved1,
        'reserved2': reserved2,
        'cspName': cspName,
    }
    return header


def _parse_encryptionverifier(blob, algorithm):
    saltSize, = unpack('<I', blob.read(4))
    salt = blob.read(16)
    encryptedVerifier = blob.read(16)
    verifierHashSize, = unpack('<I', blob.read(4))
    if algorithm == 'RC4':
        encryptedVerifierHash = blob.read(20)
    elif algorithm == 'AES':
        encryptedVerifierHash = blob.read(32)
    verifier = {
        'saltSize': saltSize,
        'salt': salt,
        'encryptedVerifier': encryptedVerifier,
        'verifierHashSize': verifierHashSize,
        'encryptedVerifierHash': encryptedVerifierHash,
    }
    return verifier


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
        raise AssertionError("Unsupported EncryptionInfo version (Extensible Encryption)")


class OOXMLFile(base.BaseOfficeFile):
    def __init__(self, file):
        self.spec = "OOXML"  # TODO: Should be removed in 4.0
        self.format = "ooxml"
        ole = olefile.OleFileIO(file)
        self.file = ole
        self.type, self.info = _parseinfo(self.file.openstream('EncryptionInfo'))
        self.secret_key = None
        if self.type == 'agile':
            # TODO: Support aliases?
            self.keyTypes = ('password', 'private_key', 'secret_key')
        elif self.type == 'standard':
            self.keyTypes = ('password', 'secret_key')
        elif self.type == 'extensible':
            pass

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
                    raise AssertionError()
            elif self.type == 'extensible':
                pass
        elif private_key:
            if self.type == 'agile':
                self.secret_key = ECMA376Agile.makekey_from_privkey(private_key, self.info['encryptedKeyValue'])
            else:
                raise AssertionError("Unsupported key type for the encryption method")
        elif secret_key:
            self.secret_key = secret_key

    def decrypt(self, ofile):
        if self.type == 'agile':
            obuf = ECMA376Agile.decrypt(
                self.secret_key, self.info['keyDataSalt'],
                self.info['keyDataHashAlgorithm'],
                self.file.openstream('EncryptedPackage')
            )
            ofile.write(obuf)
        elif self.type == 'standard':
            obuf = ECMA376Standard.decrypt(self.secret_key, self.file.openstream('EncryptedPackage'))
            ofile.write(obuf)

        # If the file is successfully decrypted, there must be a valid OOXML file, i.e. a valid zip file
        if not zipfile.is_zipfile(io.BytesIO(obuf)):
            raise Exception("The file could not be decrypted with this password")

    # For backward compatibility; Should be removed in 4.0
    def load_password(self, password):
        self.load_key(password=password)

    def load_privkey(self, privkey):
        self.load_key(private_key=privkey)

    def load_skey(self, skey):
        self.load_key(secret_key=skey)
